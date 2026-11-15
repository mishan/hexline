package org.foggyden.hexline.chat

import android.app.Application
import android.content.SharedPreferences
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewmodel.CreationExtras
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.MainCoroutineDispatcher
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestCoroutineScheduler
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.foggyden.hexline.core.ClassicLogin
import org.foggyden.hexline.core.Connection
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.DeviceIdentity
import org.foggyden.hexline.core.Enrolled
import org.foggyden.hexline.core.Enrollment
import org.foggyden.hexline.core.HistoryPage
import org.foggyden.hexline.core.LoginInfo
import org.foggyden.hexline.core.UpdateSink
import org.foggyden.hexline.identity.EnrollProblem
import org.foggyden.hexline.identity.Enrolling
import org.foggyden.hexline.identity.Identities
import org.foggyden.hexline.secrets.SecretUnavailable
import org.foggyden.hexline.secrets.SecretUnreadable
import org.foggyden.hexline.secrets.Secrets
import org.foggyden.hexline.servers.SavedServers
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn
import org.foggyden.hexline.servers.StoreQueue
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.io.IOException
import kotlin.coroutines.CoroutineContext

/**
 * The view model's connections and stores, driven step by step. The main
 * thread and the store queue are each a dispatcher that runs only when
 * told, so a forget or a delete can be made to land between any two of a
 * connection's steps. Main is immediate where the app's is: a call the
 * test makes stands for one from the UI, on the main thread, and runs
 * there until it first waits; what the store queue or the core hands back
 * is dispatched to it. The stores are the real ones over an in-memory
 * stand-in for the Keystore, which refuses to be touched off the queue
 * while a model is alive; the core is a connection whose answers the test
 * gives, from the core's side.
 */
@OptIn(ExperimentalCoroutinesApi::class, InternalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class ChatViewModelTest {
    private val app: Application = RuntimeEnvironment.getApplication()

    /** Whether the store queue is running a task, or the core calling in. */
    private var onDisk = false
    private var fromCore = false

    private val main = Main(StandardTestDispatcher(TestCoroutineScheduler()))
    private val disk = Counted(StandardTestDispatcher(TestCoroutineScheduler())) { onDisk = it }

    /** A model is alive, so the stores are the queue's alone. */
    private var armed = false

    /** The test's own look at the stores, apart from the model's. */
    private var exempt = false

    private var cases = 0
    private var stores = Stores(cases)
    private val servers get() = stores.servers
    private val identities get() = stores.identities
    private val secrets get() = stores.secrets

    private val opened = mutableListOf<FakeConnection>()
    private val enrollments = mutableListOf<FakeEnrollment>()
    private var now = ISSUED + DAY
    private val owner = ViewModelStore()
    private val uncaught = mutableListOf<Throwable>()

    init {
        Dispatchers.setMain(main)
        Thread.currentThread().setUncaughtExceptionHandler { _, e -> uncaught += e }
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        Thread.currentThread().uncaughtExceptionHandler = null
        assertEquals("nothing thrown on the model's threads", emptyList<Throwable>(), uncaught)
    }

    /** The stores of one case, apart from any other's. */
    private inner class Stores(
        n: Int,
    ) {
        val secrets = MemorySecrets()
        val servers = SavedServers(app, secrets, QueuedPrefs(app.getSharedPreferences("servers-$n", 0)))
        val identities = Identities(app, secrets, File(app.filesDir, "identities-$n"))
    }

    /** A case's own stores and connections, the model before it cleared. */
    private fun fresh() {
        owner.clear()
        settle()
        armed = false
        stores = Stores(++cases)
        opened.clear()
        enrollments.clear()
    }

    private fun model(): ChatViewModel {
        val factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(
                    modelClass: Class<T>,
                    extras: CreationExtras,
                ): T =
                    ChatViewModel(app, servers, identities, StoreQueue(disk), { url, sink ->
                        FakeConnection(url, sink).also { opened += it }
                    }, { renewing, expecting -> FakeEnrollment(renewing, expecting).also { enrollments += it } }, { now }) as T
            }
        armed = true
        return ViewModelProvider.create(owner, factory)[ChatViewModel::class.java]
    }

    private fun <T> outside(look: () -> T): T {
        exempt = true
        try {
            return look()
        } finally {
            exempt = false
        }
    }

    private fun core(call: () -> Unit) {
        fromCore = true
        try {
            call()
        } finally {
            fromCore = false
        }
    }

    /** The main thread's work so far, up to its next wait on the store. */
    private fun onMain() = main.inner.scheduler.advanceUntilIdle()

    /** The store's work so far. */
    private fun onDisk() = disk.inner.scheduler.advanceUntilIdle()

    /** Everything, until neither has anything left to run. */
    private fun settle() {
        repeat(SETTLE) {
            onMain()
            onDisk()
            if (main.pending == 0 && disk.pending == 0) return
        }
        error("still busy after $SETTLE rounds")
    }

    /** [conn]'s login landing, as the core answers it. */
    private fun land(
        conn: FakeConnection,
        info: LoginInfo,
    ) = core { conn.answer.complete(info) }

    private fun refuse(
        conn: FakeConnection,
        e: CoreException,
    ) = core { conn.answer.completeExceptionally(e) }

    /**
     * [conn]'s first batch, and only after it, as the core keeps it, the
     * session to resume with: the model has handled the batch by then.
     */
    private fun live(
        conn: FakeConnection,
        session: ByteArray? = "session of ${conn.url}".toByteArray(),
    ) {
        core { conn.sink.deliver(listOf(CoreUpdate.Roster(1u, emptyList(), ""))) }
        onMain()
        sessionKept(conn, session)
    }

    /** [conn]'s link's session, kept and told, as the core does once a link's first batch is handed over. */
    private fun sessionKept(
        conn: FakeConnection,
        session: ByteArray?,
    ) {
        conn.session = session
        if (session != null) core { conn.sink.deliver(listOf(CoreUpdate.SessionKept)) }
    }

    /** [conn]'s last batch, [updates]: the core keeps no session after it. */
    private fun over(
        conn: FakeConnection,
        updates: List<CoreUpdate>,
    ) {
        conn.session = null
        core { conn.sink.deliver(updates) }
    }

    private fun kept() = outside { identities.list().any { it.fingerprint == FINGERPRINT } }

    private fun device() =
        outside {
            identities
                .list()
                .single()
                .info.device
        }

    private fun keepIdentity(mailbox: String? = null) =
        outside { identities.save(SEED.copyOf(), CERT, CARD, "alice@example", null, mailbox) }

    private fun stored() = outside { identities.list().singleOrNull() }

    private fun saved(
        server: Server,
        password: String? = null,
        session: ByteArray? = null,
    ) = outside {
        servers.remember(server, password)
        session?.let { servers.keepSession(server, it) }
    }

    private fun identityServer(name: String) =
        Server("ws://${name.replace(Regex("[^a-z0-9]+"), "-")}.example/ng", null, SignIn.Identity(FINGERPRINT))

    private fun passwordServer(name: String) = Server("ws://${name.replace(Regex("[^a-z0-9]+"), "-")}.example/ng", "alice", SignIn.Password)

    @Test
    fun theLastServerAskedForIsTheOneConnectedTo() {
        val first = passwordServer("first")
        val second = passwordServer("second")
        saved(first, "pw")
        saved(second, "pw")
        val vm = model()
        settle()
        // Both asked for while the first's secrets are still being read.
        vm.connect(first, null, false)
        vm.connect(second, null, false)
        settle()
        assertEquals(listOf(second.url), opened.map { it.url })
    }

    @Test
    fun aConnectAskedForAgainWhileItsLoginIsOutKeepsTheOneMade() {
        val server = passwordServer("again")
        val vm = model()
        settle()
        vm.connect(server, "pw", true)
        settle()
        vm.connect(server, "pw", true)
        settle()
        land(opened.single(), LOGGED_IN)
        settle()
        assertEquals("the login that landed is remembered", listOf(server), outside { servers.all() })
        assertEquals("pw", outside { servers.password(server) })
    }

    @Test
    fun aSessionResumedWithIsKeptUntilTheCoreHasOneOfItsOwn() {
        for (goes in listOf(false, true)) {
            fresh()
            val server = passwordServer("resumed $goes")
            saved(server, "pw", SESSION)
            model()
            settle()
            val conn = opened.single()
            assertArrayEquals(SESSION, conn.resumedWith)
            land(conn, LOGGED_IN.copy(resumed = true))
            settle()
            if (goes) {
                // The screen goes before the core's first batch.
                owner.clear()
                settle()
            }
            assertArrayEquals("goes $goes: kept while the core has none", SESSION, outside { servers.session(server) })
            if (!goes) {
                live(conn)
                settle()
                assertArrayEquals("the core's, once it has one", conn.session, outside { servers.session(server) })
            }
        }
    }

    /** When, against a connect's steps, a forget or a delete is asked for. */
    private enum class When { SecretsRead, DeviceRead, LoginOut, Landed }

    @Test
    fun aForgetOrADeleteAskedForDuringAConnectLeavesNothingOfIt() {
        for (by in listOf("forget", "delete")) {
            for (at in When.entries) {
                fresh()
                val label = "$by at $at"
                val server = identityServer(label)
                keepIdentity()
                // Saved, so its secrets are read; with no session, so the launch resumes nothing.
                if (at == When.SecretsRead) saved(server)
                val vm = model()
                settle()
                vm.connect(server, null, false)
                when (at) {
                    When.SecretsRead -> assertTrue("$label: still reading", opened.isEmpty())
                    When.DeviceRead -> {
                        // Past the link flag, at the device's read.
                        onDisk()
                        onMain()
                        assertEquals("$label: opened", 1, opened.size)
                        assertNull("$label: not yet proved", opened.single().proved)
                    }
                    When.LoginOut -> settle()
                    When.Landed -> {
                        settle()
                        land(opened.single(), identityLoggedIn())
                        // Its remember asked for, not made.
                        onMain()
                    }
                }
                val conn = opened.singleOrNull()
                if (by == "forget") vm.forget(server) else vm.deleteIdentity(FINGERPRINT)
                settle()
                // The core answers the login it was hung up on: closed.
                if (at == When.LoginOut) {
                    land(conn!!, identityLoggedIn())
                    settle()
                }
                if (at == When.SecretsRead || at == When.DeviceRead) assertNull("$label: no seed reaches the core", conn?.proved)
                if (at == When.SecretsRead) assertTrue("$label: nothing opened", opened.isEmpty())
                conn?.let { assertEquals("$label: logged out", true, it.hungUp) }
                assertEquals("$label: shown nothing of it", Link.Idle, vm.chat.value.link)
                if (by == "delete" && at == When.SecretsRead) {
                    assertEquals("$label: a server saved before stays as it was", listOf(server), outside { servers.all() })
                } else {
                    assertTrue("$label: not remembered", server !in outside { servers.all() })
                }
                assertNull("$label: no session kept", outside { servers.session(server) })
                if (by == "delete") assertTrue("$label: the identity goes", !kept())
            }
        }
    }

    @Test
    fun aResumeAtLaunchIsMadeUnlessItsServerOrIdentityGoesWhileItIsRead() {
        for (by in listOf(null, "forget", "delete")) {
            fresh()
            val server = identityServer("launch $by")
            keepIdentity()
            saved(server, session = SESSION)
            // The launch's read is asked for, not made.
            val vm = model()
            when (by) {
                "forget" -> vm.forget(server)
                "delete" -> vm.deleteIdentity(FINGERPRINT)
            }
            settle()
            if (by == null) {
                assertArrayEquals("resumed", SESSION, opened.single().resumedWith)
            } else {
                assertTrue("$by: no connection made", opened.isEmpty())
            }
        }
    }

    @Test
    fun aServersRefusalIsKeptForItsDeviceUnlessForgottenOrDeletedFirst() {
        data class Case(
            val name: String,
            val code: String,
            val lapse: Boolean,
            val before: String?,
            val kept: Boolean,
        )
        val cases =
            listOf(
                Case("refused at login", "revoked", lapse = false, before = null, kept = true),
                Case("refused after a lapse", "rotated", lapse = true, before = null, kept = true),
                Case("refused as busy", "rate_limited", lapse = false, before = null, kept = false),
                Case("refused once forgotten", "revoked", lapse = false, before = "forget", kept = false),
                Case("refused once deleted", "revoked", lapse = false, before = "delete", kept = false),
                Case("refused after a lapse once forgotten", "rotated", lapse = true, before = "forget", kept = false),
                Case("refused after a lapse once deleted", "rotated", lapse = true, before = "delete", kept = false),
            )
        val found = mutableMapOf<String, String?>()
        for (c in cases) {
            fresh()
            val server = identityServer(c.name)
            keepIdentity()
            val device = device()
            val vm = model()
            settle()
            vm.connect(server, null, false)
            settle()
            val conn = opened.single()
            if (c.lapse) {
                land(conn, identityLoggedIn())
                live(conn)
                settle()
            }
            when (c.before) {
                "forget" -> vm.forget(server)
                "delete" -> vm.deleteIdentity(FINGERPRINT)
            }
            if (c.lapse) {
                // A login after a lapse refused: the core's last batch.
                core { conn.sink.deliver(listOf(CoreUpdate.Refused(c.code), CoreUpdate.Closed(false, false))) }
            } else {
                refuse(conn, CoreException.Refused(c.code, ""))
            }
            settle()
            found[c.name] = outside { servers.refused(server, device) }
        }
        assertEquals(cases.associate { it.name to it.code.takeIf { _ -> it.kept } }, found)
    }

    @Test
    fun aRefusedLoginLetGoOfClearsNothingANewerLoginKept() {
        val server = passwordServer("newer")
        val vm = model()
        settle()
        vm.connect(server, "old", true)
        settle()
        val old = opened.single()
        vm.forget(server)
        settle()
        vm.connect(server, "new", true)
        settle()
        val newer = opened.last()
        land(newer, LOGGED_IN)
        live(newer)
        settle()
        // Its server had answered before the hang-up reached it.
        refuse(old, CoreException.Refused("login_failed", ""))
        settle()
        assertEquals("new", outside { servers.password(server) })
        assertArrayEquals(newer.session, outside { servers.session(server) })
    }

    @Test
    fun whatIsAskedForAsTheScreenGoesIsStillMade() {
        val made = mutableMapOf<String, Boolean>()
        for (act in listOf("forget", "delete", "remember", "save")) {
            fresh()
            val server = identityServer("leaving $act")
            keepIdentity()
            if (act == "forget") saved(server)
            val vm = model()
            settle()
            when (act) {
                "forget" -> vm.forget(server)
                "delete" -> vm.deleteIdentity(FINGERPRINT)
                else -> {
                    vm.connect(server, null, false)
                    settle()
                    val conn = opened.single()
                    land(conn, identityLoggedIn())
                    // Landed, and its remember asked for, not made.
                    onMain()
                    if (act == "save") {
                        live(conn)
                        settle()
                        // The core's session as the screen goes is newer than the one kept.
                        conn.session = LATER
                    }
                }
            }
            owner.clear()
            onDisk()
            made[act] =
                outside {
                    when (act) {
                        "forget" -> server !in servers.all()
                        "delete" -> identities.list().isEmpty()
                        "remember" -> server in servers.all()
                        else -> servers.session(server)?.contentEquals(LATER) == true
                    }
                }
        }
        assertEquals(made.keys.associateWith { true }, made)
    }

    @Test
    fun anIdentityOutsideItsTimeOrRefusedHereIsNeitherSignedInWithNorResumed() {
        data class Case(
            val name: String,
            val at: Long,
            val refused: String?,
            val why: Why,
        )
        val cases =
            listOf(
                Case("expired", EXPIRES + PAST_SKEW, null, Why.CertExpired),
                Case("not yet valid", ISSUED - PAST_SKEW, null, Why.CertNotYetValid),
                Case("refused here", ISSUED + DAY, "revoked", Why.Revoked),
            )
        val signedIn = mutableListOf<String>()
        for (c in cases) {
            for (resume in listOf(false, true)) {
                fresh()
                val label = "${c.name}, ${if (resume) "resumed at launch" else "connected"}"
                val server = identityServer(label)
                keepIdentity()
                c.refused?.let { code -> outside { servers.markRefused(server, device(), code) } }
                if (resume) saved(server, session = SESSION)
                now = c.at
                val vm = model()
                settle()
                if (!resume) {
                    vm.connect(server, null, false)
                    settle()
                }
                if (opened.single().proved != null || vm.chat.value.link != Link.Ended(c.why)) signedIn += label
            }
        }
        assertEquals(emptyList<String>(), signedIn)
    }

    @Test
    fun aSecretTheKeystoreWillNotOpenIsToldOrDropped() {
        data class Case(
            val name: String,
            val secret: String,
            val fails: () -> Exception,
            val resume: Boolean,
            val why: Why?,
        )
        val locked = { SecretUnavailable("seed", IOException("locked")) }
        val cases =
            listOf(
                Case("a locked seed, connecting", "device-", locked, resume = false, why = Why.KeyLocked),
                Case("a locked seed, resuming at launch", "device-", locked, resume = true, why = Why.KeyLocked),
                Case("an unreadable seed", "device-", { SecretUnreadable("seed") }, resume = false, why = Why.NoIdentity),
                Case("an unreadable session", "session-", { SecretUnreadable("session") }, resume = true, why = null),
                Case("an unreadable password", "password-", { SecretUnreadable("password") }, resume = false, why = null),
            )
        val wrong = mutableListOf<String>()
        for (c in cases) {
            fresh()
            val server = if (c.secret == "password-") passwordServer(c.name) else identityServer(c.name)
            keepIdentity()
            saved(server, "pw".takeIf { c.secret == "password-" }, SESSION.takeIf { c.resume })
            secrets.fails[c.secret] = c.fails
            val vm = model()
            settle()
            if (opened.isEmpty()) {
                vm.connect(server, null, false)
                settle()
            }
            val conn = opened.single()
            secrets.fails.clear()
            val right =
                when (c.secret) {
                    "device-" ->
                        conn.proved == null &&
                            vm.chat.value.link == Link.Ended(c.why!!) &&
                            kept() == (c.why == Why.KeyLocked)
                    // Read as none, and forgotten.
                    "session-" -> conn.resumedWith == null && outside { servers.session(server) } == null
                    else -> conn.password == null && outside { servers.password(server) } == null
                }
            if (!right) wrong += c.name
        }
        assertEquals(emptyList<String>(), wrong)
    }

    @Test
    fun aSessionNothingWillResumeIsForgottenAndNotTakenUpAtTheNextLaunch() {
        val closed = { replaced: Boolean -> CoreUpdate.Closed(false, replaced) }
        val cases =
            listOf<Pair<String, List<CoreUpdate>?>>(
                "kicked" to listOf(CoreUpdate.Kicked, closed(false)),
                "replaced" to listOf(closed(true)),
                "refused after a lapse" to listOf(CoreUpdate.Refused("session_expired"), closed(false)),
                // No batch: the server said at login that the session would not survive.
                "not resumable from its login" to null,
                "a new login after a lapse that will not survive one" to
                    listOf(CoreUpdate.Reconnected(true, LOGGED_IN.copy(canResume = false)), CoreUpdate.Roster(1u, emptyList(), "")),
            )
        val resumed = mutableListOf<String>()
        for ((name, last) in cases) {
            // The main thread told of it before the screen goes, or not yet.
            for (heard in listOf(true, false)) {
                if (last == null && !heard) continue
                fresh()
                val label = "$name${if (heard) "" else ", the screen going first"}"
                val server = passwordServer(label)
                saved(server, "pw", SESSION)
                model()
                settle()
                val conn = opened.single()
                land(conn, LOGGED_IN.copy(canResume = last != null, resumed = true))
                settle()
                if (last != null) {
                    live(conn)
                    settle()
                    over(conn, last)
                    if (heard) settle()
                }
                owner.clear()
                settle()
                if (outside { servers.session(server) } != null) resumed += "$label: a session kept"
                model()
                settle()
                if (opened.size > 1) resumed += "$label: taken up at launch"
            }
        }
        assertEquals(emptyList<String>(), resumed)
    }

    @Test
    fun aLinksSessionIsSavedOnceTheCoreHasOne() {
        val found = mutableMapOf<String, String?>()
        for (how in listOf("logged in", "logged in again")) {
            fresh()
            val server = passwordServer(how)
            val vm = model()
            settle()
            vm.connect(server, "pw", false)
            settle()
            val conn = opened.single()
            land(conn, LOGGED_IN)
            // Nothing after either session is told: the link stays quiet.
            live(conn)
            settle()
            if (how == "logged in again") {
                // A new login made by the core, its session kept after its first batch.
                core { conn.sink.deliver(listOf(CoreUpdate.Reconnected(false, LOGGED_IN))) }
                onMain()
                sessionKept(conn, ROTATED)
                settle()
            }
            found[how] = outside { servers.session(server) }?.let(::String)
        }
        assertEquals(
            mapOf("logged in" to "session of ws://logged-in.example/ng", "logged in again" to String(ROTATED)),
            found,
        )
    }

    @Test
    fun deletingTheIdentityInUseLogsOutAndForgetsWhatEveryServerKeptForIt() {
        val server = identityServer("in use")
        val other = identityServer("other")
        keepIdentity()
        val device = device()
        val vm = model()
        settle()
        // Kept after the launch, which would resume it.
        saved(other, session = SESSION)
        outside { servers.markRefused(other, device, "revoked") }
        vm.connect(server, null, false)
        settle()
        val conn = opened.single()
        land(conn, identityLoggedIn())
        live(conn)
        settle()
        vm.deleteIdentity(FINGERPRINT)
        assertEquals("logged out at once", true, conn.hungUp)
        settle()
        assertTrue(!kept())
        for (s in listOf(server, other)) assertNull("${s.url}'s session", outside { servers.session(s) })
        assertTrue("its refusals", outside { servers.refusals() }.isEmpty())
    }

    /**
     * The Keystore's part, in memory: a secret is kept as put, or a name
     * fails as [fails] says. Touched by a live model only on the store
     * queue.
     */
    private inner class MemorySecrets : Secrets {
        private val kept = HashMap<String, ByteArray>()

        /** By the start of a secret's name, what opening it throws. */
        val fails = mutableMapOf<String, () -> Exception>()

        /** What keeping any secret throws, if anything. */
        var putFails: (() -> Exception)? = null

        private fun onQueue() = check(!armed || exempt || onDisk) { "a store touched off its queue" }

        override fun put(
            name: String,
            secret: ByteArray,
        ) {
            onQueue()
            putFails?.let { throw it() }
            kept[name] = secret.copyOf()
        }

        override fun get(name: String): ByteArray? {
            onQueue()
            fails.entries.find { name.startsWith(it.key) }?.let { throw it.value() }
            return kept[name]?.copyOf()
        }

        override fun delete(name: String) {
            onQueue()
            kept -= name
        }
    }

    /** Preferences, as [MemorySecrets] holds secrets: touched by a live model only on the store queue. */
    @Test
    fun aDeviceEnrolledIsKeptOnlyOnceThePersonHasSeenWhoseItIs() {
        for (then in listOf("keep", "discard", "cancel while waiting")) {
            fresh()
            val vm = model()
            settle()
            vm.startEnroll(null)
            settle()
            assertEquals(then, Enrolling.Ready(DEVICE), vm.enrollment.value)
            val e = enrollments.single()
            assertNull("$then: a new device", e.renewing)
            vm.requestEnroll("hl.example", "K7PM-4XWE", "Hexline")
            settle()
            assertEquals(then, Triple("hl.example", "K7PM-4XWE", "Hexline"), e.asked)
            assertEquals(then, Enrolling.Waiting(DEVICE), vm.enrollment.value)
            if (then == "cancel while waiting") {
                vm.discardEnroll()
                settle()
                assertTrue("$then: the wait ends and the key goes", e.canceled && e.closed)
                assertTrue(then, stored() == null)
                continue
            }
            core { e.answer.complete(ENROLLED) }
            settle()
            assertEquals(then, Enrolling.Answered(DEVICE, "Fixture", SHORT), vm.enrollment.value)
            assertTrue("$then: nothing kept before the person says", stored() == null)
            if (then == "keep") vm.confirmEnroll() else vm.discardEnroll()
            settle()
            assertTrue("$then: the key is let go of", e.closed)
            if (then == "keep") {
                val kept = stored()!!
                assertEquals(listOf(FINGERPRINT, "Fixture", "hl.example"), listOf(kept.fingerprint, kept.handle, kept.mailbox))
                assertArrayEquals(SEED, outside { identities.device(FINGERPRINT)?.second })
                assertEquals(Enrolling.Done(FINGERPRINT), vm.enrollment.value)
            } else {
                assertNull(then, stored())
            }
        }
    }

    @Test
    fun aRenewalByCodeIsTheDeviceKeptWhileInItsTimeAndANewOneOnceExpired() {
        for (expired in listOf(false, true)) {
            fresh()
            keepIdentity("hl.example")
            now = if (expired) EXPIRES + PAST_SKEW else ISSUED + DAY
            val vm = model()
            settle()
            vm.startEnroll(FINGERPRINT)
            settle()
            val e = enrollments.single()
            if (expired) {
                assertNull("a lapsed certificate enrolls afresh", e.renewing)
                assertArrayEquals("as the same identity's", CERT, e.expecting)
            } else {
                assertArrayEquals(SEED, e.renewing!!.first)
                assertArrayEquals(CERT, e.renewing.second)
            }
        }
    }

    @Test
    fun anEnrollmentAskedForAgainWhileTheFirstReadsItsDeviceLetsTheFirstGo() {
        keepIdentity("hl.example")
        val vm = model()
        settle()
        vm.startEnroll(FINGERPRINT)
        // Its device's read is queued, not made.
        onMain()
        vm.startEnroll(FINGERPRINT)
        settle()
        assertEquals(2, enrollments.size)
        assertTrue("the first is let go of", enrollments[0].closed)
        assertTrue("the second is the one shown", !enrollments[1].closed)
        assertEquals(Enrolling.Ready(DEVICE), vm.enrollment.value)
    }

    @Test
    fun anAnswerForAnIdentityOnThePhoneSaysWhatItReplaces() {
        for (held in listOf(false, true)) {
            fresh()
            if (held) keepIdentity("hl.example")
            val vm = model()
            settle()
            vm.startEnroll(null)
            settle()
            vm.requestEnroll("hl.example", "K7PM-4XWE", "Hexline")
            settle()
            core { enrollments.single().answer.complete(ENROLLED) }
            settle()
            val answered = vm.enrollment.value as Enrolling.Answered
            assertEquals("held $held", held, answered.replaces != null)
        }
    }

    @Test
    fun anAnswerThePhoneCouldNotKeepAsksToStartAgain() {
        val vm = model()
        settle()
        vm.startEnroll(null)
        settle()
        vm.requestEnroll("hl.example", "K7PM-4XWE", "Hexline")
        settle()
        val e = enrollments.single()
        core { e.answer.complete(ENROLLED) }
        settle()
        secrets.putFails = { SecretUnavailable("seed", IOException("locked")) }
        vm.confirmEnroll()
        settle()
        assertEquals(Enrolling.Failed("", EnrollProblem.AnswerNotKept), vm.enrollment.value)
        assertTrue("its device is gone", e.closed)
        secrets.putFails = null
        vm.startEnroll(null)
        settle()
        assertEquals("a new device to ask with", Enrolling.Ready(DEVICE), vm.enrollment.value)
        assertEquals(2, enrollments.size)
    }

    @Test
    fun aSaveConfirmedThenLeftForAnotherEnrollmentDoesNotEndTheOther() {
        val vm = model()
        settle()
        vm.startEnroll(null)
        settle()
        vm.requestEnroll("hl.example", "K7PM-4XWE", "Hexline")
        settle()
        core { enrollments.single().answer.complete(ENROLLED) }
        settle()
        vm.confirmEnroll()
        assertEquals("nothing left to discard", Enrolling.Saving("Fixture", SHORT), vm.enrollment.value)
        // Its save still queued, another begun.
        vm.discardEnroll()
        vm.startEnroll(null)
        settle()
        assertEquals("the second's screen", Enrolling.Ready(DEVICE), vm.enrollment.value)
        assertTrue("the second still open", !enrollments[1].closed)
        assertEquals("the first kept, as the person said", "Fixture", stored()?.handle)
    }

    @Test
    fun aQuietRenewalIsOfTheRecordAsItIsWhenItsDeviceIsRead() {
        keepIdentity("old.example")
        now = ISSUED + (EXPIRES - ISSUED) * 2 / 3 + DAY
        model()
        // The launch's first read, then the renewal's list of what is due.
        onMain()
        onDisk()
        onMain()
        onDisk()
        // Enrolled again through another mailbox before its device is read.
        keepIdentity("new.example")
        settle()
        assertEquals("new.example", enrollments.single().asked?.first)
    }

    @Test
    fun aDueDeviceIsRenewedQuietlyOnceADayWhereAHolderStandsBy() {
        val due = ISSUED + (EXPIRES - ISSUED) * 2 / 3 + DAY
        for (answer in listOf("renewed", "no holder", "unreachable", "not due")) {
            fresh()
            keepIdentity("hl.example")
            // Tried long ago, and found no holder then.
            outside { identities.renewTried(FINGERPRINT, CERT, 1, true) }
            now = if (answer == "not due") ISSUED + DAY else due
            model()
            settle()
            if (answer == "not due") {
                assertTrue(answer, enrollments.isEmpty())
                continue
            }
            val e = enrollments.single()
            assertArrayEquals("$answer: the device it has", SEED, e.renewing!!.first)
            assertEquals(answer, Triple("hl.example", null, "Hexline"), e.asked)
            when (answer) {
                "renewed" -> core { e.answer.complete(ENROLLED) }
                "no holder" -> core { e.answer.completeExceptionally(CoreException.Refused("no_holder", "")) }
                else -> core { e.answer.completeExceptionally(CoreException.Connect("offline")) }
            }
            settle()
            assertTrue("$answer: let go of", e.closed)
            val kept = stored()!!
            when (answer) {
                "renewed" -> assertEquals(answer, listOf(0L, false, "hl.example"), listOf(kept.renewTried, kept.noHolder, kept.mailbox))
                "no holder" -> assertEquals(answer, listOf(due, true), listOf(kept.renewTried, kept.noHolder))
                else -> assertEquals("$answer: not counted", listOf(1L, true), listOf(kept.renewTried, kept.noHolder))
            }
            if (answer == "renewed") continue
            // The app again, the same day, and the next.
            owner.clear()
            settle()
            model()
            settle()
            assertEquals("$answer: asked again the same day", if (answer == "unreachable") 2 else 1, enrollments.size)
            owner.clear()
            settle()
            now += DAY
            model()
            settle()
            assertEquals("$answer: and the next", if (answer == "unreachable") 3 else 2, enrollments.size)
        }
    }

    @Test
    fun aRenewalAnsweredAfterItsIdentityIsDeletedKeepsNothing() {
        keepIdentity("hl.example")
        now = ISSUED + (EXPIRES - ISSUED) * 2 / 3 + DAY
        val vm = model()
        settle()
        val e = enrollments.single()
        vm.deleteIdentity(FINGERPRINT)
        settle()
        core { e.answer.complete(ENROLLED) }
        settle()
        assertNull(stored())
        assertNull(outside { identities.device(FINGERPRINT) })
    }

    /** An enrollment whose holder answers when the test says, as the core's would. */
    private class FakeEnrollment(
        given: Pair<ByteArray, ByteArray>?,
        /** Another device's certificate, whose identity alone an answer may be from. */
        val expecting: ByteArray?,
    ) : Enrollment {
        /** Copied as the core copies it: the caller wipes its own. */
        val renewing = given?.let { it.first.copyOf() to it.second.copyOf() }
        val answer = CompletableDeferred<Enrolled>()
        var asked: Triple<String, String?, String>? = null
        var canceled = false
        var closed = false

        override fun deviceFingerprint() = DEVICE

        override suspend fun enroll(
            mailbox: String,
            code: String?,
            name: String,
        ): Enrolled {
            check(!closed) { "a closed enrollment called" }
            asked = Triple(mailbox, code, name)
            return answer.await()
        }

        override fun cancel() {
            canceled = true
            answer.completeExceptionally(CoreException.Refused("canceled", ""))
        }

        override fun seed() = (renewing?.first ?: SEED).copyOf()

        override fun expectIdentityOf(cert: ByteArray) = error("set when made, by the factory")

        override fun close() {
            closed = true
        }
    }

    private inner class QueuedPrefs(
        private val prefs: SharedPreferences,
    ) : SharedPreferences by prefs {
        private fun <T> onQueue(read: () -> T): T {
            check(!armed || exempt || onDisk) { "preferences touched off the store queue" }
            return read()
        }

        override fun getAll(): Map<String, *> = onQueue { prefs.all }

        override fun getString(
            key: String?,
            defValue: String?,
        ) = onQueue { prefs.getString(key, defValue) }

        override fun getStringSet(
            key: String?,
            defValues: Set<String>?,
        ) = onQueue { prefs.getStringSet(key, defValues) }

        override fun getInt(
            key: String?,
            defValue: Int,
        ) = onQueue { prefs.getInt(key, defValue) }

        override fun getLong(
            key: String?,
            defValue: Long,
        ) = onQueue { prefs.getLong(key, defValue) }

        override fun getFloat(
            key: String?,
            defValue: Float,
        ) = onQueue { prefs.getFloat(key, defValue) }

        override fun getBoolean(
            key: String?,
            defValue: Boolean,
        ) = onQueue { prefs.getBoolean(key, defValue) }

        override fun contains(key: String?) = onQueue { prefs.contains(key) }

        override fun edit(): SharedPreferences.Editor = onQueue { prefs.edit() }
    }

    /**
     * A connection whose login answers when the test says, as the core's
     * does: hung up while connecting, a login that would have landed is
     * closed instead; once closed, nothing it has may be called.
     */
    private class FakeConnection(
        val url: String,
        val sink: UpdateSink,
    ) : Connection {
        val answer = CompletableDeferred<LoginInfo>()

        /** The seed an identity login was given, as it was given. */
        var proved: ByteArray? = null
        var resumedWith: ByteArray? = null
        var password: String? = null
        var hungUp: Boolean? = null
        private var closed = false

        /** The session the core would resume with: none until its first batch. */
        var session: ByteArray? = null

        private fun alive() = check(!closed) { "a closed connection called" }

        private suspend fun answered(): LoginInfo {
            val info = answer.await()
            if (hungUp != null) throw CoreException.Closed()
            return info
        }

        override suspend fun login(
            login: String?,
            password: String?,
            saved: ByteArray?,
        ): LoginInfo {
            alive()
            this.password = password
            resumedWith = saved
            return answered()
        }

        override suspend fun loginIdentity(
            device: DeviceIdentity,
            create: Boolean,
            link: ClassicLogin?,
            saved: ByteArray?,
        ): LoginInfo {
            alive()
            proved = device.deviceSeed.copyOf()
            resumedWith = saved
            return answered()
        }

        override suspend fun chat(text: String) = alive()

        override suspend fun disconnect() = alive()

        override fun hangUp(logout: Boolean) {
            alive()
            hungUp = logout
        }

        override suspend fun history(
            before: ULong?,
            after: ULong?,
            limit: UInt,
        ): HistoryPage {
            alive()
            throw CoreException.Refused("not_available", "")
        }

        override fun networkChanged() = alive()

        override fun saved(): ByteArray? {
            alive()
            return session
        }

        override fun setBackgroundLinger(millis: ULong) = alive()

        override fun setForeground(foreground: Boolean) = alive()

        override fun close() {
            closed = true
        }
    }

    /** A dispatcher that says when it runs, and counts what it has yet to. */
    private class Counted(
        val inner: TestDispatcher,
        val running: (Boolean) -> Unit,
    ) : CoroutineDispatcher(),
        Delay by inner {
        var pending = 0

        override fun dispatch(
            context: CoroutineContext,
            block: Runnable,
        ) {
            pending++
            inner.dispatch(context) {
                pending--
                running(true)
                try {
                    block.run()
                } finally {
                    running(false)
                }
            }
        }
    }

    /**
     * The test's main thread: what is handed to it waits for [onMain], and
     * its [immediate] runs inline when the caller is already on it, as
     * Android's does; only the store queue and the core are not.
     */
    private inner class Main(
        val inner: TestDispatcher,
    ) : MainCoroutineDispatcher(),
        Delay by inner {
        var pending = 0

        override fun dispatch(
            context: CoroutineContext,
            block: Runnable,
        ) {
            pending++
            inner.dispatch(context) {
                pending--
                block.run()
            }
        }

        override val immediate: MainCoroutineDispatcher =
            object :
                MainCoroutineDispatcher(),
                Delay by inner {
                override val immediate get() = this

                override fun isDispatchNeeded(context: CoroutineContext) = onDisk || fromCore

                override fun dispatch(
                    context: CoroutineContext,
                    block: Runnable,
                ) = this@Main.dispatch(context, block)
            }
    }

    private companion object {
        const val SETTLE = 50
        const val DAY = 86_400L

        /** A second past the skew a certificate's time is allowed, as a server allows it. */
        const val PAST_SKEW = 301L

        val SESSION = "a saved session".toByteArray()
        val LATER = "a later session".toByteArray()
        val ROTATED = "a new login's session".toByteArray()
        val LOGGED_IN = LoginInfo("hxd", emptyList(), true, null, null, false)

        fun identityLoggedIn() = LoginInfo("hxd", emptyList(), true, FINGERPRINT, "linked", false)

        fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        // An identity and a device of it, made with hl-identity: the app
        // cannot sign a certificate of its own. The same as IdentitiesTest's.
        val SEED = hex("0202020202020202020202020202020202020202020202020202020202020202")
        val CERT =
            hex(
                "a76176016373696758405824fbeefc383034d005006130620730d74936582d87c31f0c23d13e8f50ce590a1dc6843b5bd7284e197e48c54bd4b219fe4d7c4532a2e4b0f97c10530ceb006664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b49d20067657870697265731a7e15d500686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
            )
        val CARD =
            hex(
                "a561760163736967584067d88dac70a297fd5f414f8df75ac190a6a6d8f78659c342d4259dda59fae16f57c55711d6c0b05b502616b95d286d97b98b518ff50bf4c013db9a915e30fd0e646e616d65674669787475726567757064617465641a6b49d200686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            )
        const val FINGERPRINT = "6htgz65xb7yfs53dmhdanfmk7fgn995n1571rjnz8a36a1fks5z0"
        const val SHORT = "6htgz65x"
        const val DEVICE = "9c41e7b2"
        val ENROLLED get() = Enrolled(CERT, CARD, FINGERPRINT, SHORT, "Fixture")

        // The certificate's own window.
        const val ISSUED = 0x6b49d200L
        const val EXPIRES = 0x7e15d500L
    }
}
