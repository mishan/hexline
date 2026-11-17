package org.foggyden.hexline.chat

import android.app.Application
import android.content.SharedPreferences
import android.net.ConnectivityManager
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewmodel.CreationExtras
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.DisposableHandle
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
import org.foggyden.hexline.core.certForDevice
import org.foggyden.hexline.identity.Enrolling
import org.foggyden.hexline.identity.HeldSeeds
import org.foggyden.hexline.identity.Identities
import org.foggyden.hexline.secrets.FakeHolderKeys
import org.foggyden.hexline.secrets.Secrets
import org.foggyden.hexline.servers.SavedServers
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn
import org.foggyden.hexline.servers.StoreQueue
import org.junit.After
import org.junit.Assert.assertEquals
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.shadows.ShadowConnectivityManager
import java.io.File
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

/**
 * The view model's connections and stores, driven step by step. The main
 * thread and the store queue are each a dispatcher that runs only when
 * told, a task at a time if need be, so a forget or a delete can be made
 * to land between any two of a connection's steps. Main is immediate where
 * the app's is: a call the test makes stands for one from the UI, on the
 * main thread, and runs there until it first waits; what the store queue
 * or the core hands back is dispatched to it. The stores are the real ones
 * over an in-memory stand-in for the Keystore, which refuses to be touched
 * off the queue while a model is alive; the core is a connection whose
 * answers the test gives, from the core's side.
 */
@OptIn(ExperimentalCoroutinesApi::class, InternalCoroutinesApi::class)
abstract class ViewModelHarness {
    protected val app: Application = RuntimeEnvironment.getApplication()

    /** Whether the store queue is running a task, or the core calling in. */
    protected var onDisk = false
    protected var fromCore = false

    protected val main = Main(Stepped())
    protected val disk = Stepped { onDisk = it }

    /** A model is alive, so the stores are the queue's alone. */
    protected var armed = false

    /** The test's own look at the stores, apart from the model's. */
    protected var exempt = false

    protected var cases = 0
    protected var stores = Stores(cases)
    protected val servers get() = stores.servers
    protected val identities get() = stores.identities
    protected val secrets get() = stores.secrets

    protected val opened = mutableListOf<FakeConnection>()
    protected val enrollments = mutableListOf<FakeEnrollment>()

    /** What the store held of the identity's last try when the holder was asked. */
    protected var triedWhenAsked: Long? = null
    protected var now = ISSUED + DAY
    protected var owner = ViewModelStore()

    /** The process's lifecycle the next model is given: whether the app is in front. */
    protected var process = Process()

    protected class Process : LifecycleOwner {
        override val lifecycle = LifecycleRegistry.createUnsafe(this)
    }

    protected val uncaught = mutableListOf<Throwable>()

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
    protected inner class Stores(
        n: Int,
        /** The Keystore's part: another process's stores, given the same, read what this one wrote. */
        val secrets: MemorySecrets = MemorySecrets(),
    ) {
        val servers = SavedServers(app, secrets, QueuedPrefs(app.getSharedPreferences("servers-$n", 0)))
        val identityDir = File(app.filesDir, "identities-$n")
        val identities = Identities(app, secrets, identityDir)
        val keys = FakeHolderKeys()
        val held = HeldSeeds(File(app.filesDir, "held-$n"), keys, EmptyCoroutineContext)
    }

    /** A case's own stores and connections, the model before it cleared. */
    protected fun fresh() {
        owner.clear()
        settle()
        // A model left registered is kept alive, with its stores, for the rest of the run.
        assertEquals("network callbacks a cleared model leaves", 0, networkCallbacks().size)
        // Robolectric also keeps every callback ever registered, and each its
        // model, until the test ends; a run of seeds is one test, so each
        // seed starts as a new test would.
        ShadowConnectivityManager.reset()
        armed = false
        stores = Stores(++cases)
        process = Process()
        opened.clear()
        enrollments.clear()
    }

    /**
     * Lets go of what a killed process registered with the system. In the app
     * it goes with the process; here its model's network callback would stay
     * registered, still called and still keeping the model.
     */
    protected fun forgetDeadProcess() {
        val connectivity = app.getSystemService(ConnectivityManager::class.java)
        for (callback in networkCallbacks()) connectivity.unregisterNetworkCallback(callback)
    }

    private fun networkCallbacks() = shadowOf(app.getSystemService(ConnectivityManager::class.java)).networkCallbacks.toList()

    protected fun model(): ChatViewModel {
        val factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(
                    modelClass: Class<T>,
                    extras: CreationExtras,
                ): T =
                    ChatViewModel(app, servers, identities, stores.held, StoreQueue(disk), { url, sink ->
                        connection(url, sink).also { opened += it }
                    }, { renewing, expecting ->
                        enrollment(renewing, expecting).also { enrollments += it }
                    }, { now }, process.lifecycle) as T
            }
        armed = true
        return ViewModelProvider.create(owner, factory)[ChatViewModel::class.java]
    }

    /** The core's connection to [url], as the model asks for it. */
    protected open fun connection(
        url: String,
        sink: UpdateSink,
    ) = FakeConnection(url, sink)

    /** An enrollment, as the model asks for one. */
    protected open fun enrollment(
        renewing: Pair<ByteArray, ByteArray>?,
        expecting: String?,
    ) = FakeEnrollment(renewing, expecting) { triedWhenAsked = outside { identities.list().singleOrNull()?.renewTried } }

    protected fun <T> outside(look: () -> T): T {
        exempt = true
        try {
            return look()
        } finally {
            exempt = false
        }
    }

    protected fun core(call: () -> Unit) {
        fromCore = true
        try {
            call()
        } finally {
            fromCore = false
        }
    }

    /** The main thread's work so far, up to its next wait on the store. */
    protected fun onMain() = main.queue.drain()

    /** The store's work so far. */
    protected fun onDisk() = disk.drain()

    /** Everything, until neither has anything left to run. */
    protected fun settle() {
        repeat(SETTLE) {
            onMain()
            onDisk()
            if (main.pending == 0 && disk.pending == 0) return
        }
        error("still busy after $SETTLE rounds")
    }

    /** [conn]'s login landing, as the core answers it. */
    protected fun land(
        conn: FakeConnection,
        info: LoginInfo,
    ) = core { conn.answer.complete(info) }

    protected fun refuse(
        conn: FakeConnection,
        e: CoreException,
    ) = core { conn.answer.completeExceptionally(e) }

    /**
     * [conn]'s first batch, and only after it, as the core keeps it, the
     * session to resume with: the model has handled the batch by then.
     */
    protected fun live(
        conn: FakeConnection,
        session: ByteArray? = "session of ${conn.url}".toByteArray(),
    ) {
        core { conn.sink.deliver(listOf(CoreUpdate.Roster(1u, emptyList(), ""))) }
        onMain()
        sessionKept(conn, session)
    }

    /** [conn]'s link's session, kept and told, as the core does once a link's first batch is handed over. */
    protected fun sessionKept(
        conn: FakeConnection,
        session: ByteArray?,
    ) {
        conn.session = session
        if (session != null) core { conn.sink.deliver(listOf(CoreUpdate.SessionKept)) }
    }

    /** [conn]'s last batch, [updates]: the core keeps no session after it. */
    protected fun over(
        conn: FakeConnection,
        updates: List<CoreUpdate>,
    ) {
        conn.session = null
        core { conn.sink.deliver(updates) }
    }

    protected fun kept() = outside { identities.list().any { it.fingerprint == FINGERPRINT } }

    protected fun device() =
        outside {
            identities
                .list()
                .single()
                .info.device
        }

    protected fun keepIdentity(mailbox: String? = null) =
        outside { identities.save(SEED.copyOf(), CERT, CARD, "alice@example", null, mailbox) }

    protected fun stored() = outside { identities.list().singleOrNull() }

    /** The run the enroll screen shows, which a tap answers to. */
    protected fun gen(vm: ChatViewModel) =
        when (val e = vm.enrollment.value) {
            is Enrolling.Ready -> e.gen
            is Enrolling.Failed -> e.gen
            is Enrolling.Answered -> e.gen
            else -> -1
        }

    /** Keep, as the screen asks it: for the run and the identity shown. */
    protected fun confirm(vm: ChatViewModel) {
        val shown = vm.enrollment.value as Enrolling.Answered
        vm.confirmEnroll(shown.gen, shown.fingerprint)
    }

    protected fun shownAs(vm: ChatViewModel): String =
        when (val e = vm.enrollment.value) {
            is Enrolling.Ready -> "ready ${e.device}"
            is Enrolling.Waiting -> "waiting ${e.device}"
            is Enrolling.Saving -> "saving ${e.name}"
            is Enrolling.Failed -> "failed ${e.device} ${e.problem}"
            is Enrolling.Done -> "done ${e.fingerprint}"
            else -> e.toString()
        }

    protected fun saved(
        server: Server,
        password: String? = null,
        session: ByteArray? = null,
    ) = outside {
        servers.remember(server, password)
        session?.let { servers.keepSession(server, it) }
    }

    protected fun identityServer(name: String) =
        Server("ws://${name.replace(Regex("[^a-z0-9]+"), "-")}.example/ng", null, SignIn.Identity(FINGERPRINT))

    protected fun passwordServer(name: String) =
        Server("ws://${name.replace(Regex("[^a-z0-9]+"), "-")}.example/ng", "alice", SignIn.Password)

    /**
     * The Keystore's part, in memory: a secret is kept as put, or a name
     * fails as [fails] says. Touched by a live model only on the store
     * queue.
     */
    protected inner class MemorySecrets : Secrets {
        private val kept = HashMap<String, ByteArray>()

        /** By the start of a secret's name, what opening it throws. */
        val fails = mutableMapOf<String, () -> Exception>()

        /** What keeping any secret throws, if anything. */
        var putFails: (() -> Exception)? = null

        /** The names of the secrets kept, in order, each time one is. */
        val puts = mutableListOf<String>()

        private fun onQueue() = check(!armed || exempt || onDisk) { "a store touched off its queue" }

        override fun put(
            name: String,
            secret: ByteArray,
        ) {
            onQueue()
            putFails?.let { throw it() }
            puts += name
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
    protected inner class QueuedPrefs(
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

    /** An enrollment whose holder answers when the test says, as the core's would. */
    protected open class FakeEnrollment(
        given: Pair<ByteArray, ByteArray>?,
        /** The identity alone an answer may be from, held to it as the core holds it. */
        val expecting: String?,
        /** Told as the holder is asked. */
        val onAsk: () -> Unit = {},
    ) : Enrollment {
        /** Copied as the core copies it: the caller wipes its own. */
        val renewing = given?.let { it.first.copyOf() to it.second.copyOf() }

        /** The seed the model handed over, as handed: the model's to wipe. */
        val given = given?.first

        /** Every seed this gave out, as given: each the model's to wipe. */
        val handed = mutableListOf<ByteArray>()
        val answer = CompletableDeferred<Enrolled>()
        var asked: Triple<String, String?, String>? = null
        var canceled = false
        var closed = false

        /** Whether its request was sent: once asked, unless the test says not. */
        var posted = false
        private var inFlight = false

        override fun deviceFingerprint() = DEVICE

        override suspend fun enroll(
            mailbox: String,
            code: String?,
            name: String,
        ): Enrolled {
            check(!closed) { "a closed enrollment called" }
            if (inFlight) throw CoreException.Refused("busy", "")
            inFlight = true
            onAsk()
            asked = Triple(mailbox, code, name)
            posted = true
            try {
                val got = answer.await()
                if (expecting != null && got.fingerprint != expecting) throw CoreException.Refused("wrong_identity", "")
                refuses(got)?.let { throw it }
                return got
            } finally {
                inFlight = false
            }
        }

        override fun cancel() {
            canceled = true
            answer.completeExceptionally(CoreException.Refused("canceled", ""))
        }

        /** What else the core would refuse [got] for; nothing, unless a test says. */
        open fun refuses(got: Enrolled): CoreException? = null

        override fun seed() = (renewing?.first ?: SEED).copyOf().also { handed += it }

        override fun expectIdentity(fingerprint: String) = error("set when made, by the factory")

        override fun mayHaveAsked() = posted

        override fun close() {
            closed = true
        }
    }

    /**
     * A connection whose login answers when the test says, as the core's
     * does: hung up while connecting, a login that would have landed is
     * closed instead; once closed, nothing it has may be called.
     */
    protected open class FakeConnection(
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

        /** Every seed a login was handed, as handed: the model's to wipe once the login is over. */
        val seeds = mutableListOf<ByteArray>()

        /** The account an identity login was to link, as it was given. */
        var linked: ClassicLogin? = null

        /** Asked to log in, and what came of it once it had answered. */
        var loginAsked = false
        var outcome: Result<LoginInfo>? = null
        val isClosed get() = closed

        private suspend fun answered(): LoginInfo {
            loginAsked = true
            val got =
                runCatching {
                    val info = answer.await()
                    if (hungUp != null) throw CoreException.Closed()
                    info
                }
            outcome = got
            return got.getOrThrow()
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
            seeds += device.deviceSeed
            linked = link
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

    /**
     * A dispatcher whose tasks wait in order until the test runs them, one
     * at a time or all, and that says while it runs one. Delays go to
     * [inner]'s clock, which only [drain] moves.
     */
    protected open class Stepped(
        val running: (Boolean) -> Unit = {},
    ) : CoroutineDispatcher(),
        Delay {
        private val tasks = ArrayDeque<Runnable>()
        val pending get() = tasks.size

        /** Where its waits are timed; a process that dies takes its own with it. */
        private var inner: TestDispatcher = StandardTestDispatcher(TestCoroutineScheduler())

        override fun scheduleResumeAfterDelay(
            timeMillis: Long,
            continuation: CancellableContinuation<Unit>,
        ) = (inner as Delay).scheduleResumeAfterDelay(timeMillis, continuation)

        override fun invokeOnTimeout(
            timeMillis: Long,
            block: Runnable,
            context: CoroutineContext,
        ): DisposableHandle = (inner as Delay).invokeOnTimeout(timeMillis, block, context)

        override fun dispatch(
            context: CoroutineContext,
            block: Runnable,
        ) {
            tasks.addLast(block)
        }

        /** The oldest task, run; false if there was none. */
        fun step(): Boolean {
            val task = tasks.removeFirstOrNull() ?: return false
            running(true)
            try {
                task.run()
            } finally {
                running(false)
            }
            return true
        }

        /** Every task, those they hand on included, until none is left. */
        fun drain() {
            do {
                while (step()) continue
                inner.scheduler.advanceUntilIdle()
            } while (tasks.isNotEmpty())
        }

        /**
         * Every task waiting, never run: the process they were for has gone.
         * Its waits go too, or a later [drain] would end them and run what
         * the dead process meant to do after.
         */
        fun drop() {
            tasks.clear()
            inner = StandardTestDispatcher(TestCoroutineScheduler())
        }
    }

    /**
     * The test's main thread: what is handed to it waits for [onMain], and
     * its [immediate] runs inline when the caller is already on it, as
     * Android's does; only the store queue and the core are not.
     */
    protected inner class Main(
        val queue: Stepped,
    ) : MainCoroutineDispatcher(),
        Delay by queue {
        val pending get() = queue.pending

        override fun dispatch(
            context: CoroutineContext,
            block: Runnable,
        ) = queue.dispatch(context, block)

        override val immediate: MainCoroutineDispatcher =
            object :
                MainCoroutineDispatcher(),
                Delay by queue {
                override val immediate get() = this

                override fun isDispatchNeeded(context: CoroutineContext) = onDisk || fromCore

                override fun dispatch(
                    context: CoroutineContext,
                    block: Runnable,
                ) = this@Main.dispatch(context, block)
            }
    }

    protected companion object {
        const val SETTLE = 50
        const val DAY = 86_400L
        const val HOUR = 3_600L

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
        val ENROLLED get() = enrolled(CERT)

        fun enrolled(
            cert: ByteArray,
            fingerprint: String = FINGERPRINT,
        ) = Enrolled(cert, CARD, fingerprint, fingerprint.take(8), "Fixture", certForDevice(cert, CARD, SEED))

        // The same device, certified again a month on.
        val RENEWED =
            hex(
                "a76176016373696758401b505586185f8c75833ebd49142220abd7461d5b86f995c866c989c28073293088d79e95b6cc118dcc756f9b07d979ad335ff585eee4adefa85a2d22beb4a0016664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b715f0067657870697265731a7e3d6200686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
            )

        // The certificate's own window.
        const val ISSUED = 0x6b49d200L
        const val EXPIRES = 0x7e15d500L
    }
}
