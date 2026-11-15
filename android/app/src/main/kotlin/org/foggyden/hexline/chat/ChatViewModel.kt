package org.foggyden.hexline.chat

import android.app.Application
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Handler
import android.os.Looper
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.foggyden.hexline.core.ClassicLogin
import org.foggyden.hexline.core.Connection
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.DeviceIdentity
import org.foggyden.hexline.core.LoginInfo
import org.foggyden.hexline.core.Restored
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.UpdateSink
import org.foggyden.hexline.core.coreConnection
import org.foggyden.hexline.core.refusalLasts
import org.foggyden.hexline.core.restoreIdentity
import org.foggyden.hexline.identity.Identities
import org.foggyden.hexline.identity.RestoreProblem
import org.foggyden.hexline.identity.Restoring
import org.foggyden.hexline.identity.Standing
import org.foggyden.hexline.identity.StoredIdentity
import org.foggyden.hexline.identity.restoreProblem
import org.foggyden.hexline.identity.standing
import org.foggyden.hexline.secrets.SecretUnavailable
import org.foggyden.hexline.servers.SavedServers
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn
import org.foggyden.hexline.servers.StoreQueue
import java.io.IOException

/**
 * One server's connection and what its screen shows. The session outlives
 * the screen: in the background the core keeps it detached, and what
 * resumes it is saved, so the app picks it up where it was when it comes
 * back, even in a new process.
 *
 * Everything here but [state] is touched on the main thread alone: the
 * core's batches and the network's callbacks are brought to it.
 */
class ChatViewModel internal constructor(
    app: Application,
    private val servers: SavedServers,
    private val identities: Identities,
    /**
     * Where every read and write of [servers] and [identities] this makes
     * is made. A forget or a delete lets go of what it names on the main
     * thread before it asks for its own work, so queue order is the main
     * thread's. A write the person may leave before it is made is asked
     * for on [StoreQueue.scope], which outlives this.
     */
    private val queue: StoreQueue,
    private val open: (url: String, sink: UpdateSink) -> Connection,
    /** Seconds since the epoch, that a certificate's time is judged by. */
    private val now: () -> Long,
) : AndroidViewModel(app) {
    /** The one the app makes: its own stores, the process's queue, the core's connections and the clock. */
    constructor(app: Application) : this(
        app,
        SavedServers(app),
        Identities(app),
        StoreQueue.process,
        ::coreConnection,
        { System.currentTimeMillis() / 1000 },
    )

    private val store = queue.dispatcher

    private fun later(work: () -> Unit) = queue.scope.launch { work() }

    private val state = MutableStateFlow(ChatState())
    val chat: StateFlow<ChatState> = state

    private val savedServers = MutableStateFlow<List<Server>>(emptyList())

    /** The servers connected to, the last first, to offer again. */
    val saved: StateFlow<List<Server>> = savedServers

    private val kept = MutableStateFlow<List<StoredIdentity>>(emptyList())

    /** The identities this phone is a device of. */
    val identityList: StateFlow<List<StoredIdentity>> = kept

    private val refused = MutableStateFlow<Map<String, String>>(emptyMap())

    /** What servers refused this phone's devices as, by [org.foggyden.hexline.servers.refusalKey]. */
    val refusals: StateFlow<Map<String, String>> = refused

    private val restoring = MutableStateFlow<Restoring>(Restoring.Idle)
    val restore: StateFlow<Restoring> = restoring

    // Read from the store queue too, to see a forget that came first.
    @Volatile private var connection: Connection? = null
    private var server: Server? = null

    /**
     * One connection asked for (a connect, the resume at launch), from the
     * moment it is asked, on the main thread before anything waits, to its
     * login landing or failing. A forget or a delete that could name it
     * lets go of it, on the main thread before its own work, and every
     * step after a wait asks [live] first: nothing is started, proved, or
     * kept for a server or an identity let go of. [server] is null while
     * the launch's resume has yet to read which server it is, and any
     * forget or delete lets go of it then.
     */
    private class Attempt(
        var server: Server?,
    ) {
        @Volatile var live = true
    }

    /** Every attempt not yet over; on the main thread. */
    private val attempts = mutableListOf<Attempt>()

    /** The attempt [connection] came of: let go of with it. */
    private var current: Attempt? = null

    private fun attempt(server: Server?) = Attempt(server).also { attempts += it }

    private fun letGo(a: Attempt) {
        a.live = false
        attempts -= a
    }

    /**
     * Lets go of every attempt [names] could be, and the connection if it
     * is one of them: that one through [leave], which logs it out.
     */
    private fun letGo(names: (Server) -> Boolean) {
        for (a in attempts.filter { a -> a !== current && (a.server?.let(names) ?: true) }) letGo(a)
        if (server?.let(names) == true) leave()
    }

    /** The connection has been live: what it saves from now on is its own. */
    private var established = false
    private var foreground = true

    /**
     * One sink per connection, so a late batch from one no longer current
     * changes nothing. Called on a core thread: `update` is atomic, so the
     * batch is applied whole and in order, and the call returns at once, as
     * the core asks.
     */
    private inner class Sink(
        val server: Server,
        /** When its connect was asked for, a [SavedServers.generation]. */
        val since: Long,
    ) : UpdateSink {
        /** The device an identity login proved: the one to mark if a later login is refused. */
        @Volatile var device: ByteArray? = null

        override fun deliver(updates: List<CoreUpdate>) {
            var before: ChatState? = null
            state.update { s ->
                if (sink !== this) return
                before = s
                updates.fold(s) { acc, u -> acc.apply(u) }
            }
            val wasConnecting = before?.link == Link.Connecting
            val kept = updates.any { it is CoreUpdate.SessionKept }
            // A login after a lapse, refused by the server.
            val refused = updates.firstNotNullOfOrNull { (it as? CoreUpdate.Refused)?.code }
            // Kicked, replaced, refused after a lapse, or a new login made by
            // the core that will not survive one: nothing will resume it.
            // Forgotten from here, so a screen that goes before the main
            // thread hears of it cannot keep it.
            val over =
                updates.any {
                    (it is CoreUpdate.Closed && !it.canResume) ||
                        (it is CoreUpdate.Reconnected && it.info?.canResume == false)
                }
            if (over && !state.value.leaving) {
                val at = servers.generation()
                later { servers.forgetSession(server, at) }
            }
            viewModelScope.launch {
                if (refused != null) markRefused(server, device, refused, since)
                if (sink !== this@Sink) return@launch
                if (kept) save()
                // The first page waits for the roster that makes the link live.
                if (wasConnecting && state.value.link == Link.Live) loadEarlier()
                if (state.value.fillAfter != null && state.value.link == Link.Live) fill()
            }
        }
    }

    @Volatile private var sink: Sink? = null

    private val connectivity = app.getSystemService(ConnectivityManager::class.java)

    // On the main thread; the core rate-limits, so every change is passed on.
    private val network =
        object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = nudge()

            override fun onCapabilitiesChanged(
                network: Network,
                capabilities: NetworkCapabilities,
            ) = nudge()

            override fun onLost(network: Network) = nudge()
        }

    private fun nudge() = connection?.networkChanged() ?: Unit

    // The process's, not an activity's: a rotation is not the app going away.
    private val lifecycle =
        object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = foreground(true)

            override fun onStop(owner: LifecycleOwner) = foreground(false)
        }

    init {
        connectivity.registerDefaultNetworkCallback(network, Handler(Looper.getMainLooper()))
        ProcessLifecycleOwner.get().lifecycle.addObserver(lifecycle)
        val ask = attempt(null)
        val since = servers.generation()
        viewModelScope.launch {
            val found =
                withContext(store) {
                    publishIdentities()
                    publishRefusals()
                    publishServers()
                    servers.last()?.let { Triple(it, servers.session(it), servers.password(it)) }
                }
            // A session left without leaving: take it up again, unless let go of while it was read.
            if (found == null || found.second == null || !ask.live) {
                end(ask)
                return@launch
            }
            val (last, session, password) = found
            ask.server = last
            start(last, password, null, session, keep = password, since = since, ask = ask)
        }
    }

    private fun end(ask: Attempt) {
        attempts -= ask
    }

    /**
     * Connects to [wanted], with [link] an existing account's login to link
     * an identity to. A saved server's kept password stands in for none
     * typed, and its session is resumed rather than a second made beside it.
     */
    fun connect(
        wanted: Server,
        password: String?,
        remember: Boolean,
        link: ClassicLogin? = null,
    ) {
        // The last asked for takes the place of any not yet started; one
        // started is the connection's, let go of only by leaving it.
        for (a in attempts.filter { it !== current }) letGo(a)
        val ask = attempt(wanted)
        val since = servers.generation()
        viewModelScope.launch {
            val (kept, saved) =
                if (wanted in savedServers.value) {
                    withContext(store) { servers.password(wanted) to servers.session(wanted).takeIf { link == null } }
                } else {
                    null to null
                }
            // Let go of while its secrets were read.
            if (!ask.live) return@launch end(ask)
            start(wanted, password ?: kept, link, saved, passwordToKeep(password, kept, remember), since, ask)
        }
    }

    /**
     * Forgets [server], and lets go of its connection if it has one, so
     * nothing it does after (a login landing, a session saved on the way
     * out) remembers it again.
     */
    fun forget(server: Server) {
        // Forgetting a server is leaving it: no session is left behind that
        // nothing will resume or end.
        letGo { it == server }
        val at = servers.generation()
        later {
            servers.forget(server, at)
            publishRefusals()
            publishServers()
        }
    }

    /** Makes this phone a device of the identity a registrar keeps for [handle]. */
    fun restore(
        registrar: String,
        handle: String,
        kind: SecretKind,
        secret: String,
        deviceName: String,
    ) {
        if (restoring.value == Restoring.Working) return
        restoring.value = Restoring.Working
        viewModelScope.launch {
            var made: Restored? = null
            // Once the store's task has the seed, it is that task's to wipe.
            var handed = false
            restoring.value =
                try {
                    val device = restoreIdentity(registrar, handle, kind, secret, deviceName).also { made = it }
                    val at = servers.generation()
                    handed = true
                    queue.scope
                        .async {
                            try {
                                val replaced =
                                    identities
                                        .list()
                                        .find { it.fingerprint == device.fingerprint }
                                        ?.info
                                        ?.device
                                identities.save(device.seed, device.cert, device.card, handle, registrar)
                                // The new device starts with no server's refusal; the old one's go with it.
                                replaced?.let {
                                    servers.forgetRefusalsOf(it, at)
                                    publishRefusals()
                                }
                                publishIdentities()
                            } finally {
                                device.seed.fill(0)
                            }
                        }.await()
                    Restoring.Done(device.fingerprint)
                } catch (e: CoreException) {
                    Restoring.Failed(restoreProblem(e))
                } catch (_: SecretUnavailable) {
                    Restoring.Failed(RestoreProblem.NotKept)
                } catch (_: IOException) {
                    Restoring.Failed(RestoreProblem.NotKept)
                } finally {
                    if (!handed) made?.seed?.fill(0)
                }
        }
    }

    fun restoreSeen() {
        if (restoring.value != Restoring.Working) restoring.value = Restoring.Idle
    }

    /** Logs out of the current connection and lets go of it. */
    private fun leave() {
        current?.let(::letGo)
        current = null
        sink = null
        connection?.let {
            it.hangUp(true)
            it.close()
        }
        connection = null
        this.server = null
        state.value = ChatState()
    }

    /**
     * Forgets [fingerprint]'s identity, its device's seed, and what every
     * saved server kept for it (a session, a refusal), and logs out of the
     * current connection if it is signed in as it.
     */
    fun deleteIdentity(fingerprint: String) {
        val signedIn = SignIn.Identity(fingerprint)
        // A connect asked for after this reads the device after it, and finds none.
        letGo { it.signIn == signedIn }
        // Asked for now: what a login asked for after this keeps is not this delete's to clear.
        val since = servers.generation()
        later {
            val device =
                identities
                    .list()
                    .find { it.fingerprint == fingerprint }
                    ?.info
                    ?.device
            identities.delete(fingerprint)
            publishIdentities()
            for (s in servers.all().filter { it.signIn == signedIn }) servers.forgetSession(s, since)
            device?.let { servers.forgetRefusalsOf(it, since) }
            publishRefusals()
        }
    }

    /**
     * Forgets [server]'s refusal of [fingerprint]'s device, so a login
     * tries it there again: the server may have lifted it.
     */
    fun tryAgain(
        server: Server,
        fingerprint: String,
    ) {
        later {
            identities.list().find { it.fingerprint == fingerprint }?.let { servers.forgetRefusal(server, it.info.device) }
            publishRefusals()
        }
    }

    // Called on the store queue alone, so a slower read is never shown over a newer one.
    private fun publishIdentities() {
        kept.value = identities.list()
    }

    private fun publishServers() {
        savedServers.value = servers.all()
    }

    private fun publishRefusals() {
        refused.value = servers.refusals()
    }

    /**
     * Keeps [server]'s refusal of [device] when only a new device answers
     * it: that device is not offered to sign in there again, and is
     * everywhere else.
     */
    private fun markRefused(
        server: Server,
        device: ByteArray?,
        code: String,
        since: Long,
    ) {
        if (server.signIn !is SignIn.Identity || device == null || !refusalLasts(code)) return
        later {
            servers.markRefused(server, device, code, since)
            publishRefusals()
        }
    }

    private class NoIdentity : Exception()

    /** An identity this phone will not sign in to [to] with, and why. */
    private class Unusable(
        val why: Why,
    ) : Exception()

    /**
     * Logs in to [to] as the identity [fingerprint] names, its seed wiped
     * once handed over; not with a certificate outside its time, nor a
     * device [to] refused, and not resumed with either.
     */
    private suspend fun loginIdentity(
        conn: Connection,
        ask: Attempt,
        to: Server,
        fingerprint: String,
        create: Boolean,
        link: ClassicLogin?,
        saved: ByteArray?,
        proving: (ByteArray) -> Unit,
    ): LoginInfo {
        // Held outside the read, so a cancellation after it still wipes it.
        var seed: ByteArray? = null
        try {
            val (stored, mine) =
                withContext(store) { identities.device(fingerprint)?.also { seed = it.second } }
                    ?: throw NoIdentity()
            when (standing(stored, now())) {
                Standing.Expired -> throw Unusable(Why.CertExpired)
                Standing.NotYetValid -> throw Unusable(Why.CertNotYetValid)
                else -> {}
            }
            withContext(store) { servers.refused(to, stored.info.device) }?.let { throw Unusable(refusal(it)) }
            // Let go of while the reads were made: nothing is proved for it,
            // and its connection, closed, would take no call.
            if (!ask.live) throw CancellationException("let go of")
            proving(stored.info.device)
            return conn.loginIdentity(DeviceIdentity(mine, stored.cert, stored.card), create, link, saved)
        } finally {
            seed?.fill(0)
        }
    }

    private fun start(
        to: Server,
        password: String?,
        link: ClassicLogin?,
        saved: ByteArray?,
        keep: String?,
        since: Long,
        ask: Attempt,
    ) {
        if (state.value.link.let { it == Link.Connecting || it == Link.Live || it is Link.Reconnecting }) return end(ask)
        state.value = ChatState(link = Link.Connecting)
        current?.let(::letGo)
        current = ask
        connection?.let {
            connection = null
            it.close()
        }
        val mine = Sink(to, since)
        sink = mine
        val conn = open(to.url, mine)
        conn.setForeground(foreground)
        connection = conn
        server = to
        established = false
        viewModelScope.launch {
            try {
                val info =
                    when (val how = to.signIn) {
                        SignIn.Password -> conn.login(loginFor(to, password, saved), password, saved)
                        is SignIn.Identity -> {
                            // An account named to link and not linked yet is
                            // never made in its place.
                            val asked = link != null || withContext(store) { servers.linkAsked(to) }
                            loginIdentity(conn, ask, to, how.fingerprint, !asked, link, saved) { mine.device = it }
                        }
                    }
                // Let go of while logging in: nothing of it is kept.
                if (!ask.live) return@launch
                established = true
                state.update { if (info.resumed) it.copy(outcome = info.outcome) else it.signedIn(info.outcome) }
                later {
                    if (!ask.live) return@later
                    if (!servers.remember(to, keep.takeIf { to.signIn == SignIn.Password }, since)) return@later
                    if (to.signIn is SignIn.Identity && !info.resumed) {
                        servers.askedToLink(to, info.outcome != "linked" && (link != null || servers.linkAsked(to)), since)
                    }
                    publishServers()
                }
                // Queued after the remember, which a session is kept only beside.
                save()
                // A session the server will not let survive a lapse is no session to keep.
                if (!info.canResume) later { servers.forgetSession(to, since) }
            } catch (_: NoIdentity) {
                if (!ask.live) return@launch
                state.update { it.copy(link = Link.Ended(Why.NoIdentity)) }
            } catch (e: Unusable) {
                if (!ask.live) return@launch
                state.update { it.copy(link = Link.Ended(e.why)) }
            } catch (_: SecretUnavailable) {
                if (!ask.live) return@launch
                state.update { it.copy(link = Link.Ended(Why.KeyLocked)) }
            } catch (e: CoreException) {
                val code = (e as? CoreException.Refused)?.code
                // Kept whether or not this is still the connection: the
                // server said it of this device, and a forget since is
                // honored by the generation.
                if (code != null) markRefused(to, mine.device, code, since)
                if (!ask.live) return@launch
                later {
                    // Refused for good: the saved session is not coming back.
                    // Busy or unreachable, it may yet.
                    // Its own to clear: not if let go of since, nor what a newer login kept.
                    if (!ask.live) return@later
                    if (saved != null && code != null && !keepsSession(code)) servers.forgetSession(to, since)
                    if (code == "login_failed") servers.forgetPassword(to, since)
                }
                if (!ask.live) return@launch
                state.update { it.copy(link = Link.Ended(why(e))) }
            } finally {
                end(ask)
            }
        }
    }

    fun send(text: String) {
        val conn = connection ?: return
        if (text.isBlank()) return
        viewModelScope.launch {
            try {
                conn.chat(text)
            } catch (e: CoreException) {
                state.update { it.notSent(why(e)) }
            }
        }
    }

    private var loading = false

    fun loadEarlier() {
        val conn = connection ?: return
        if (loading || !state.value.earlierToLoad || state.value.link != Link.Live) return
        loading = true
        viewModelScope.launch {
            try {
                val page = conn.history(state.value.oldestId, null, PAGE)
                state.update { it.withEarlier(page.lines, page.hasMore) }
            } catch (e: CoreException) {
                // A server that keeps no history has none to load; anything
                // else is worth trying again when the reader scrolls back.
                if (e is CoreException.Refused && e.code == "not_available") {
                    state.update { it.copy(earlierToLoad = false) }
                }
            } finally {
                loading = false
            }
        }
    }

    private var filling = false

    /** The lines said while the link was down, a page at a time, up to a bound. */
    private suspend fun fill() {
        val conn = connection ?: return
        if (filling) return
        filling = true
        try {
            var pages = 0
            while (true) {
                val after = state.value.fillAfter ?: return
                if (pages == FILL_PAGES) {
                    state.update { it.withMissed() }
                    return
                }
                // Let go of while it waited: a closed connection takes no call.
                if (connection !== conn) return
                try {
                    val page = conn.history(null, after, FILL_PAGE)
                    state.update { it.withLater(page.lines, page.hasMore) }
                    pages++
                } catch (e: CoreException) {
                    when {
                        e is CoreException.Refused && e.code == "not_available" -> {
                            state.update { it.withMissed() }
                            return
                        }
                        // Paged too fast: wait, and go on.
                        e is CoreException.Refused && e.code == "rate_limited" -> delay(FILL_WAIT)
                        // The link went; the next batch from a live one tries again.
                        else -> return
                    }
                }
            }
        } finally {
            filling = false
        }
    }

    private fun foreground(foreground: Boolean) {
        this.foreground = foreground
        connection?.setForeground(foreground)
        if (!foreground) save()
    }

    /**
     * Writes what resumes the session, once the connection has been live and
     * unless the person is leaving: before that, none is what it has, and a
     * session kept from before must not be overwritten with nothing.
     */
    private fun save() {
        val (conn, to) = (connection ?: return) to (server ?: return)
        if (!established || state.value.leaving) return
        // None until the core's first batch: not a reason to forget the one kept.
        val saved = conn.saved() ?: return
        // Asked for now: a clear that comes first wins, even if this write lands after it.
        val since = servers.generation()
        later { servers.keepSession(to, saved, since) }
    }

    fun disconnect() {
        val (conn, to) = (connection ?: return) to (server ?: return)
        state.update { it.copy(leaving = true) }
        val at = servers.generation()
        viewModelScope.launch {
            // Forgotten first, so a process gone before the logout lands does
            // not wake up in the chat the person left.
            later { servers.forgetSession(to, at) }.join()
            // Let go of meanwhile (a forget, a delete), which logged it out already.
            if (connection === conn) conn.disconnect()
        }
    }

    // The scope is already cancelled here: save what resumes the session
    // on the store queue, which outlives this, hang up leaving it to be
    // resumed, and let the core finish on its own threads.
    override fun onCleared() {
        connectivity.unregisterNetworkCallback(network)
        ProcessLifecycleOwner.get().lifecycle.removeObserver(lifecycle)
        sink = null
        val (conn, to) = (connection ?: return) to (server ?: return)
        connection = null
        val leaving = state.value.leaving
        val saved = conn.saved().takeIf { established && !leaving }
        conn.hangUp(leaving)
        conn.close()
        val since = servers.generation()
        // Leaving, the kept one goes; staying, the core's, once it has one.
        if (leaving || saved != null) later { servers.keepSession(to, saved, since) }
    }

    private fun why(e: CoreException): Why =
        when (e) {
            is CoreException.Connect -> Why.Unreachable
            is CoreException.Refused -> refusal(e.code)
            is CoreException.Protocol -> Why.NotUnderstood
            is CoreException.RateLimited -> Why.Refused("rate_limited")
            is CoreException.Closed, is CoreException.Busy -> Why.Lost
        }

    private companion object {
        const val PAGE = 50u
        const val FILL_PAGE = 200u
        const val FILL_PAGES = 5
        const val FILL_WAIT = 2_000L
    }
}
