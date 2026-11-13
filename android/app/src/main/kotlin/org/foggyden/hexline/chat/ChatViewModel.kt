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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.ServerConnection
import org.foggyden.hexline.core.UpdateSink
import org.foggyden.hexline.servers.SavedServers
import org.foggyden.hexline.servers.Server
import kotlin.concurrent.thread

/**
 * One server's connection and what its screen shows. The session outlives
 * the screen: in the background the core keeps it detached, and what
 * resumes it is saved, so the app picks it up where it was when it comes
 * back, even in a new process.
 *
 * Everything here but [state] is touched on the main thread alone: the
 * core's batches and the network's callbacks are brought to it.
 */
class ChatViewModel(
    app: Application,
) : AndroidViewModel(app) {
    private val servers = SavedServers(app)
    private val state = MutableStateFlow(ChatState())
    val chat: StateFlow<ChatState> = state

    private val lastServer = MutableStateFlow<Server?>(null)

    /** The server last connected to, to offer again. */
    val last: StateFlow<Server?> = lastServer

    private var connection: ServerConnection? = null
    private var server: Server? = null

    /** The connection has been live: what it saves from now on is its own. */
    private var established = false
    private var foreground = true

    /**
     * One sink per connection, so a late batch from one no longer current
     * changes nothing. Called on a core thread: `update` is atomic, so the
     * batch is applied whole and in order, and the call returns at once, as
     * the core asks.
     */
    private inner class Sink : UpdateSink {
        override fun deliver(updates: List<CoreUpdate>) {
            var before: ChatState? = null
            state.update { s ->
                if (sink !== this) return
                before = s
                updates.fold(s) { acc, u -> acc.apply(u) }
            }
            val wasConnecting = before?.link == Link.Connecting
            val reconnected = updates.any { it is CoreUpdate.Reconnected }
            viewModelScope.launch {
                if (sink !== this@Sink) return@launch
                // The first page waits for the roster that makes the link live.
                if (wasConnecting && state.value.link == Link.Live) loadEarlier()
                // A new login made by the core has a new session to keep.
                if (reconnected) save()
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
        viewModelScope.launch {
            val found =
                withContext(Dispatchers.IO) {
                    servers.last()?.let { Triple(it, servers.session(it), servers.password(it)) }
                } ?: return@launch
            val (last, session, password) = found
            lastServer.value = last
            // A session left without leaving: take it up again.
            if (session != null) start(last, password, session, remember = password != null)
        }
    }

    fun connect(
        url: String,
        login: String?,
        password: String?,
        remember: Boolean,
    ) {
        val wanted = Server(url, login)
        viewModelScope.launch {
            // The server last used: its kept password if none is typed, and
            // its session if one was kept, rather than a second beside it.
            val (pw, saved) =
                if (wanted == lastServer.value) {
                    withContext(Dispatchers.IO) { (password ?: servers.password(wanted)) to servers.session(wanted) }
                } else {
                    password to null
                }
            start(wanted, pw, saved, remember)
        }
    }

    private fun start(
        to: Server,
        password: String?,
        saved: ByteArray?,
        remember: Boolean,
    ) {
        if (state.value.link.let { it == Link.Connecting || it == Link.Live || it is Link.Reconnecting }) return
        state.value = ChatState(link = Link.Connecting)
        connection?.let {
            connection = null
            it.close()
        }
        val mine = Sink()
        sink = mine
        val conn = ServerConnection(to.url, mine)
        conn.setForeground(foreground)
        connection = conn
        server = to
        established = false
        viewModelScope.launch {
            try {
                conn.login(loginFor(to, password, saved), password, saved)
                established = true
                lastServer.value = to
                withContext(Dispatchers.IO) { servers.remember(to, password.takeIf { remember }) }
                save()
            } catch (e: CoreException) {
                val code = (e as? CoreException.Refused)?.code
                withContext(Dispatchers.IO) {
                    // Refused for good: the saved session is not coming back.
                    // Busy or unreachable, it may yet.
                    if (saved != null && code != null && !keepsSession(code)) servers.keepSession(to, null)
                    if (code == "login_failed") servers.forgetPassword(to)
                }
                state.update { it.copy(link = Link.Ended(why(e))) }
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
        val saved = conn.saved()
        viewModelScope.launch(Dispatchers.IO) { servers.keepSession(to, saved) }
    }

    fun disconnect() {
        val (conn, to) = (connection ?: return) to (server ?: return)
        state.update { it.copy(leaving = true) }
        viewModelScope.launch {
            // Forgotten first, so a process gone before the logout lands does
            // not wake up in the chat the person left.
            withContext(Dispatchers.IO) { servers.keepSession(to, null) }
            conn.disconnect()
        }
    }

    // The scope is already cancelled here, so nothing suspends: save what
    // resumes the session, hang up leaving it to be resumed, and let the
    // core finish on its own threads.
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
        if (established || leaving) thread(name = "hexline-save") { servers.keepSession(to, saved) }
    }

    private fun why(e: CoreException): Why =
        when (e) {
            is CoreException.Connect -> Why.Unreachable
            is CoreException.Refused -> refusal(e.code)
            is CoreException.Protocol -> Why.NotUnderstood
            is CoreException.Closed, is CoreException.Busy -> Why.Lost
        }

    private companion object {
        const val PAGE = 50u
        const val FILL_PAGE = 200u
        const val FILL_PAGES = 5
        const val FILL_WAIT = 2_000L
    }
}
