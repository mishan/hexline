package org.foggyden.hexline.chat

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.ServerConnection
import org.foggyden.hexline.core.UpdateSink

/** One server's connection and what its screen shows. */
class ChatViewModel : ViewModel() {
    private val state = MutableStateFlow(ChatState())
    val chat: StateFlow<ChatState> = state

    private var connection: ServerConnection? = null

    // Called on a core thread. `update` is atomic, so the batch is applied
    // whole and in order, and the call returns at once, as the core asks.
    private val sink =
        object : UpdateSink {
            override fun deliver(updates: List<CoreUpdate>) {
                state.update { s -> updates.fold(s) { acc, u -> acc.apply(u) } }
            }
        }

    fun connect(
        url: String,
        login: String?,
        password: String?,
    ) {
        if (state.value.link == Link.Connecting || state.value.link == Link.Live) return
        state.value = ChatState(link = Link.Connecting)
        connection?.close()
        val conn = ServerConnection(url, sink)
        connection = conn
        viewModelScope.launch {
            try {
                conn.login(login, password)
                loadEarlier()
            } catch (e: CoreException) {
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

    fun disconnect() {
        val conn = connection ?: return
        state.update { it.copy(leaving = true) }
        viewModelScope.launch { conn.disconnect() }
    }

    // The scope is already cancelled here, so nothing suspends: hang up and
    // let the core finish on its own threads.
    override fun onCleared() {
        connection?.hangUp()
        connection?.close()
        connection = null
    }

    private fun why(e: CoreException): Why =
        when (e) {
            is CoreException.Connect -> Why.Unreachable
            is CoreException.Refused ->
                when (e.code) {
                    "login_failed" -> Why.WrongPassword
                    "banned" -> Why.Banned
                    "server_full" -> Why.Full
                    else -> Why.Refused(e.code)
                }
            is CoreException.Protocol -> Why.NotUnderstood
            is CoreException.Closed, is CoreException.Busy -> Why.Lost
        }

    private companion object {
        const val PAGE = 50u
    }
}
