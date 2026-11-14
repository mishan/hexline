package org.foggyden.hexline

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.foggyden.hexline.chat.ChatScreen
import org.foggyden.hexline.chat.ChatViewModel
import org.foggyden.hexline.chat.ConnectScreen
import org.foggyden.hexline.chat.Link
import org.foggyden.hexline.chat.RestoreScreen
import org.foggyden.hexline.identity.Restoring

class MainActivity : ComponentActivity() {
    private val chat: ChatViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { Surface { Hexline(chat) } } }
    }
}

@Composable
fun Hexline(chat: ChatViewModel) {
    val state by chat.chat.collectAsStateWithLifecycle()
    val saved by chat.saved.collectAsStateWithLifecycle()
    val identities by chat.identityList.collectAsStateWithLifecycle()
    val restore by chat.restore.collectAsStateWithLifecycle()
    var restoring by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(restore) { if (restore is Restoring.Done) restoring = false }
    when (val link = state.link) {
        Link.Live, is Link.Reconnecting -> ChatScreen(state, chat::send, chat::loadEarlier, chat::disconnect)
        else ->
            if (restoring) {
                RestoreScreen(restore, chat::restore) {
                    restoring = false
                    chat.restoreSeen()
                }
            } else {
                ConnectScreen(
                    saved = saved,
                    identities = identities,
                    restored = (restore as? Restoring.Done)?.fingerprint,
                    error = (link as? Link.Ended)?.why,
                    connecting = link == Link.Connecting,
                    onConnect = chat::connect,
                    onForget = chat::forget,
                    onRestore = {
                        chat.restoreSeen()
                        restoring = true
                    },
                    onRestored = chat::restoreSeen,
                )
            }
    }
}
