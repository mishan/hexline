package org.foggyden.hexline

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.foggyden.hexline.chat.ChatScreen
import org.foggyden.hexline.chat.ChatViewModel
import org.foggyden.hexline.chat.ConnectScreen
import org.foggyden.hexline.chat.Link

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
    when (val link = state.link) {
        Link.Live, is Link.Reconnecting -> ChatScreen(state, chat::send, chat::loadEarlier, chat::disconnect)
        else ->
            ConnectScreen(
                error = (link as? Link.Ended)?.why,
                connecting = link == Link.Connecting,
                onConnect = chat::connect,
            )
    }
}
