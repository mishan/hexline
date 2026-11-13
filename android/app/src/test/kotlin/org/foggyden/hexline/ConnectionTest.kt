package org.foggyden.hexline

import kotlinx.coroutines.runBlocking
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.ServerConnection
import org.foggyden.hexline.core.UpdateSink
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ServerSocket

class ConnectionTest {
    private object Nowhere : UpdateSink {
        override fun deliver(updates: List<CoreUpdate>) = Unit
    }

    @Test
    fun aServerThatIsNotThereIsAConnectError() {
        val port = ServerSocket(0).use { it.localPort }
        val connection = ServerConnection("ws://127.0.0.1:$port/ng", Nowhere)
        val error = runCatching { runBlocking { connection.login("alice", "pw") } }.exceptionOrNull()
        assertTrue("$error", error is CoreException.Connect)
    }
}
