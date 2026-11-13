package org.foggyden.hexline.chat

import org.foggyden.hexline.servers.Server
import org.junit.Assert.assertEquals
import org.junit.Test

class SessionPolicyTest {
    @Test
    fun aSavedSessionIsKeptOnlyThroughRefusalsThatPass() {
        val cases =
            mapOf(
                "rate_limited" to true,
                "too_many_connections" to true,
                "server_full" to true,
                "server_error" to true,
                "session_expired" to false,
                "bad_request" to false,
                "kicked" to false,
                "replaced" to false,
                "banned" to false,
                "login_failed" to false,
            )
        for ((code, kept) in cases) assertEquals(code, kept, keepsSession(code))
    }

    @Test
    fun aSavedSessionWithNoPasswordIsResumedAsNobodyRatherThanLoggedInWithout() {
        val alice = Server("wss://a.example/ng", "alice")
        val guest = Server("wss://a.example/ng", null)
        val saved = byteArrayOf(1)
        assertEquals(null, loginFor(alice, null, saved))
        assertEquals("alice", loginFor(alice, "pw", saved))
        assertEquals("alice", loginFor(alice, null, null))
        assertEquals(null, loginFor(guest, null, saved))
    }
}
