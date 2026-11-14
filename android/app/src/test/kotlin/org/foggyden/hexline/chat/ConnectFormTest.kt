package org.foggyden.hexline.chat

import org.foggyden.hexline.core.CertInfo
import org.foggyden.hexline.identity.StoredIdentity
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ConnectFormTest {
    private fun kept(fingerprint: String) =
        StoredIdentity(
            null,
            byteArrayOf(),
            byteArrayOf(),
            CertInfo(fingerprint, byteArrayOf(), byteArrayOf(), 0u, 0u, 0u, true, true, false, true, null),
        )

    private val a = "wss://a.example/ng"
    private val b = "wss://b.example/ng"

    @Test
    fun whatWasTypedForOneServerIsNeverSentToAnother() {
        val typed = ConnectForm().withUrl(a).copy(login = "alice", password = "pw-a", rememberPassword = true)
        assertEquals(
            "a saved server picked",
            ConnectRequest(Server(b, "bob"), null, false, null),
            typed.filled(Server(b, "bob")).request(emptyList()),
        )
        assertEquals(
            "the address edited",
            ConnectRequest(Server(b, "alice"), null, false, null),
            typed.withUrl(b).request(emptyList()),
        )

        val linking =
            ConnectForm(byIdentity = true, chosen = "fp-x")
                .withUrl(a)
                .copy(linking = true, linkLogin = "alice", linkPassword = "pw-a")
        assertEquals("pw-a", linking.request(listOf(kept("fp-x")))?.link?.password)
        assertNull(
            "nor an account to link",
            linking.filled(Server(b, null, SignIn.Identity("fp-x"))).request(listOf(kept("fp-x")))?.link,
        )
    }

    @Test
    fun anIdentityNoLongerOnThePhoneIsMissingAndNotStoodInForByAnother() {
        val form = ConnectForm().filled(Server(a, null, SignIn.Identity("fp-gone")))
        val identities = listOf(kept("fp-x"))
        assertTrue(form.missing(identities))
        assertNull(form.request(identities))
        val picked = form.copy(chosen = "fp-x")
        assertFalse(picked.missing(identities))
        assertEquals(SignIn.Identity("fp-x"), picked.request(identities)?.server?.signIn)
    }
}
