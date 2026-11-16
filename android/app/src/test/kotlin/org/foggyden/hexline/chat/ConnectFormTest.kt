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
    private fun kept(
        fingerprint: String,
        expires: Long = NOW + 90 * DAY,
        manage: Boolean = true,
    ) = StoredIdentity(
        null,
        byteArrayOf(),
        byteArrayOf(),
        CertInfo(fingerprint, byteArrayOf(), byteArrayOf(), 0u, expires.toULong(), true, true, false, manage, null),
    )

    @Test
    fun anAccountToLinkGoesWithTheIdentityItWasTypedForAndOnlyWithOneThatMayManage() {
        val linking =
            ConnectForm(byIdentity = true, chosen = "fp-x")
                .withUrl(a)
                .copy(linking = true, linkLogin = "alice", linkPassword = "pw-a")
        val identities = listOf(kept("fp-x"), kept("fp-y"), kept("fp-web", manage = false))
        assertEquals("pw-a", linking.request(identities, NOW, none)?.link?.password)
        assertEquals(
            "picked again, kept",
            "pw-a",
            linking
                .chose("fp-x")
                .request(identities, NOW, none)
                ?.link
                ?.password,
        )
        val other = linking.chose("fp-y")
        assertFalse("another picked", other.linking)
        assertNull(other.request(identities, NOW, none)?.link)
        assertFalse("another just restored or enrolled", linking.restored("fp-y").linking)
        assertEquals(
            "pw-a",
            linking
                .restored("fp-x")
                .request(identities, NOW, none)
                ?.link
                ?.password,
        )
        val web = linking.copy(chosen = "fp-web").request(identities, NOW, none)
        assertNull("a device that may not manage asks no link", web?.link)
        assertEquals("but still signs in", "fp-web", (web?.server?.signIn as? SignIn.Identity)?.fingerprint)
    }

    private val none: (Server, StoredIdentity) -> String? = { _, _ -> null }

    private val a = "wss://a.example/ng"
    private val b = "wss://b.example/ng"

    @Test
    fun whatWasTypedForOneServerIsNeverSentToAnother() {
        val typed = ConnectForm().withUrl(a).copy(login = "alice", password = "pw-a", rememberPassword = true)
        assertEquals(
            "a saved server picked",
            ConnectRequest(Server(b, "bob"), null, false, null),
            typed.filled(Server(b, "bob")).request(emptyList(), NOW, none),
        )
        assertEquals(
            "the address edited",
            ConnectRequest(Server(b, "alice"), null, false, null),
            typed.withUrl(b).request(emptyList(), NOW, none),
        )

        val linking =
            ConnectForm(byIdentity = true, chosen = "fp-x")
                .withUrl(a)
                .copy(linking = true, linkLogin = "alice", linkPassword = "pw-a")
        assertEquals("pw-a", linking.request(listOf(kept("fp-x")), NOW, none)?.link?.password)
        assertNull(
            "nor an account to link",
            linking.filled(Server(b, null, SignIn.Identity("fp-x"))).request(listOf(kept("fp-x")), NOW, none)?.link,
        )
    }

    @Test
    fun anIdentityNoLongerOnThePhoneIsMissingAndNotStoodInForByAnother() {
        val form = ConnectForm().filled(Server(a, null, SignIn.Identity("fp-gone")))
        val identities = listOf(kept("fp-x"))
        assertTrue(form.missing(identities))
        assertNull(form.request(identities, NOW, none))
        val picked = form.copy(chosen = "fp-x")
        assertFalse(picked.missing(identities))
        assertEquals(SignIn.Identity("fp-x"), picked.request(identities, NOW, none)?.server?.signIn)
    }

    @Test
    fun anIdentityExpiredOrRefusedByThisServerIsNotSignedInWithThere() {
        val form = ConnectForm(byIdentity = true, chosen = "fp-x").withUrl(a)
        assertNull("expired", form.request(listOf(kept("fp-x", expires = NOW - DAY)), NOW, none))
        assertEquals(
            "soon to expire, still good",
            SignIn.Identity("fp-x"),
            form.request(listOf(kept("fp-x", expires = NOW + DAY)), NOW, none)?.server?.signIn,
        )
        val refusedByA: (Server, StoredIdentity) -> String? = { s, _ -> "revoked".takeIf { s.url == a } }
        assertNull("refused here", form.request(listOf(kept("fp-x")), NOW, refusedByA))
        assertEquals(
            "and still good elsewhere",
            SignIn.Identity("fp-x"),
            form
                .withUrl(b)
                .copy(chosen = "fp-x", byIdentity = true)
                .request(listOf(kept("fp-x")), NOW, refusedByA)
                ?.server
                ?.signIn,
        )
    }

    private companion object {
        const val NOW = 1_800_000_000L
        const val DAY = 86_400L
    }
}
