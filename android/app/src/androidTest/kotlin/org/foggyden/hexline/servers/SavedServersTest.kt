package org.foggyden.hexline.servers

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.foggyden.hexline.secrets.SecretStore
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class SavedServersTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val alias = "hexline-test-${UUID.randomUUID()}"
    private val dir = File(context.cacheDir, alias)
    private val prefs = context.getSharedPreferences(alias, Context.MODE_PRIVATE)

    private fun servers() = SavedServers(context, SecretStore(context, alias, dir), prefs)

    @After
    fun cleanUp() {
        dir.deleteRecursively()
        context.deleteSharedPreferences(alias)
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
    }

    @Test
    fun theLastServerIsRememberedWithItsSecretsApartFromAnothers() {
        val a = Server("wss://a.example/ng", "alice")
        val guest = Server("wss://a.example/ng", null)
        assertNull(servers().last())
        servers().remember(a, "hunter2")
        servers().keepSession(a, byteArrayOf(1, 2, 3))
        assertEquals(a, servers().last())
        assertEquals("hunter2", servers().password(a))
        assertArrayEquals(byteArrayOf(1, 2, 3), servers().session(a))

        servers().remember(guest, null)
        servers().keepSession(guest, byteArrayOf(4))
        assertEquals("another login's secrets are its own", "hunter2", servers().password(a))
        assertArrayEquals(byteArrayOf(1, 2, 3), servers().session(a))
    }

    @Test
    fun eachServerIsKeptWithHowItSignsInTheLastFirstUntilForgottenWhole() {
        val a = Server("wss://a.example/ng", "alice")
        val b = Server("wss://b.example/ng", null, SignIn.Identity("fp-alice"))
        servers().remember(a, "hunter2")
        servers().keepSession(a, byteArrayOf(1))
        servers().remember(b, null)
        servers().keepSession(b, byteArrayOf(2))
        assertEquals(listOf(b, a), servers().all())
        assertEquals("hunter2", servers().password(a))
        assertArrayEquals(byteArrayOf(1), servers().session(a))

        servers().remember(a, "hunter2")
        assertEquals(listOf(a, b), servers().all())
        servers().forget(a)
        assertEquals(listOf(b), servers().all())
        assertNull(servers().password(a))
        assertNull(servers().session(a))
        assertArrayEquals(byteArrayOf(2), servers().session(b))
    }

    @Test
    fun anIdentitysSessionIsNotAGuestsAtTheSameServer() {
        val guest = Server("wss://a.example/ng", null)
        val identity = Server("wss://a.example/ng", null, SignIn.Identity("fp-alice"))
        servers().remember(guest, null)
        servers().remember(identity, null)
        servers().keepSession(guest, byteArrayOf(1))
        servers().keepSession(identity, byteArrayOf(2))
        assertArrayEquals(byteArrayOf(1), servers().session(guest))
        assertArrayEquals(byteArrayOf(2), servers().session(identity))
    }

    @Test
    fun aPasswordOrSessionLetGoIsGone() {
        val a = Server("wss://a.example/ng", "alice")
        servers().remember(a, "hunter2")
        servers().keepSession(a, byteArrayOf(1))
        servers().remember(a, null)
        servers().keepSession(a, null)
        assertNull(servers().password(a))
        assertNull(servers().session(a))
    }

    @Test
    fun aSecretThatWillNeverOpenIsForgotten() {
        val a = Server("wss://a.example/ng", "alice")
        servers().remember(a, null)
        servers().keepSession(a, byteArrayOf(1))
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
        assertNull(servers().session(a))
        assertEquals("nothing is left to fail again", 0, dir.listFiles()?.size ?: 0)
    }

    @Test
    fun aSessionIsKeptOnlyForAServerStillSaved() {
        val a = Server("wss://a.example/ng", "alice")
        servers().keepSession(a, byteArrayOf(1))
        assertNull("never saved", servers().session(a))
        servers().remember(a, null)
        servers().forget(a)
        servers().keepSession(a, byteArrayOf(2))
        assertNull("forgotten while connected", servers().session(a))
        assertEquals(0, dir.listFiles()?.size ?: 0)
    }

    @Test
    fun theOneServerKeptBeforeIsForgottenWithItsSecrets() {
        prefs
            .edit()
            .putString("url", "wss://a.example/ng")
            .putString("login", "alice")
            .commit()
        val digest = MessageDigest.getInstance("SHA-256").digest("wss://a.example/ng\nalice".toByteArray())
        val named = digest.take(12).joinToString("") { "%02x".format(it) }
        SecretStore(context, alias, dir).put("password-$named", "hunter2".toByteArray())
        assertEquals(emptyList<Server>(), servers().all())
        assertFalse(prefs.contains("url"))
        assertEquals(0, dir.listFiles()?.size ?: 0)
    }

    @Test
    fun aLinkAskedForIsKeptForItsServerAloneUntilClearedOrForgotten() {
        val a = Server("wss://a.example/ng", null, SignIn.Identity("fp-alice"))
        val b = Server("wss://b.example/ng", null, SignIn.Identity("fp-alice"))
        servers().remember(a, null)
        servers().askedToLink(a, true)
        assertTrue(servers().linkAsked(a))
        assertFalse(servers().linkAsked(b))
        servers().askedToLink(a, false)
        assertFalse(servers().linkAsked(a))
        servers().askedToLink(a, true)
        servers().forget(a)
        assertFalse(servers().linkAsked(a))
    }
}
