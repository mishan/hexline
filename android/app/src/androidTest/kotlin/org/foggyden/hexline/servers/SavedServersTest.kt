package org.foggyden.hexline.servers

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.foggyden.hexline.secrets.SecretStore
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
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

        servers().keepSession(guest, byteArrayOf(4))
        assertEquals("another login's secrets are its own", "hunter2", servers().password(a))
        assertArrayEquals(byteArrayOf(1, 2, 3), servers().session(a))
    }

    @Test
    fun anotherServerTakesTheLastPlaceAndTheOneBeforeIsForgottenWhole() {
        val a = Server("wss://a.example/ng", "alice")
        val b = Server("wss://b.example/ng", "alice")
        servers().remember(a, "hunter2")
        servers().keepSession(a, byteArrayOf(1))
        servers().remember(b, null)
        assertEquals(b, servers().last())
        assertNull(servers().password(a))
        assertNull(servers().session(a))
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
        servers().keepSession(a, byteArrayOf(1))
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
        assertNull(servers().session(a))
        assertEquals("nothing is left to fail again", 0, dir.listFiles()?.size ?: 0)
    }
}
