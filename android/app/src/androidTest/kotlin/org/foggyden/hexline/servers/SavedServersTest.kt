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

    @Test
    fun aRefusalIsKeptForItsServerAndDeviceAloneUntilTheServerIsForgotten() {
        val a = Server("wss://a.example/ng", null, SignIn.Identity("fp-x"))
        val b = Server("wss://b.example/ng", null, SignIn.Identity("fp-x"))
        val (device, renewed) = ByteArray(32) { 1 } to ByteArray(32) { 2 }
        servers().remember(a, null)
        servers().markRefused(a, device, "revoked")
        assertEquals("revoked", servers().refused(a, device))
        assertNull("another server", servers().refused(b, device))
        assertNull("a new device", servers().refused(a, renewed))
        servers().forget(a)
        assertNull("forgotten with its server", servers().refused(a, device))
    }

    @Test
    fun aRotatedRefusalKeepsTheKeyItNamedBesideItsCode() {
        val a = Server("wss://a.example/ng", null, SignIn.Identity("fp-x"))
        val (device, other) = ByteArray(32) { 1 } to ByteArray(32) { 2 }
        servers().remember(a, null)
        servers().markRefused(a, device, "rotated", successor = "fp-y")
        servers().markRefused(a, other, "revoked")
        assertEquals(listOf("rotated", "revoked"), listOf(servers().refused(a, device), servers().refused(a, other)))
        assertEquals(listOf("fp-y", null), listOf(servers().successor(a, device), servers().successor(a, other)))
        assertEquals(setOf("rotated", "revoked"), servers().refusals().values.toSet())
    }

    @Test
    fun aServerAlreadySignedInToAsTheSuccessorIsListedOnce() {
        val old = Server("wss://a.example/ng", null, SignIn.Identity("fp-x"))
        val new = old.copy(signIn = SignIn.Identity("fp-y"))
        servers().remember(old, null)
        servers().remember(new, null)
        servers().repoint("fp-x", "fp-y")
        assertEquals(listOf(new), servers().all())
    }

    @Test
    fun aRotatedIdentitysServersSignInAsItsSuccessorInTheirPlaceAndForgetWhatTheyKept() {
        val a = Server("wss://a.example/ng", null, SignIn.Identity("fp-x"))
        val b = Server("wss://b.example/ng", "bob")
        val c = Server("wss://c.example/ng", null, SignIn.Identity("fp-x"))
        val d = Server("wss://d.example/ng", null, SignIn.Identity("fp-z"))
        val device = ByteArray(32) { 1 }
        for (s in listOf(d, c, b, a)) {
            servers().remember(s, null)
            servers().keepSession(s, byteArrayOf(1))
            servers().markRefused(s, device, "rotated", successor = "fp-y")
        }
        servers().askedToLink(a, true)
        val since = servers().generation()
        servers().repoint("fp-x", "fp-y")
        val moved = { s: Server -> s.copy(signIn = SignIn.Identity("fp-y")) }
        assertEquals(listOf(moved(a), b, moved(c), d), servers().all())
        assertEquals("their sessions", listOf(null, null), listOf(servers().session(a), servers().session(c)))
        assertEquals("their refusals", listOf(null, null), listOf(servers().refused(a, device), servers().refused(c, device)))
        assertFalse("their link asked", servers().linkAsked(a))
        assertEquals("the rest", listOf("rotated", "rotated"), listOf(servers().refused(b, device), servers().refused(d, device)))
        assertArrayEquals(byteArrayOf(1), servers().session(d))
        assertFalse("a login begun before is not kept", servers().keepSession(a, byteArrayOf(2), since))
        assertFalse("nor its server brought back", servers().remember(a, null, since))
    }

    @Test
    fun aDevicesRefusalsGoWithItAndAnotherDevicesStay() {
        val a = Server("wss://a.example/ng", null, SignIn.Identity("fp-x"))
        val b = Server("wss://b.example/ng", null, SignIn.Identity("fp-x"))
        val (device, other) = ByteArray(32) { 1 } to ByteArray(32) { 2 }
        for (s in listOf(a, b)) {
            servers().remember(s, null)
            servers().markRefused(s, device, "revoked")
            servers().markRefused(s, other, "rotated")
        }
        servers().forgetRefusalsOf(device)
        assertEquals(listOf(null, null), listOf(servers().refused(a, device), servers().refused(b, device)))
        assertEquals(listOf("rotated", "rotated"), listOf(servers().refused(a, other), servers().refused(b, other)))
        servers().forgetRefusal(a, other)
        assertEquals("tried again there alone", listOf(null, "rotated"), listOf(servers().refused(a, other), servers().refused(b, other)))
    }

    @Test
    fun whatALoginBegunBeforeAForgetOrADeleteKeepsIsNotKept() {
        val a = Server("wss://a.example/ng", null, SignIn.Identity("fp-x"))
        val device = ByteArray(32) { 1 }
        servers().remember(a, null)
        val since = servers().generation()
        servers().forgetRefusalsOf(device)
        servers().markRefused(a, device, "revoked", since)
        assertNull("a refusal of a device deleted since", servers().refused(a, device))

        servers().forget(a)
        servers().askedToLink(a, true, since)
        assertFalse("a link flag for a server forgotten since", servers().linkAsked(a))
    }

    @Test
    fun aClearAskedForBeforeANewerLoginKeptItsOwnLeavesThatOneBe() {
        val a = Server("wss://a.example/ng", "alice")
        servers().remember(a, "pw-old")
        val since = servers().generation()
        // A newer login keeps its own, then the older one's clear lands.
        servers().remember(a, "pw-new")
        servers().keepSession(a, byteArrayOf(4))
        servers().forgetPassword(a, since)
        servers().forgetSession(a, since)
        assertEquals("pw-new", servers().password(a))
        assertArrayEquals(byteArrayOf(4), servers().session(a))
        // Its own clear, asked for after them, still clears.
        servers().forgetPassword(a, servers().generation())
        servers().forgetSession(a, servers().generation())
        assertNull(servers().password(a))
        assertNull(servers().session(a))
    }

    @Test
    fun actsAreOrderedByWhenTheyWereAskedForNotWhenTheyRan() {
        val a = Server("wss://a.example/ng", "alice")
        servers().remember(a, null)
        // A forget, then a login asked for after it: the forget runs first.
        val forget = servers().generation()
        val login = servers().generation()
        servers().forget(a, forget)
        assertTrue("a login asked for after a forget", servers().remember(a, "pw", login))
        // A clear, then a save asked for after it: the clear runs first.
        val clear = servers().generation()
        val save = servers().generation()
        servers().forgetSession(a, clear)
        servers().keepSession(a, byteArrayOf(4), save)
        assertArrayEquals("a save asked for after a clear", byteArrayOf(4), servers().session(a))
    }

    @Test
    fun anOlderSaveNeverOverwritesANewerOneNorOutlivesAForget() {
        val a = Server("wss://a.example/ng", "alice")
        servers().remember(a, null)
        val older = servers().generation()
        servers().keepSession(a, byteArrayOf(2), servers().generation())
        servers().keepSession(a, byteArrayOf(1), older)
        assertArrayEquals("the newer save stands", byteArrayOf(2), servers().session(a))

        // A forget, then the server remembered again by a newer login: a
        // save asked for before the forget is still the forgotten one's.
        val beforeForget = servers().generation()
        servers().forget(a, servers().generation())
        servers().remember(a, null, servers().generation())
        servers().keepSession(a, byteArrayOf(3), beforeForget)
        assertNull(servers().session(a))
    }

    @Test
    fun aSessionSavedAfterItWasClearedIsNotWrittenBack() {
        val a = Server("wss://a.example/ng", null, SignIn.Identity("fp-x"))
        servers().remember(a, null)
        val since = servers().generation()
        servers().forgetSession(a)
        servers().keepSession(a, byteArrayOf(1, 2, 3), since)
        assertNull("a save from before the clear", servers().session(a))
        servers().keepSession(a, byteArrayOf(4), servers().generation())
        assertArrayEquals("one from after it", byteArrayOf(4), servers().session(a))
    }

    @Test
    fun aRefusalForAServerForgottenSinceItsLoginBeganIsNotKept() {
        val a = Server("wss://a.example/ng", null, SignIn.Identity("fp-x"))
        val device = ByteArray(32) { 1 }
        servers().remember(a, null)
        val since = servers().generation()
        servers().forget(a)
        servers().markRefused(a, device, "revoked", since)
        assertNull(servers().refused(a, device))
    }

    @Test
    fun aServerForgottenSinceALoginBeganIsNotRememberedByIt() {
        val a = Server("wss://a.example/ng", "alice")
        servers().remember(a, null)
        servers().forget(a)
        assertTrue("forgotten before it began", servers().remember(a, "hunter2", servers().generation()))
        assertEquals(listOf(a), servers().all())

        val began = servers().generation()
        servers().forget(a)
        assertFalse(servers().remember(a, "hunter2", began))
        assertEquals(emptyList<Server>(), servers().all())
        assertNull(servers().password(a))
    }
}
