package org.foggyden.hexline.secrets

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class SecretStoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    // Each test its own key and directory, so nothing one leaves, even a
    // run that died before cleaning up, reaches another.
    private val alias = "hexline-test-${UUID.randomUUID()}"
    private val dir = File(context.cacheDir, alias)

    private fun store() = SecretStore(context, alias, dir)

    private fun forgetKey() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)

    @After
    fun cleanUp() {
        dir.deleteRecursively()
        forgetKey()
    }

    @Test
    fun aSecretPutIsTheSecretGotByAnotherStoreOnTheSameKey() {
        store().put("token-s1", "hunter2".toByteArray())
        assertArrayEquals("hunter2".toByteArray(), store().get("token-s1"))
        val onDisk = File(dir, "token-s1").readBytes()
        assertTrue(!String(onDisk, Charsets.ISO_8859_1).contains("hunter2"))
    }

    @Test
    fun aSecretPutAgainIsTheLatest() {
        store().put("token-s1", "old".toByteArray())
        store().put("token-s1", "new".toByteArray())
        assertArrayEquals("new".toByteArray(), store().get("token-s1"))
    }

    @Test
    fun aSecretNeverPutOrDeletedIsNull() {
        val store = store()
        assertNull(store.get("token-s1"))
        store.put("token-s1", byteArrayOf(1))
        store.delete("token-s1")
        assertNull(store.get("token-s1"))
    }

    @Test
    fun anAlteredOrRenamedSecretDoesNotOpen() {
        val store = store()
        store.put("token-s1", "hunter2".toByteArray())
        val file = File(dir, "token-s1")
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes.last().toInt() xor 1).toByte()
        file.writeBytes(bytes)
        assertThrows(SecretUnreadable::class.java) { store.get("token-s1") }

        store.put("token-s2", "other".toByteArray())
        File(dir, "token-s2").copyTo(File(dir, "token-s3"))
        assertThrows(SecretUnreadable::class.java) { store.get("token-s3") }
    }

    @Test
    fun aSecretSealedByAKeyThePhoneNoLongerHasDoesNotOpenAndANewOneIsMade() {
        store().put("token-s1", "hunter2".toByteArray())
        forgetKey()
        assertThrows(SecretUnreadable::class.java) { store().get("token-s1") }
        store().put("token-s2", "fresh".toByteArray())
        assertArrayEquals("fresh".toByteArray(), store().get("token-s2"))
    }

    @Test
    fun namesThatAreNotPlainFilesAreRefused() {
        for (name in listOf(".", "..", "x.bak", "x.new", "../escape", "Upper", "", "a".repeat(65))) {
            assertThrows(name, IllegalArgumentException::class.java) { store().get(name) }
            assertThrows(name, IllegalArgumentException::class.java) { store().put(name, byteArrayOf(1)) }
            assertThrows(name, IllegalArgumentException::class.java) { store().delete(name) }
        }
    }

    @Test
    fun storesStartingAtOnceShareOneKeyAndOneNameHasOneWriterAtATime() {
        val pool = Executors.newFixedThreadPool(8)
        val names = (0 until 16).map { "token-$it" }
        val writes =
            names.map { name -> pool.submit { store().put(name, name.toByteArray()) } } +
                (0 until 16).map { i -> pool.submit { store().put("shared", "writer-$i".toByteArray()) } }
        pool.shutdown()
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS))
        writes.forEach { it.get() }
        assertEquals(names, names.map { String(store().get(it)!!) })
        assertTrue(String(store().get("shared")!!).startsWith("writer-"))
    }
}
