package org.foggyden.hexline.identity

import android.app.Application
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.foggyden.hexline.core.shortHash
import org.foggyden.hexline.secrets.FakeHolderKeys
import org.foggyden.hexline.secrets.HeldKeyLost
import org.foggyden.hexline.secrets.NoScreenLock
import org.foggyden.hexline.secrets.SoftwareKeysOnly
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.KeyStoreException
import java.security.ProviderException
import kotlin.coroutines.EmptyCoroutineContext

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class HeldSeedsTest {
    private val dir: File = Files.createTempDirectory(RuntimeEnvironment.getApplication().filesDir.toPath(), "held").toFile()
    private val keys = FakeHolderKeys()
    private val held = HeldSeeds(dir, keys, EmptyCoroutineContext)
    private val seed = ByteArray(32) { (it * 7 + 1).toByte() }

    private fun hold(
        fp: String = FP,
        what: ByteArray = seed,
        allow: Boolean = true,
    ) = runBlocking { held.hold(fp, what.copyOf(), keys.authorizer { allow }) }

    private fun open(fp: String = FP) = runBlocking { held.use(fp, keys.authorizer()) { it.copyOf() } }

    @Test
    fun aHeldSeedOpensOnlyForAUseThePersonAllowsAndIsWipedAfter() =
        runBlocking {
            assertTrue(hold())
            assertNull("refused", held.use(FP, keys.authorizer { false }) { it.copyOf() })
            var handed: ByteArray? = null
            val opened =
                held.use(FP, keys.authorizer()) {
                    handed = it
                    it.copyOf()
                }
            assertArrayEquals(seed, opened)
            assertTrue("wiped after its use", handed!!.all { it == 0.toByte() })
            for (file in dir.listFiles().orEmpty()) {
                val clear =
                    file
                        .readBytes()
                        .toList()
                        .windowed(seed.size)
                        .any { it == seed.toList() }
                assertFalse("${file.name} holds the seed as it is", clear)
            }
        }

    @Test
    fun aSeedOpenedAsItsUseIsCanceledIsWipedStill() {
        assertTrue(hold())
        // A dispatcher of its own, so the use is told of its cancellation as the open returns.
        val apart = HeldSeeds(dir, keys, Dispatchers.IO)
        var opened: ByteArray? = null
        runBlocking {
            lateinit var use: Job
            keys.onRun = {
                opened = it
                use.cancel()
            }
            use = launch { apart.use(FP, keys.authorizer()) { it.copyOf() } }
            use.join()
        }
        assertTrue("wiped though canceled", opened!!.all { it == 0.toByte() })
    }

    @Test
    fun aSeedThePersonWouldNotHoldIsNotHeld() {
        assertFalse(hold(allow = false))
        assertFalse(held.isHeld(FP))
        assertEquals("no key left behind", emptyList<String>(), keys.aliases)
    }

    @Test
    fun aHoldAgainThePersonRefusesLeavesTheSeedBeforeAsItWas() {
        assertTrue(hold())
        assertFalse(hold(what = ByteArray(32) { 9 }, allow = false))
        assertArrayEquals(seed, open())
        assertEquals("one key", 1, keys.aliases.size)
    }

    @Test
    fun aSeedHeldAgainReplacesTheOneBeforeAndItsKey() {
        assertTrue(hold())
        val again = ByteArray(32) { 9 }
        assertTrue(hold(what = again))
        assertArrayEquals(again, open())
        assertEquals("the key before let go of", 1, keys.aliases.size)
    }

    @Test
    fun aKeystoreInSoftwareAloneHoldsNothingOutsideADebugBuild() {
        keys.level = "software"
        try {
            hold()
            fail("held in software")
        } catch (_: SoftwareKeysOnly) {
        }
        assertFalse(held.isHeld(FP))
        assertEquals("the key made let go of", emptyList<String>(), keys.aliases)
        assertEquals("the person never asked", emptyList<FakeHolderKeys.FakeSeal>(), keys.begun)
        val debug = HeldSeeds(dir, keys, EmptyCoroutineContext, softwareKeys = true)
        assertTrue(runBlocking { debug.hold(FP, seed.copyOf(), keys.authorizer()) })
    }

    @Test
    fun withoutAScreenLockNothingIsHeld() {
        keys.removeLock()
        try {
            hold()
            fail("held without a screen lock")
        } catch (_: NoScreenLock) {
        }
        assertFalse(held.isHeld(FP))
    }

    @Test
    fun anIdentityWhoseKeyWentIsLetGoOfWithANoticeUntilRead() {
        for (gone in listOf("lock removed", "key lost")) {
            assertTrue(hold())
            assertTrue(hold(OTHER))
            assertEquals(gone, emptyList<String>(), held.demoteLost(listOf(FP, OTHER)))
            if (gone == "lock removed") {
                keys.removeLock()
            } else {
                keys.invalidate(keys.aliases.first())
            }
            val expected = if (gone == "lock removed") listOf(FP, OTHER) else listOf(FP)
            assertEquals(gone, expected, held.demoteLost(listOf(FP, OTHER)).sorted())
            assertFalse(gone, held.isHeld(FP))
            assertNull(gone, open())
            assertEquals(gone, expected, held.notices())
            for (fp in expected) held.dismiss(fp)
            assertEquals(gone, emptyList<String>(), held.notices())
            held.forget(OTHER)
            keys.setLock()
        }
    }

    @Test
    fun theKeystoresTroubleForNowLetsGoOfNothing() {
        assertTrue(hold())
        val troubled = keys.aliases.single()
        for (trouble in listOf(ProviderException("busy"), IOException("locked"), IllegalStateException("system"))) {
            assertTrue(hold(OTHER))
            keys.invalidate(keys.aliases.last())
            keys.trouble = { if (it == troubled) trouble else null }
            assertEquals("$trouble", listOf(OTHER), held.demoteLost(listOf(FP, OTHER)))
            keys.trouble = null
            assertTrue("$trouble", held.isHeld(FP))
            assertEquals("$trouble", listOf(OTHER), held.notices())
            held.dismiss(OTHER)
            assertArrayEquals("$trouble", seed, open())
        }
    }

    @Test
    fun aHeldFileThatDoesNotReadIsLeftAsItIsAndNoReasonToFallOver() {
        assertTrue(hold())
        val file = dir.listFiles()!!.single { it.name.startsWith("held-") }
        val alias = keys.aliases.single().toByteArray()
        val named = byteArrayOf(2, alias.size.toByte()) + alias
        val badIvs = listOf(0, 11, 17).map { named + byteArrayOf(it.toByte()) + ByteArray(it + 16) }
        val shapes = listOf(byteArrayOf(), byteArrayOf(2, 0), byteArrayOf(2, 3, 65, 65, 65, 0), byteArrayOf(2, 3, 65, 65, 65, -1))
        for (bad in shapes + badIvs) {
            file.writeBytes(bad)
            assertEquals(emptyList<String>(), held.demoteLost(listOf(FP)))
            assertTrue("left as it is", file.exists())
            try {
                open()
                fail("opened ${bad.size} bytes")
            } catch (_: HeldSeeds.BadHeldFile) {
            }
        }
    }

    @Test
    fun anAlteredFileOpensAsALostKeyNotAsAnotherSeed() {
        assertTrue(hold())
        val file = dir.listFiles()!!.single { it.name.startsWith("held-") }
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        try {
            open()
            fail("an altered seed opened")
        } catch (_: HeldKeyLost) {
        }
    }

    @Test
    fun aDemotionCutShortIsToldAndDoneAgain() {
        assertTrue(hold())
        keys.removeLock()
        keys.deleteFails = { IOException("cut short") }
        held.demoteLost(listOf(FP))
        assertEquals("told already", listOf(FP), held.notices())
        assertEquals(listOf(FP), held.demoteLost(listOf(FP)))
        assertFalse(held.isHeld(FP))
    }

    @Test
    fun whatNoIdentityNamesIsSweptAway() {
        assertTrue(hold())
        assertTrue(hold(OTHER))
        keys.create("hexline-held-stray")
        held.sweep(setOf(shortHash(FP.toByteArray())))
        assertTrue(held.isHeld(FP))
        assertFalse(held.isHeld(OTHER))
        assertEquals("the one key named", 1, keys.aliases.size)
        assertArrayEquals(seed, open())
    }

    @Test
    fun aKeptFileThatDoesNotReadNowKeepsItsKey() {
        assertTrue(hold())
        val file = dir.listFiles()!!.single { it.name.startsWith("held-") }
        val bytes = file.readBytes()
        file.writeBytes(byteArrayOf(2, 0))
        held.sweep(setOf(shortHash(FP.toByteArray())))
        file.writeBytes(bytes)
        assertArrayEquals(seed, open())
    }

    @Test
    fun aSweepTheKeystoreCannotAnswerNowLetsGoOfNothing() {
        assertTrue(hold())
        keys.trouble = { KeyStoreException("busy") }
        held.sweep(setOf(shortHash(FP.toByteArray())))
        keys.trouble = null
        assertArrayEquals(seed, open())
    }

    @Test
    fun aKeyTheKeystoreWillNotLetGoOfNowIsAStoreFailureToForgetAgain() {
        assertTrue(hold())
        keys.deleteFails = { KeyStoreException("busy") }
        try {
            held.forget(FP)
            fail("forgotten")
        } catch (_: IOException) {
        }
        assertTrue(held.isHeld(FP))
        held.forget(FP)
        assertFalse(held.isHeld(FP))
        assertEquals(emptyList<String>(), keys.aliases)
    }

    @Test
    fun aWriteTheFileSystemDidNotMakeLetsGoOfNothing() {
        // A directory where the file goes: AtomicFile logs the failed rename and returns.
        fun blocked(name: String) = File(dir, name + "-" + shortHash(FP.toByteArray())).apply { mkdirs() }.resolve("x").writeText("x")
        assertTrue(hold())
        blocked("lost")
        keys.removeLock()
        assertEquals("not demoted untold", emptyList<String>(), held.demoteLost(listOf(FP)))
        assertTrue(held.isHeld(FP))
        keys.setLock()
        File(dir, "held-" + shortHash(FP.toByteArray())).delete()
        blocked("held")
        assertTrue("a hold not written is not held", runCatching { hold() }.isFailure)
        assertEquals("its key let go of", emptyList<String>(), keys.aliases)
    }

    private companion object {
        const val FP = "6htgz65xb7yfs53dmhdanfmk7fgn995n1571rjnz8a36a1fks5z0"
        const val OTHER = "9htgz65xb7yfs53dmhdanfmk7fgn995n1571rjnz8a36a1fks5z0"
    }
}
