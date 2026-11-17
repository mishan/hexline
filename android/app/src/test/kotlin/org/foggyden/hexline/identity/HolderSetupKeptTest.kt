package org.foggyden.hexline.identity

import android.app.Application
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.NewIdentity
import org.foggyden.hexline.core.holderMint
import org.foggyden.hexline.core.newIdentity
import org.foggyden.hexline.secrets.Secrets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.nio.file.Files

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class HolderSetupKeptTest {
    private val app = RuntimeEnvironment.getApplication()
    private val dir: File = Files.createTempDirectory(app.filesDir.toPath(), "identities").toFile()
    private val secrets =
        object : Secrets {
            private val kept = HashMap<String, ByteArray>()

            override fun put(
                name: String,
                secret: ByteArray,
            ) {
                kept[name] = secret.copyOf()
            }

            override fun get(name: String) = kept[name]?.copyOf()

            override fun delete(name: String) {
                kept -= name
            }
        }

    private fun identities() = Identities(app, secrets, dir)

    /** A holder's device kept as a setup leaves it before its commit. */
    private fun keptUnfinished(): Pair<NewIdentity, StoredIdentity> {
        val made = newIdentity("Carol")
        val minted = holderMint(made.seed, made.card, "Pixel")
        return made to identities().save(minted.deviceSeed, minted.cert, made.card, "carol", "reg.example", unfinished = true)
    }

    @Test
    fun aSetupNotYetCommittedIsKeptAsUnfinishedUntilItIs() {
        val (setup, kept) = keptUnfinished()
        assertTrue(kept.unfinished)
        val unfinished = identities().list().single()
        assertTrue("read back so", unfinished.unfinished)
        assertEquals("the handle to resume it as", "carol", unfinished.handle)
        assertEquals("reg.example", unfinished.registrar)
        val done = checkNotNull(identities().committed(setup.fingerprint, setup.card))
        assertFalse(done.unfinished)
        val read = identities().list().single()
        assertFalse(read.unfinished)
        assertEquals("carol", read.handle)
        assertEquals("reg.example", read.registrar)
        assertArrayEquals(setup.card, read.card)
    }

    @Test
    fun anotherIdentitysCardIsNoCommitOfThisOne() {
        val (setup, _) = keptUnfinished()
        try {
            identities().committed(setup.fingerprint, newIdentity("Dave").card)
            fail("committed with another's card")
        } catch (_: CoreException) {
        }
        assertTrue(identities().list().single().unfinished)
    }
}
