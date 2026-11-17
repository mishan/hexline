package org.foggyden.hexline.secrets

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * The Keystore's Keys B on a real Android: the screen lock is set and
 * removed through the shell, and the system's prompt answered by typing
 * the PIN into it, as a person would.
 */
@RunWith(AndroidJUnit4::class)
class HolderKeysTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val alias = "hexline-held-test"

    @Before
    fun lock() {
        assumeTrue("holder mode needs API 30", Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        shell("locksettings clear --old $PIN")
        shell("locksettings set-pin $PIN")
    }

    @After
    fun unlock() {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
        shell("locksettings clear --old $PIN")
    }

    @Test
    fun aKeyBAsksThePersonForEachUse() {
        val keys = KeystoreHolderKeys(context)
        keys.create(alias)
        val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(alias, null) as SecretKey
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        assertTrue(info.isUserAuthenticationRequired)
        assertEquals(KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL, info.userAuthenticationType)
        // Read back as asked; a phone with no fingerprint reader shows no difference either way.
        assertFalse(info.isInvalidatedByBiometricEnrollment)
        // The emulator's KeyMint is software; a phone's is its TEE or StrongBox,
        // which Android 11 tells apart from software alone.
        val expected =
            when {
                Build.HARDWARE in setOf("ranchu", "goldfish") -> setOf("software")
                Build.VERSION.SDK_INT < Build.VERSION_CODES.S -> setOf("secure hardware")
                else -> setOf("tee", "strongbox")
            }
        val level = keys.security(alias)
        assertTrue("in $level", level in expected)
        val seal = keys.begin(alias, null)
        assertThrows("used without the person", Exception::class.java) { seal.run(ByteArray(32)) }
    }

    @Test
    fun withoutAScreenLockNoKeyBIsMade() {
        shell("locksettings clear --old $PIN")
        assertThrows(NoScreenLock::class.java) { KeystoreHolderKeys(context).create(alias) }
    }

    private fun shell(command: String) {
        instrumentation.uiAutomation.executeShellCommand(command).use { pfd ->
            android.os.ParcelFileDescriptor
                .AutoCloseInputStream(pfd)
                .readBytes()
        }
    }

    private companion object {
        const val PIN = "1234"
    }
}
