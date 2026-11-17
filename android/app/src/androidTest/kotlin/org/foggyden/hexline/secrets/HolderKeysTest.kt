package org.foggyden.hexline.secrets

import android.os.Build
import android.os.SystemClock
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.lifecycle.lifecycleScope
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.foggyden.hexline.debug.HolderDebugActivity
import org.foggyden.hexline.identity.HeldSeeds
import org.foggyden.hexline.identity.Identities
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import kotlin.coroutines.EmptyCoroutineContext

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
    private var minted: String? = null

    @Before
    fun lock() {
        assumeTrue("holder mode needs API 30", Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        shell("locksettings clear --old $PIN")
        shell("locksettings set-pin $PIN")
    }

    @After
    fun unlock() {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
        File(context.filesDir, "held").deleteRecursively()
        minted?.let { Identities(context).delete(it) }
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
        // The emulator's KeyMint is software; a phone's is its TEE or StrongBox.
        val emulator = Build.HARDWARE in setOf("ranchu", "goldfish")
        val level = keys.security(alias)
        assertTrue("in $level", if (emulator) level == "software" else level in setOf("tee", "strongbox"))
        val seal = keys.begin(alias, null)
        assertThrows("used without the person", Exception::class.java) { seal.run(ByteArray(32)) }
    }

    @Test
    fun withoutAScreenLockNoKeyBIsMade() {
        shell("locksettings clear --old $PIN")
        assertThrows(NoScreenLock::class.java) { KeystoreHolderKeys(context).create(alias) }
    }

    @Test
    fun aSeedHeldBehindThePromptMintsThisPhonesDeviceAndGoesWithTheScreenLock() {
        ActivityScenario.launch(HolderDebugActivity::class.java).use { scenario ->
            assertTrue("held", answered(scenario) { it.hold() })
            minted = answered(scenario) { it.mint() }
            var activity: HolderDebugActivity? = null
            scenario.onActivity { activity = it }
            val shown = checkNotNull(activity)
            assertEquals("this phone's device, minted by its identity", shown.fingerprint, minted)
            val fp = checkNotNull(shown.fingerprint)
            assertTrue(shown.held.isHeld(fp))
            shell("locksettings clear --old $PIN")
            val held = HeldSeeds(File(context.filesDir, "held"), KeystoreHolderKeys(context), EmptyCoroutineContext)
            assertEquals(listOf(fp), held.demoteLost(listOf(fp)))
            assertFalse(held.isHeld(fp))
            assertEquals(listOf(fp), held.notices())
        }
    }

    /** [act] run in the activity, the system's prompt answered with the PIN while it waits. */
    private fun <T> answered(
        scenario: ActivityScenario<HolderDebugActivity>,
        act: suspend (HolderDebugActivity) -> T,
    ): T {
        var job: kotlinx.coroutines.Deferred<T>? = null
        scenario.onActivity { a -> job = a.lifecycleScope.async { act(a) } }
        val deferred = checkNotNull(job)
        val deadline = SystemClock.uptimeMillis() + 30_000
        while (!deferred.isCompleted && SystemClock.uptimeMillis() < deadline) {
            SystemClock.sleep(1_500)
            if (deferred.isCompleted) break
            shell("input text $PIN")
            shell("input keyevent KEYCODE_ENTER")
        }
        assertTrue("the prompt was answered", deferred.isCompleted)
        return runBlocking { deferred.await() }
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
