package org.foggyden.hexline.chat

import android.os.Build
import android.os.ParcelFileDescriptor
import android.view.WindowManager
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.fragment.app.testing.EmptyFragmentActivity
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import org.foggyden.hexline.R
import org.foggyden.hexline.core.HeldRestore
import org.foggyden.hexline.core.HolderCommitted
import org.foggyden.hexline.core.HolderSetup
import org.foggyden.hexline.core.HolderSetupInterface
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.identity.BiometricAuthorizer
import org.foggyden.hexline.identity.HeldSeeds
import org.foggyden.hexline.identity.HolderSetups
import org.foggyden.hexline.identity.Identities
import org.foggyden.hexline.identity.SettingUp
import org.foggyden.hexline.identity.Setup
import org.foggyden.hexline.secrets.KeystoreHolderKeys
import org.foggyden.hexline.secrets.SecretStore
import org.foggyden.hexline.servers.SavedServers
import org.foggyden.hexline.servers.StoreQueue
import org.foggyden.hexline.setupActions
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * The holder setup screen on a real Android, with the real Keystore and
 * the system's prompt, answered by typing the PIN into it as a person
 * would; only the registrar is the test's, answering every commit.
 */
@RunWith(AndroidJUnit4::class)
class HolderSetupScreenTest {
    @get:Rule
    val rule = createAndroidComposeRule<EmptyFragmentActivity>()

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val identityDir = File(context.filesDir, "identities-setup-test")
    private val heldDir = File(context.filesDir, "held-setup-test")
    private val identities = Identities(context, SecretStore(context), identityDir)
    private var held: HeldSeeds? = null
    private var made: String? = null

    @Before
    fun lock() {
        assumeTrue("holder mode needs API 30", Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
        shell("locksettings clear --old $PIN")
        shell("locksettings set-pin $PIN")
    }

    @After
    fun unlock() {
        made?.let { fp ->
            runCatching { held?.forget(fp) }
            identities.delete(fp)
        }
        identityDir.deleteRecursively()
        heldDir.deleteRecursively()
        shell("locksettings clear --old $PIN")
    }

    private fun text(id: Int) = context.getString(id)

    /** The model the app makes, over stores of the test's own and its registrar. */
    private fun model(softwareKeys: Boolean): ChatViewModel {
        val seeds = HeldSeeds(heldDir, KeystoreHolderKeys(context), Dispatchers.IO, softwareKeys).also { held = it }
        var vm: ChatViewModel? = null
        rule.runOnUiThread {
            vm =
                ChatViewModel(
                    rule.activity.application,
                    SavedServers(context),
                    identities,
                    seeds,
                    StoreQueue(Dispatchers.IO.limitedParallelism(1)),
                    { _, _ -> error("no server here") },
                    { _, _ -> error("no mailbox here") },
                    OfflineSetups,
                    { System.currentTimeMillis() / 1000 },
                    ProcessLifecycleOwner.get().lifecycle,
                )
        }
        val model = checkNotNull(vm)
        // The activity has a view of its own: the screen goes in one of the test's.
        rule.runOnUiThread {
            val activity = rule.activity
            activity.setContentView(
                ComposeView(activity).apply {
                    setContent {
                        MaterialTheme {
                            val state by model.holderSetup.collectAsState()
                            HolderSetupScreen(
                                state,
                                setupActions(model, BiometricAuthorizer(activity, "Hexline", "Hold this identity's key")),
                            ) {}
                        }
                    }
                },
            )
        }
        return model
    }

    private fun begin() {
        rule.onNode(hasSetTextAction() and hasText(text(R.string.registrar))).performTextInput("reg.example")
        rule.onNode(hasSetTextAction() and hasText(text(R.string.handle))).performTextInput("carol")
        rule.onNode(hasText(text(R.string.holder_continue))).performClick()
    }

    private fun secure(): Boolean {
        var flags = 0
        rule.runOnUiThread { flags = rule.activity.window.attributes.flags }
        return flags and WindowManager.LayoutParams.FLAG_SECURE != 0
    }

    private fun <T : SettingUp> reached(
        vm: ChatViewModel,
        state: Class<T>,
    ): T {
        rule.waitUntil(15_000) { state.isInstance(vm.holderSetup.value) }
        return state.cast(vm.holderSetup.value)!!
    }

    @Test
    fun anIdentityIsSetUpOnTheScreenHeldBehindThePromptAndGoesWithTheScreenLock() {
        val vm = model(softwareKeys = true)
        begin()
        assertFalse("nothing secret on screen yet", secure())
        val successor = reached(vm, SettingUp.Successor::class.java).code
        rule.waitForIdle()
        assertTrue("a code kept off screenshots", secure())
        rule.onNode(hasText(text(R.string.holder_written))).performClick()
        rule.onNode(hasSetTextAction() and hasText(text(R.string.holder_confirm_successor))).performTextInput(successor)
        rule.onNode(hasText(text(R.string.holder_confirm))).performClick()
        val recovery = reached(vm, SettingUp.Recovery::class.java).code
        rule.onNode(hasText(text(R.string.holder_written))).performClick()
        rule.onNode(hasSetTextAction() and hasText(text(R.string.holder_confirm_recovery))).performTextInput(recovery)
        rule.onNode(hasText(text(R.string.holder_confirm))).performClick()
        reached(vm, SettingUp.ReadyToHold::class.java)
        rule.waitForIdle()
        assertFalse("no code on screen", secure())
        rule.onNode(hasText(text(R.string.holder_hold))).performClick()
        val deadline = System.currentTimeMillis() + 30_000
        while (vm.holderSetup.value !is SettingUp.Done && System.currentTimeMillis() < deadline) {
            Thread.sleep(1_500)
            if (vm.holderSetup.value is SettingUp.Done) break
            shell("input text $PIN")
            shell("input keyevent KEYCODE_ENTER")
        }
        val fingerprint = reached(vm, SettingUp.Done::class.java).fingerprint.also { made = it }
        val kept = identities.list().single { it.fingerprint == fingerprint }
        assertFalse("committed", kept.unfinished)
        assertEquals("carol", kept.handle)
        val seeds = checkNotNull(held)
        assertTrue(seeds.isHeld(fingerprint))
        shell("locksettings clear --old $PIN")
        assertEquals(listOf(fingerprint), seeds.demoteLost(listOf(fingerprint)))
        assertFalse(seeds.isHeld(fingerprint))
        assertEquals(listOf(fingerprint), seeds.notices())
    }

    @Test
    fun aKeystoreInSoftwareIsRefusedOnTheScreenOutsideADebugBuild() {
        assumeTrue("the emulator's KeyMint is software", Build.HARDWARE in setOf("ranchu", "goldfish"))
        val vm = model(softwareKeys = false)
        begin()
        reached(vm, SettingUp.Refused::class.java)
        rule.onNode(hasText(text(R.string.holder_software_only))).assertExists()
    }

    /** A registrar that takes every commit, the setups otherwise the core's. */
    private object OfflineSetups : HolderSetups {
        override fun new(name: String): Setup = Offline(HolderSetup(name))

        override fun resume(
            identitySeed: ByteArray,
            card: ByteArray,
            registrar: String,
            handle: String,
            deviceSeed: ByteArray,
            deviceCert: ByteArray,
        ): Setup = error("not resumed here")

        override fun checkDeviceName(name: String) =
            org.foggyden.hexline.core
                .checkDeviceName(name)

        override suspend fun check(registrar: String) = Unit

        override suspend fun restoreToHold(
            registrar: String,
            handle: String,
            kind: SecretKind,
            secret: String,
            deviceName: String,
        ): HeldRestore = error("not restored here")
    }

    private class Offline(
        private val setup: HolderSetup,
    ) : Setup,
        HolderSetupInterface by setup {
        override suspend fun commit(
            registrar: String,
            handle: String,
            invite: String?,
        ) = HolderCommitted(setup.card())

        override fun close() = setup.close()
    }

    private fun shell(command: String) {
        instrumentation.uiAutomation.executeShellCommand(command).use { pfd ->
            ParcelFileDescriptor.AutoCloseInputStream(pfd).readBytes()
        }
    }

    private companion object {
        const val PIN = "1234"
    }
}
