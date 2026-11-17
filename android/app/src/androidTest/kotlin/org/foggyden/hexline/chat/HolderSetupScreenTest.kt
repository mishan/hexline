package org.foggyden.hexline.chat

import android.content.Context
import android.os.Build
import android.os.ParcelFileDescriptor
import android.view.WindowManager
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.fragment.app.testing.EmptyFragmentActivity
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewmodel.CreationExtras
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
import java.security.KeyStore

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

    // Stores of the test's own: nothing the app or an earlier run saved reaches the model.
    private val secretDir = File(context.filesDir, "secrets-setup-test")
    private val secrets = SecretStore(context, STORE, secretDir)
    private val identities = Identities(context, secrets, identityDir)
    private val servers = SavedServers(context, secrets, context.getSharedPreferences(STORE, Context.MODE_PRIVATE))
    private val owner = ViewModelStore()
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
        // Cleared as an activity's would be, letting go of what it registered.
        rule.runOnUiThread { owner.clear() }
        made?.let { fp ->
            runCatching { held?.forget(fp) }
            identities.delete(fp)
        }
        identityDir.deleteRecursively()
        heldDir.deleteRecursively()
        secretDir.deleteRecursively()
        context.deleteSharedPreferences(STORE)
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(STORE)
        shell("locksettings clear --old $PIN")
    }

    private fun text(id: Int) = context.getString(id)

    /** The model the app makes, over stores of the test's own and its registrar. */
    private fun model(softwareKeys: Boolean): ChatViewModel {
        val seeds = HeldSeeds(heldDir, KeystoreHolderKeys(context), Dispatchers.IO, softwareKeys).also { held = it }
        val factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(
                    modelClass: Class<T>,
                    extras: CreationExtras,
                ): T =
                    ChatViewModel(
                        rule.activity.application,
                        servers,
                        identities,
                        seeds,
                        StoreQueue(Dispatchers.IO.limitedParallelism(1)),
                        { _, _ -> error("no server here") },
                        { _, _ -> error("no mailbox here") },
                        OfflineSetups,
                        { System.currentTimeMillis() / 1000 },
                        ProcessLifecycleOwner.get().lifecycle,
                    ) as T
            }
        var vm: ChatViewModel? = null
        rule.runOnUiThread { vm = ViewModelProvider.create(owner, factory)[ChatViewModel::class.java] }
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
        type(R.string.registrar, "reg.example")
        type(R.string.handle, "carol")
        tap(R.string.holder_continue)
    }

    // Scrolled to first, as a person would: a small screen, as CI's emulator has, puts
    // most of the form below the fold, where a tap lands outside the window.
    private fun tap(label: Int) {
        rule.onNode(hasText(text(label))).performScrollTo().performClick()
    }

    private fun type(
        label: Int,
        typed: String,
    ) {
        rule.onNode(hasSetTextAction() and hasText(text(label))).performScrollTo().performTextInput(typed)
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
        try {
            rule.waitUntil(15_000) { state.isInstance(vm.holderSetup.value) }
        } catch (e: ComposeTimeoutException) {
            // What it stopped at, its codes left out as the states print them.
            throw AssertionError("waited for ${state.simpleName}, at ${vm.holderSetup.value}", e)
        }
        return state.cast(vm.holderSetup.value)!!
    }

    @Test
    fun anIdentityIsSetUpOnTheScreenHeldBehindThePromptAndGoesWithTheScreenLock() {
        val vm = model(softwareKeys = true)
        rule.waitForIdle()
        assertFalse("nothing secret on screen yet", secure())
        begin()
        val successor = reached(vm, SettingUp.Successor::class.java).code
        rule.waitForIdle()
        assertTrue("a code kept off screenshots", secure())
        tap(R.string.holder_written)
        type(R.string.holder_confirm_successor, successor)
        tap(R.string.holder_confirm)
        val recovery = reached(vm, SettingUp.Recovery::class.java).code
        tap(R.string.holder_written)
        type(R.string.holder_confirm_recovery, recovery)
        tap(R.string.holder_confirm)
        reached(vm, SettingUp.ReadyToHold::class.java)
        rule.waitForIdle()
        assertFalse("no code on screen", secure())
        tap(R.string.holder_hold)
        // Typed only into the system's own prompt, once it has the focus: keys sent
        // before it is up go to nothing, or count as a wrong PIN.
        val deadline = System.currentTimeMillis() + 60_000
        var typed = false
        while (vm.holderSetup.value !is SettingUp.Done && System.currentTimeMillis() < deadline) {
            Thread.sleep(1_000)
            val focus = shell("dumpsys window").lineSequence().firstOrNull { "mCurrentFocus=" in it }.orEmpty()
            if (!typed && "Window{" in focus && context.packageName !in focus) {
                shell("input text $PIN")
                shell("input keyevent KEYCODE_ENTER")
                typed = true
            } else if (context.packageName in focus) {
                typed = false
            }
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

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use { pfd ->
            String(ParcelFileDescriptor.AutoCloseInputStream(pfd).readBytes())
        }

    private companion object {
        const val PIN = "1234"
        const val STORE = "hexline-setup-test"
    }
}
