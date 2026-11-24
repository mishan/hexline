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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import org.foggyden.hexline.R
import org.foggyden.hexline.core.Caps
import org.foggyden.hexline.core.Certified
import org.foggyden.hexline.core.DeviceStanding
import org.foggyden.hexline.core.DeviceStandings
import org.foggyden.hexline.core.DevicesReset
import org.foggyden.hexline.core.Evidence
import org.foggyden.hexline.core.HeldRestore
import org.foggyden.hexline.core.HolderCommitted
import org.foggyden.hexline.core.HolderKept
import org.foggyden.hexline.core.HolderRequest
import org.foggyden.hexline.core.HolderSetup
import org.foggyden.hexline.core.HolderSetupInterface
import org.foggyden.hexline.core.ListedDevice
import org.foggyden.hexline.core.PostOutcome
import org.foggyden.hexline.core.Qr
import org.foggyden.hexline.core.ResetRetried
import org.foggyden.hexline.core.RevokeReason
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.certForDevice
import org.foggyden.hexline.core.deviceFingerprintOf
import org.foggyden.hexline.core.holderMint
import org.foggyden.hexline.core.holderRenew
import org.foggyden.hexline.identity.BackingUp
import org.foggyden.hexline.identity.BiometricAuthorizer
import org.foggyden.hexline.identity.CertifySession
import org.foggyden.hexline.identity.Certifying
import org.foggyden.hexline.identity.HeldSeeds
import org.foggyden.hexline.identity.HolderSetups
import org.foggyden.hexline.identity.Identities
import org.foggyden.hexline.identity.NewRecoveryCode
import org.foggyden.hexline.identity.Renewing
import org.foggyden.hexline.identity.ResetRetries
import org.foggyden.hexline.identity.SettingUp
import org.foggyden.hexline.identity.Setup
import org.foggyden.hexline.secrets.KeystoreHolderKeys
import org.foggyden.hexline.secrets.SecretStore
import org.foggyden.hexline.servers.SavedServers
import org.foggyden.hexline.servers.StoreQueue
import org.foggyden.hexline.setupActions
import org.junit.After
import org.junit.Assert.assertArrayEquals
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
                        retries = NoRetries,
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

    /**
     * The system's prompt answered with the PIN until [done]: typed only once
     * the prompt has the focus, as keys sent before it is up go to nothing,
     * or count as a wrong PIN.
     */
    private fun answer(done: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 60_000
        var typed = false
        while (!done() && System.currentTimeMillis() < deadline) {
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
    fun anIdentityIsSetUpOnTheScreenHeldBehindThePromptCertifiesAnotherDeviceAndGoesWithTheScreenLock() {
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
        answer { vm.holderSetup.value is SettingUp.Done }
        val fingerprint = reached(vm, SettingUp.Done::class.java).fingerprint.also { made = it }
        val kept = identities.list().single { it.fingerprint == fingerprint }
        assertFalse("committed", kept.unfinished)
        assertEquals("carol", kept.handle)
        val seeds = checkNotNull(held)
        assertTrue(seeds.isHeld(fingerprint))
        // This phone's certificate renewed by the key it holds, behind the prompt again.
        var authorizer: BiometricAuthorizer? = null
        rule.runOnUiThread { authorizer = BiometricAuthorizer(rule.activity, "Hexline", "Renew this phone") }
        rule.runOnUiThread { vm.renewHeld(fingerprint, checkNotNull(authorizer)) }
        answer { vm.renewing.value !is Renewing.Working }
        assertEquals(Renewing.Done(fingerprint), vm.renewing.value)
        // Another device certified by the key, approved on the devices screen behind the prompt.
        devicesScreen(vm, fingerprint)
        tap(R.string.certify_start)
        rule.waitUntil(15_000) { vm.certify.value is Certifying.Showing }
        val lm = Caps(login = true, message = true, manage = false, vouch = false)
        val asked = HolderRequest(ByteArray(32) { 7 }, "b283bthc", "Tablet", false, false, null, null, lm, true, 90uL * 86_400uL)
        OfflineSetups.session.next.complete(asked)
        rule.waitUntil(15_000) { vm.certify.value is Certifying.Asked }
        rule.onNode(hasText("b283bthc")).assertExists()
        tap(R.string.certify_approve)
        answer { vm.certify.value is Certifying.Approved }
        val approved = (vm.certify.value as Certifying.Approved).device
        assertEquals("certified by the identity's own key", fingerprint, OfflineSetups.session.certifiedBy)
        // The key the screen handed the core to certify, not the subject of a certificate:
        // this mailbox makes none for it.
        assertArrayEquals("the device asked about, as passed to certify", asked.device, approved.device)
        assertTrue(OfflineSetups.session.delivered)
        rule.waitUntil(15_000) {
            vm.devices.value
                ?.devices
                .orEmpty()
                .any { it.device.contentEquals(asked.device) }
        }
        // A code shown when the screen goes admits nobody.
        tap(R.string.certify_start)
        rule.waitUntil(15_000) { vm.certify.value is Certifying.Showing }
        val shown = OfflineSetups.session
        rule.runOnUiThread { rule.activity.setContentView(android.view.View(rule.activity)) }
        rule.waitForIdle()
        assertTrue("given back with the screen", shown.canceled)
        shell("locksettings clear --old $PIN")
        assertEquals(listOf(fingerprint), seeds.demoteLost(listOf(fingerprint)))
        assertFalse(seeds.isHeld(fingerprint))
        assertEquals(listOf(fingerprint), seeds.notices())
    }

    private fun devicesScreen(
        vm: ChatViewModel,
        fingerprint: String,
    ) {
        rule.runOnUiThread {
            val activity = rule.activity
            activity.setContentView(
                ComposeView(activity).apply {
                    setContent {
                        MaterialTheme {
                            val certifying by vm.certify.collectAsState()
                            val devices by vm.devices.collectAsState()
                            val revoking by vm.revoking.collectAsState()
                            DevicesScreen(
                                fingerprint,
                                "carol",
                                "mail.example",
                                devices,
                                certifying,
                                revoking,
                                setupActions(vm, BiometricAuthorizer(activity, "Hexline", "Certify a device")),
                            ) {}
                        }
                    }
                },
            )
        }
        rule.waitForIdle()
    }

    @Test
    fun theBackupScreenIsKeptFromScreenshotsWhileItIsUp() {
        val vm = model(softwareKeys = true)
        rule.waitForIdle()
        assertFalse(secure())
        rule.runOnUiThread {
            val activity = rule.activity
            activity.setContentView(
                ComposeView(activity).apply {
                    setContent {
                        MaterialTheme {
                            BackupScreen(
                                "fp",
                                "carol",
                                BackingUp.Idle,
                                setupActions(vm, BiometricAuthorizer(activity, "Hexline", "Back up this identity")),
                            ) {}
                        }
                    }
                },
            )
        }
        rule.waitForIdle()
        assertTrue("a passphrase typed is kept off screenshots", secure())
        rule.runOnUiThread { rule.activity.setContentView(android.view.View(rule.activity)) }
        rule.waitForIdle()
        assertFalse("and the window let go once the screen is", secure())
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

        override fun renew(
            identitySeed: ByteArray,
            card: ByteArray,
            deviceSeed: ByteArray,
            cert: ByteArray,
            epoch: Long,
        ) = holderRenew(identitySeed, card, deviceSeed, cert, epoch.toULong())

        override suspend fun putPassphrase(
            identitySeed: ByteArray,
            registrar: String,
            passphrase: String,
        ): Unit = error("no backups here")

        override suspend fun deleteBackup(
            identitySeed: ByteArray,
            registrar: String,
            kind: SecretKind,
        ): Unit = error("no backups here")

        override fun newRecoveryCode(): NewRecoveryCode = error("no backups here")

        lateinit var session: Mailbox

        override suspend fun openSession(
            mailbox: String,
            card: ByteArray,
            kept: HolderKept,
        ): CertifySession = Mailbox(mailbox, card).also { session = it }

        override suspend fun revoke(
            identitySeed: ByteArray,
            registrar: String,
            device: ByteArray,
            reason: RevokeReason,
            until: Long,
            thisDevice: ByteArray,
        ): Unit = error("no registrar here")

        override suspend fun standing(
            card: ByteArray,
            registrars: List<String>,
            epoch: Long,
            devices: List<ListedDevice>,
        ) = DeviceStandings(devices.map { DeviceStanding.IN_FORCE }, complete = false)

        override fun evidence(card: ByteArray) = Evidence(emptyList(), 0uL)

        override fun deviceFingerprint(device: ByteArray) = deviceFingerprintOf(device)

        override fun floor(card: ByteArray) = 0L

        override suspend fun postRotation(
            registrar: String,
            record: ByteArray,
        ): PostOutcome = error("no registrar here")

        override suspend fun resetDevices(
            identitySeed: ByteArray,
            card: ByteArray,
            registrars: List<String>,
            epoch: Long,
            deviceSeed: ByteArray,
            cert: ByteArray,
        ): DevicesReset = error("no registrar here")

        override suspend fun retryReset(
            retry: ByteArray,
            card: ByteArray,
        ): ResetRetried = error("no registrar here")
    }

    /** No reset is made here, so none is retried. */
    private object NoRetries : ResetRetries {
        override fun schedule(
            fingerprint: String,
            inSecs: Long,
        ) = Unit

        override fun ensure(
            fingerprint: String,
            inSecs: Long,
        ) = Unit

        override fun cancel(fingerprint: String) = Unit
    }

    /** A mailbox that hands over the request the test makes, and certifies with the seed it is handed. */
    private class Mailbox(
        private val host: String,
        private val card: ByteArray,
    ) : CertifySession {
        val next = CompletableDeferred<HolderRequest>()

        /** The identity whose key certified the device: the seed the approval was handed signs for it. */
        var certifiedBy: String? = null

        override fun code() = "K7PM-QX2D"

        override fun identity() = "3f2a8c1d"

        override fun host() = host

        override fun expiresIn() = 600uL

        override fun qr(): Qr? = null

        override suspend fun nextRequest() = next.await()

        override suspend fun answerEnds() = CompletableDeferred<Unit>().await()

        var delivered = false

        override suspend fun certify(
            identitySeed: ByteArray,
            manage: Boolean,
            device: ByteArray,
            listed: List<ListedDevice>,
        ): Certified {
            val asked = next.await()
            check(device.contentEquals(asked.device)) { "certified a device not asked about" }
            // A certificate the seed it was handed makes: which identity's it is says whose seed that was.
            val minted = holderMint(identitySeed, card, "Tablet", 0uL)
            val info = certForDevice(minted.cert, card, minted.deviceSeed)
            certifiedBy = info.fingerprint
            return Certified(device, asked.name, manage, info.expires)
        }

        override suspend fun deliver() {
            delivered = true
        }

        override suspend fun deny(reason: String) = Unit

        var canceled = false

        override fun cancel() {
            canceled = true
        }

        override fun close() = Unit
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
