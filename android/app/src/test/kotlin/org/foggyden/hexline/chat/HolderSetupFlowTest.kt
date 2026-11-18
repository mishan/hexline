package org.foggyden.hexline.chat

import androidx.lifecycle.ViewModelStore
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.newIdentity
import org.foggyden.hexline.identity.Backed
import org.foggyden.hexline.identity.BackingUp
import org.foggyden.hexline.identity.HolderRefusal
import org.foggyden.hexline.identity.Renewing
import org.foggyden.hexline.identity.RestoreProblem
import org.foggyden.hexline.identity.Restoring
import org.foggyden.hexline.identity.SettingUp
import org.foggyden.hexline.identity.SetupProblem
import org.foggyden.hexline.secrets.SecretUnavailable
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.IOException
import java.security.ProviderException

@RunWith(RobolectricTestRunner::class)
@Config(application = android.app.Application::class)
class HolderSetupFlowTest : ViewModelHarness() {
    private fun bytes(text: String) = text.toByteArray()

    /** A setup started and walked through both codes, as the person would; its typed bytes wiped. */
    private fun throughTheCodes(vm: ChatViewModel): FakeSetups.FakeSetup {
        vm.startHolderSetup("reg.example", "carol", null, "Pixel")
        settle()
        val setup = setups.made.single()
        assertEquals(SettingUp.Successor("SUCCE-SSORC-ODE00"), vm.holderSetup.value)
        vm.successorWritten()
        val wrong = bytes("SUCCE-SSORC-ODE01")
        vm.confirmSuccessor(wrong)
        assertEquals(SettingUp.ConfirmSuccessor(true), vm.holderSetup.value)
        assertTrue("typed bytes wiped", wrong.all { it == 0.toByte() })
        vm.confirmSuccessor(bytes("SUCCE-SSORC-ODE00"))
        assertEquals(SettingUp.Recovery(setup.recovery, replaces = false), vm.holderSetup.value)
        vm.recoveryWritten()
        vm.confirmRecovery(bytes(setup.recovery))
        assertEquals(SettingUp.ReadyToHold, vm.holderSetup.value)
        return setup
    }

    private fun keptIdentities() = outside { identities.list() }

    @Test
    fun aHolderIsSetUpThroughBothCodesThenHeldThenCommitted() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        vm.holdSetup(stores.keys.authorizer())
        settle()
        assertEquals(SettingUp.Done(setup.fingerprint()), vm.holderSetup.value)
        assertEquals(listOf(Triple("reg.example", "carol", null as String?)), setup.commits)
        assertTrue("let go of", setup.closed)
        assertTrue(stores.held.isHeld(setup.fingerprint()))
        val identity = keptIdentities().single()
        assertFalse(identity.unfinished)
        assertEquals("carol", identity.handle)
        assertEquals("reg.example", identity.registrar)
        assertTrue("every seed handed out wiped", setups.handed.all { seed -> seed.all { it == 0.toByte() } })
    }

    @Test
    fun aPhoneThatCannotHoldIsToldSoBeforeAnyCodeIsMade() {
        for ((why, cannot) in listOf<Pair<HolderRefusal, () -> Unit>>(
            HolderRefusal.NoScreenLock to { stores.keys.removeLock() },
            HolderRefusal.SoftwareOnly to { stores.keys.level = "software" },
        )) {
            fresh()
            setups = FakeSetups()
            cannot()
            val vm = model()
            settle()
            vm.startHolderSetup("reg.example", "carol", null, "Pixel")
            settle()
            assertEquals("$why", SettingUp.Refused(why), vm.holderSetup.value)
            assertEquals("$why: no codes", emptyList<FakeSetups.FakeSetup>(), setups.made)
            assertEquals("$why: no key", emptyList<String>(), stores.keys.aliases)
        }
    }

    @Test
    fun aRegistrarThatCannotKeepTheRecoveryCodeIsToldBeforeAnyCodeIsMade() {
        setups.checkFails = CoreException.Refused("no_envelopes", "")
        val vm = model()
        settle()
        vm.startHolderSetup("reg.example", "carol", null, "Pixel")
        settle()
        assertEquals(SettingUp.Failed(SetupProblem.NoBackups, "carol", fixed = false), vm.holderSetup.value)
        assertEquals(emptyList<FakeSetups.FakeSetup>(), setups.made)
    }

    @Test
    fun aPromptRefusedLeavesTheSetupReadyToHoldAndNothingKept() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        vm.holdSetup(stores.keys.authorizer { false })
        settle()
        assertEquals(SettingUp.ReadyToHold, vm.holderSetup.value)
        assertEquals(emptyList<Any>(), keptIdentities())
        assertEquals(emptyList<String>(), stores.keys.aliases)
        assertEquals(emptyList<Any>(), setup.commits)
    }

    @Test
    fun aHandleTakenIsAskedAgainAsAnotherAndKeptAsIt() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        setup.answers += CoreException.Refused("handle_taken", "")
        vm.holdSetup(stores.keys.authorizer())
        settle()
        assertEquals(SettingUp.Failed(SetupProblem.HandleTaken, "carol", fixed = false), vm.holderSetup.value)
        assertTrue("kept, unfinished, while it is asked again", keptIdentities().single().unfinished)
        vm.retrySetup("carol2", null)
        settle()
        assertEquals(SettingUp.Done(setup.fingerprint()), vm.holderSetup.value)
        assertEquals(listOf("carol", "carol2"), setup.commits.map { it.second })
        assertEquals("carol2", keptIdentities().single().handle)
    }

    @Test
    fun aBackupThatDidNotGoThroughIsAskedAgainAsItsOwnHandle() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        setup.answers += CoreException.Refused("registered_not_backed_up", "")
        vm.holdSetup(stores.keys.authorizer())
        settle()
        assertEquals(SettingUp.Failed(SetupProblem.NotBackedUp, "carol", fixed = true), vm.holderSetup.value)
        vm.retrySetup("someone-else", null)
        settle()
        assertEquals(SettingUp.Done(setup.fingerprint()), vm.holderSetup.value)
        assertEquals(listOf("carol", "carol"), setup.commits.map { it.second })
    }

    @Test
    fun aSetupTheProcessEndedInIsFinishedUnderANewRecoveryCodeThatSaysItReplaces() {
        val vm = model()
        settle()
        val first = throughTheCodes(vm)
        first.answers += CoreException.Connect("unreachable")
        vm.holdSetup(stores.keys.authorizer())
        settle()
        val fingerprint = first.fingerprint()
        forgetDeadProcess()
        owner = ViewModelStore()

        val again = model()
        settle()
        assertTrue(
            "shown unfinished",
            again.identityList.value
                .single()
                .unfinished,
        )
        again.finishSetup(fingerprint, stores.keys.authorizer())
        settle()
        val resumed = setups.made.last()
        assertEquals("reg.example" to "carol", resumed.resumed)
        assertEquals(SettingUp.Recovery(resumed.recovery, replaces = true), again.holderSetup.value)
        again.recoveryWritten()
        again.confirmRecovery(bytes(resumed.recovery))
        settle()
        assertEquals(SettingUp.Done(fingerprint), again.holderSetup.value)
        assertFalse(keptIdentities().single().unfinished)
    }

    @Test
    fun aSetupWhoseKeyWentIsLetGoOfWithItsNotice() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        setup.answers += CoreException.Connect("unreachable")
        vm.holdSetup(stores.keys.authorizer())
        settle()
        stores.keys.invalidate(stores.keys.aliases.single())
        vm.finishSetup(setup.fingerprint(), stores.keys.authorizer())
        settle()
        assertEquals(SettingUp.Failed(SetupProblem.KeyLost, "carol", fixed = true), vm.holderSetup.value)
        assertEquals(listOf(setup.fingerprint()), vm.heldLostNotices.value)
        val left = keptIdentities().single()
        assertFalse("no setup left to finish", left.unfinished)
        assertTrue("and none to recover", left.unrecoverable)
    }

    @Test
    fun aSetupCanceledBeforeItsKeyIsHeldLeavesNothing() {
        val vm = model()
        settle()
        vm.startHolderSetup("reg.example", "carol", null, "Pixel")
        settle()
        vm.cancelHolderSetup()
        assertEquals(SettingUp.Idle, vm.holderSetup.value)
        assertTrue(setups.made.single().closed)
        assertEquals(emptyList<Any>(), keptIdentities())
        assertEquals(emptyList<String>(), stores.keys.aliases)
    }

    @Test
    fun anIdentityRestoredToHoldIsKeptAndHeldAndItsSeedWiped() {
        val identity = newIdentity("Dana")
        setups.restores = identity
        val vm = model()
        settle()
        vm.restore("reg.example", "dana", SecretKind.RECOVERY_CODE, "code", "Pixel", stores.keys.authorizer())
        settle()
        assertEquals(Restoring.Done(identity.fingerprint), vm.restore.value)
        assertTrue(stores.held.isHeld(identity.fingerprint))
        assertEquals(identity.fingerprint, keptIdentities().single().fingerprint)
        assertTrue("its seed wiped", setups.handed.single().all { it == 0.toByte() })
    }

    @Test
    fun aDeviceNameNoServerReadsIsRefusedBeforeAnyCodeIsMade() {
        val vm = model()
        settle()
        vm.startHolderSetup("reg.example", "carol", null, "x".repeat(70))
        settle()
        assertEquals(SettingUp.Failed(SetupProblem.BadDeviceName, "carol", fixed = false), vm.holderSetup.value)
        assertEquals(emptyList<FakeSetups.FakeSetup>(), setups.made)
    }

    @Test
    fun theKeystoresTroubleIsToldAndThrownAtNothing() {
        stores.keys.trouble = { ProviderException("busy") }
        val vm = model()
        settle()
        vm.startHolderSetup("reg.example", "carol", null, "Pixel")
        settle()
        assertEquals(SettingUp.Failed(SetupProblem.NotKept, "carol", fixed = false), vm.holderSetup.value)
        setups.restores = newIdentity("Dana")
        vm.restore("reg.example", "dana", SecretKind.RECOVERY_CODE, "code", "Pixel", stores.keys.authorizer())
        settle()
        assertEquals(Restoring.Failed(RestoreProblem.NotKept), vm.restore.value)
    }

    @Test
    fun aCheckThatFailedTriedAgainGoesBackToTheForm() {
        setups.checkFails = CoreException.Connect("unreachable")
        val vm = model()
        settle()
        vm.startHolderSetup("reg.example", "carol", null, "Pixel")
        settle()
        vm.retrySetup("carol", null)
        assertEquals(SettingUp.Idle, vm.holderSetup.value)
    }

    @Test
    fun aSeedHeldForADeviceNotKeptIsLetGoOfOnCancel() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        secrets.putFails = { SecretUnavailable("device", IOException("locked")) }
        vm.holdSetup(stores.keys.authorizer())
        settle()
        assertEquals(SettingUp.Failed(SetupProblem.NotKept, "carol", fixed = false), vm.holderSetup.value)
        secrets.putFails = null
        vm.cancelHolderSetup()
        settle()
        assertFalse(stores.held.isHeld(setup.fingerprint()))
        assertEquals(emptyList<String>(), stores.keys.aliases)
    }

    @Test
    fun aCommitWhoseWriteHereFailedIsWrittenAgainAlone() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        setup.onCommit = { stores.identityDir.setWritable(false) }
        vm.holdSetup(stores.keys.authorizer())
        settle()
        assertEquals(SettingUp.Failed(SetupProblem.NotKept, "carol", fixed = false), vm.holderSetup.value)
        stores.identityDir.setWritable(true)
        setup.onCommit = {}
        vm.retrySetup("carol", null)
        settle()
        assertEquals(SettingUp.Done(setup.fingerprint()), vm.holderSetup.value)
        assertEquals("committed once", 1, setup.commits.size)
        assertFalse(keptIdentities().single().unfinished)
    }

    @Test
    fun aCodeAskedForAgainOutOfTurnIsNotFetched() {
        val vm = model()
        settle()
        vm.startHolderSetup("reg.example", "carol", null, "Pixel")
        settle()
        vm.showSuccessorAgain()
        assertTrue("every code handed out wiped", setups.codes.all { code -> code.all { it == 0.toByte() } })
    }

    @Test
    fun aCodeOnScreenIsNotWrittenToALog() {
        for (shown in listOf(SettingUp.Successor("SECRET"), SettingUp.Recovery("SECRET", false))) {
            assertFalse("$shown", "SECRET" in shown.toString())
        }
    }

    @Test
    fun anIdentityRestoredWhosePromptWasRefusedIsSaidToBeADeviceAlone() {
        val identity = newIdentity("Dana")
        setups.restores = identity
        val vm = model()
        settle()
        vm.restore("reg.example", "dana", SecretKind.RECOVERY_CODE, "code", "Pixel", stores.keys.authorizer { false })
        settle()
        assertEquals(Restoring.NotHeld(identity.fingerprint), vm.restore.value)
        assertFalse(stores.held.isHeld(identity.fingerprint))
        assertEquals(identity.fingerprint, keptIdentities().single().fingerprint)
    }

    @Test
    fun aResumedSetupRefusedItsHandleIsAskedAgainAsAnother() {
        val vm = model()
        settle()
        val first = throughTheCodes(vm)
        first.answers += CoreException.Connect("unreachable")
        vm.holdSetup(stores.keys.authorizer())
        settle()
        vm.cancelHolderSetup()
        vm.finishSetup(first.fingerprint(), stores.keys.authorizer())
        settle()
        val resumed = setups.made.last()
        resumed.answers += CoreException.Refused("handle_taken", "")
        vm.recoveryWritten()
        vm.confirmRecovery(bytes(resumed.recovery))
        settle()
        assertEquals(SettingUp.Failed(SetupProblem.HandleTaken, "carol", fixed = false), vm.holderSetup.value)
        vm.retrySetup("carol2", null)
        settle()
        assertEquals(SettingUp.Done(first.fingerprint()), vm.holderSetup.value)
        assertEquals(listOf("carol", "carol2"), resumed.commits.map { it.second })
    }

    @Test
    fun aStepAskedForTwiceIsTakenOnce() {
        val vm = model()
        settle()
        vm.startHolderSetup("reg.example", "carol", null, "Pixel")
        settle()
        val setup = setups.made.single()
        vm.successorWritten()
        vm.confirmSuccessor(bytes("SUCCE-SSORC-ODE00"))
        vm.recoveryWritten()
        vm.confirmRecovery(bytes(setup.recovery))
        val again = bytes(setup.recovery)
        vm.confirmRecovery(again)
        assertEquals(SettingUp.ReadyToHold, vm.holderSetup.value)
        assertTrue("wiped though not asked for", again.all { it == 0.toByte() })
        setup.answers += CoreException.Connect("unreachable")
        vm.holdSetup(stores.keys.authorizer())
        vm.holdSetup(stores.keys.authorizer())
        settle()
        assertEquals("held once", 1, stores.keys.begun.size)
        vm.retrySetup("carol", null)
        vm.retrySetup("carol", null)
        settle()
        assertEquals("committed twice in all", 2, setup.commits.size)
    }

    @Test
    fun aRecoveryCodeTypedBackTwiceCommitsOnce() {
        val vm = model()
        settle()
        val first = throughTheCodes(vm)
        first.answers += CoreException.Connect("unreachable")
        vm.holdSetup(stores.keys.authorizer())
        settle()
        vm.cancelHolderSetup()
        vm.finishSetup(first.fingerprint(), stores.keys.authorizer())
        settle()
        val resumed = setups.made.last()
        vm.recoveryWritten()
        vm.confirmRecovery(bytes(resumed.recovery))
        vm.confirmRecovery(bytes(resumed.recovery))
        settle()
        assertEquals(1, resumed.commits.size)
    }

    @Test
    fun aHandleCommittedAtTheRegistrarIsTheOneKeptWhateverARetryAsks() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        setup.onCommit = { stores.identityDir.setWritable(false) }
        vm.holdSetup(stores.keys.authorizer())
        settle()
        assertEquals(SettingUp.Failed(SetupProblem.NotKept, "carol", fixed = false), vm.holderSetup.value)
        stores.identityDir.setWritable(true)
        setup.onCommit = {}
        vm.retrySetup("carol2", null)
        settle()
        assertEquals(SettingUp.Done(setup.fingerprint()), vm.holderSetup.value)
        assertEquals("as the registrar took it", "carol", keptIdentities().single().handle)
        assertEquals(1, setup.commits.size)
    }

    /** An identity set up and held here, committed: its fingerprint. */
    private fun heldHere(vm: ChatViewModel): String {
        val setup = throughTheCodes(vm)
        vm.holdSetup(stores.keys.authorizer())
        settle()
        return setup.fingerprint()
    }

    @Test
    fun aHeldIdentitysDeviceIsRenewedBehindThePromptAndNotWithoutIt() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        assertTrue(
            "listed as held",
            vm.identityList.value
                .single()
                .held,
        )
        val cert = keptIdentities().single().cert
        // A renewal through a mailbox tried before, and no holder there: what this one clears.
        outside { identities.renewTried(fingerprint, cert, 1_000, noHolder = true) }
        vm.renewHeld(fingerprint, stores.keys.authorizer { false })
        settle()
        assertEquals(Renewing.Idle, vm.renewing.value)
        assertEquals(emptyList<Any>(), setups.renewals)
        vm.renewHeld(fingerprint, stores.keys.authorizer())
        settle()
        assertEquals(Renewing.Done(fingerprint), vm.renewing.value)
        assertArrayEquals("the certificate it renews", cert, setups.renewals.single().second)
        val renewed = keptIdentities().single()
        assertEquals("no renewal tried since", 0L, renewed.renewTried)
        assertFalse(renewed.noHolder)
        assertTrue(
            "still held",
            vm.identityList.value
                .single()
                .held,
        )
    }

    @Test
    fun aPassphraseBackupIsSavedAndRemovedBehindThePrompt() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.backUpPassphrase(fingerprint, "  ", stores.keys.authorizer())
        settle()
        assertEquals(BackingUp.Failed(SetupProblem.BadPassphrase), vm.backingUp.value)
        vm.backUpPassphrase(fingerprint, "correct horse", stores.keys.authorizer { false })
        settle()
        assertEquals("as it was before the prompt", BackingUp.Failed(SetupProblem.BadPassphrase), vm.backingUp.value)
        assertEquals(emptyList<Any>(), setups.backups)
        vm.backUpPassphrase(fingerprint, "correct horse", stores.keys.authorizer())
        settle()
        assertEquals(BackingUp.Done(Backed.PassphraseSaved), vm.backingUp.value)
        vm.removePassphraseBackup(fingerprint, stores.keys.authorizer())
        settle()
        assertEquals(BackingUp.Done(Backed.PassphraseRemoved), vm.backingUp.value)
        assertEquals(
            listOf("passphrase correct horse" to "reg.example", "delete PASSPHRASE" to "reg.example"),
            setups.backups,
        )
    }

    @Test
    fun aNewRecoveryCodeIsSavedOnceTypedBackBehindThePrompt() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.newRecoveryCode()
        val made = setups.newCodes.single()
        assertEquals(BackingUp.Recovery(made.code), vm.backingUp.value)
        vm.newRecoveryCodeWritten()
        vm.confirmNewRecoveryCode(fingerprint, bytes("NEWRC-0DE00-00000-00003"), stores.keys.authorizer())
        assertEquals(BackingUp.ConfirmRecovery(true), vm.backingUp.value)
        val typed = bytes(made.code)
        vm.confirmNewRecoveryCode(fingerprint, typed, stores.keys.authorizer())
        settle()
        assertEquals(BackingUp.Done(Backed.RecoveryCodeSaved), vm.backingUp.value)
        assertEquals(listOf("recovery" to "reg.example"), setups.backups)
        assertTrue("let go of", made.closed)
        assertTrue("typed bytes wiped", typed.all { it == 0.toByte() })
        assertTrue("every code handed out wiped", setups.codes.all { code -> code.all { it == 0.toByte() } })
    }

    @Test
    fun aBackupOfAHeldIdentityWhoseKeyWentLetsItGoWithItsNotice() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        stores.keys.invalidate(stores.keys.aliases.single())
        vm.backUpPassphrase(fingerprint, "correct horse", stores.keys.authorizer())
        settle()
        assertEquals(BackingUp.Failed(SetupProblem.KeyLost), vm.backingUp.value)
        assertEquals(listOf(fingerprint), vm.heldLostNotices.value)
        assertEquals(emptyList<Any>(), setups.backups)
    }

    @Test
    fun anUnfinishedSetupRenewedIsStillToBeFinished() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        setup.answers += CoreException.Connect("unreachable")
        vm.holdSetup(stores.keys.authorizer())
        settle()
        vm.renewHeld(setup.fingerprint(), stores.keys.authorizer())
        settle()
        assertEquals(Renewing.Done(setup.fingerprint()), vm.renewing.value)
        assertTrue("still to be finished", keptIdentities().single().unfinished)
    }

    @Test
    fun aPassphraseTooShortIsRefusedBeforeTheKeyIsAskedFor() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        var asked = false
        vm.backUpPassphrase(fingerprint, "nine char", stores.keys.authorizer { true.also { asked = true } })
        settle()
        assertEquals(BackingUp.Failed(SetupProblem.BadPassphrase), vm.backingUp.value)
        assertFalse("the key not asked for", asked)
    }

    @Test
    fun aNewRecoveryCodeNotSavedIsSaidToMaybeBeInEffectAndTriedAgain() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.newRecoveryCode()
        val made = setups.newCodes.single()
        vm.newRecoveryCodeWritten()
        setups.backupFails = CoreException.Connect("unreachable")
        vm.confirmNewRecoveryCode(fingerprint, bytes(made.code), stores.keys.authorizer())
        settle()
        assertEquals(BackingUp.RecoveryNotSaved(SetupProblem.Unreachable), vm.backingUp.value)
        vm.retryNewRecoveryCode(fingerprint, stores.keys.authorizer())
        settle()
        assertEquals(BackingUp.Done(Backed.RecoveryCodeSaved), vm.backingUp.value)
        assertEquals(listOf("recovery" to "reg.example"), setups.backups)
    }

    @Test
    fun aHeldDeviceAServerRevokedIsReplacedByANewOneAndNotRenewed() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val old = keptIdentities().single()
        val server = Server("wss://a.example/ng", "", SignIn.Identity(fingerprint))
        outside { servers.markRefused(server, old.info.device, "revoked") }
        vm.newDeviceHeld(fingerprint, stores.keys.authorizer())
        settle()
        assertEquals(Renewing.Done(fingerprint), vm.renewing.value)
        assertEquals("no renewal of the device it was", emptyList<Any>(), setups.renewals)
        val now = keptIdentities().single()
        assertFalse("another device", now.info.device.contentEquals(old.info.device))
        assertEquals("pixel", "Pixel", now.info.name)
        assertEquals("its refusal let go of", emptyMap<String, String>(), outside { servers.refusals() })
    }

    @Test
    fun aHeldIdentityDeletedWhileItsNewDeviceWasAskedForStaysDeleted() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val puts = stores.secrets.puts.size
        vm.newDeviceHeld(
            fingerprint,
            stores.keys.authorizer {
                vm.deleteIdentity(fingerprint)
                true
            },
        )
        settle()
        assertEquals(Renewing.Idle, vm.renewing.value)
        assertEquals(emptyList<Any>(), keptIdentities())
        assertEquals("no device seed kept for it", puts, stores.secrets.puts.size)
    }

    @Test
    fun aSetupCommittedWhileItsNewDeviceWasAskedForStaysCommitted() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        setup.answers += CoreException.Connect("unreachable")
        vm.holdSetup(stores.keys.authorizer())
        settle()
        val fingerprint = setup.fingerprint()
        val card = keptIdentities().single().card
        vm.newDeviceHeld(
            fingerprint,
            stores.keys.authorizer {
                // The commit a retry made, landing while the prompt is up.
                outside { identities.committed(fingerprint, card, "carol2") }
                true
            },
        )
        settle()
        assertEquals(Renewing.Done(fingerprint), vm.renewing.value)
        val now = keptIdentities().single()
        assertFalse("committed, not unfinished again", now.unfinished)
        assertEquals("carol2", now.handle)
    }

    @Test
    fun anUnfinishedSetupWhoseDeviceIsReplacedIsStillToBeFinished() {
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        setup.answers += CoreException.Connect("unreachable")
        vm.holdSetup(stores.keys.authorizer())
        settle()
        vm.newDeviceHeld(setup.fingerprint(), stores.keys.authorizer())
        settle()
        assertEquals(Renewing.Done(setup.fingerprint()), vm.renewing.value)
        assertTrue("still to be finished", keptIdentities().single().unfinished)
    }

    @Test
    fun anIdentityRestoredToHoldIsShownAsHeld() {
        val identity = newIdentity("Dana")
        setups.restores = identity
        val vm = model()
        settle()
        vm.restore("reg.example", "dana", SecretKind.RECOVERY_CODE, "code", "Pixel", stores.keys.authorizer())
        settle()
        assertTrue(
            "held",
            vm.identityList.value
                .single()
                .held,
        )
    }
}
