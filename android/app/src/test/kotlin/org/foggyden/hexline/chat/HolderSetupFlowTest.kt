package org.foggyden.hexline.chat

import androidx.lifecycle.ViewModelStore
import kotlinx.coroutines.CompletableDeferred
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.NewIdentity
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.newIdentity
import org.foggyden.hexline.identity.Backed
import org.foggyden.hexline.identity.BackingUp
import org.foggyden.hexline.identity.HolderRefusal
import org.foggyden.hexline.identity.Identities
import org.foggyden.hexline.identity.Renewing
import org.foggyden.hexline.identity.Resetting
import org.foggyden.hexline.identity.RestoreOffer
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
import org.junit.Assert.assertNull
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
        setups.checkFails = CoreException.Refused("no_envelopes", "", null)
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
        setup.answers += CoreException.Refused("handle_taken", "", null)
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
        setup.answers += CoreException.Refused("registered_not_backed_up", "", null)
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
    fun whatARestoreReadOfTheRecordsIsKeptWithTheIdentity() {
        val identity = newIdentity("Dana")
        setups.restores = identity
        val lost = ByteArray(32) { 7 }
        setups.verified(identity.card, lost)
        val vm = model()
        settle()
        vm.restore("reg.example", "dana", SecretKind.RECOVERY_CODE, "code", "Pixel", stores.keys.authorizer())
        settle()
        assertEquals(listOf(lost.toList()), outside { identities.seenRevoked(identity.fingerprint) }.map { it.toList() })
    }

    @Test
    fun aReadOfTheRecordsBegunBeforeItsIdentityWasDeletedWritesNothingIntoTheOneHeldAgain() {
        val identity = newIdentity("Dana")
        setups.restores = identity
        val vm = model()
        settle()
        vm.restore("reg.example", "dana", SecretKind.RECOVERY_CODE, "code", "Pixel", stores.keys.authorizer())
        settle()
        val held = CompletableDeferred<Unit>()
        setups.standingWaits = held
        vm.openDevices(identity.fingerprint)
        settle()
        vm.deleteIdentity(identity.fingerprint)
        settle()
        vm.restore("reg.example", "dana", SecretKind.RECOVERY_CODE, "code", "Pixel", stores.keys.authorizer())
        settle()
        setups.standingWaits = null
        held.complete(Unit)
        settle()
        assertNull("no read of this lifetime stands in", outside { identities.lastRead(identity.fingerprint) })
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

    /** [identity] restored to hold here, [lost] as the person said; its offer as the Devices screen is given it. */
    private fun restoredToHold(
        vm: ChatViewModel,
        identity: NewIdentity,
        lost: Boolean,
        authorizer: org.foggyden.hexline.secrets.Authorizer = stores.keys.authorizer(),
    ): RestoreOffer? {
        setups.restores = identity
        vm.restore("reg.example", "dana", SecretKind.RECOVERY_CODE, "code", "Pixel", authorizer, lost)
        settle()
        return offered(vm, identity.fingerprint)
    }

    private fun offered(
        vm: ChatViewModel,
        fingerprint: String,
    ): RestoreOffer? {
        vm.openDevices(fingerprint)
        settle()
        return checkNotNull(vm.devices.value).restored
    }

    @Test
    fun aRestoresOfferIsKeptInItsOwnSaveAcrossARestartAndAnsweredOnlyByAResetsKeptOutcome() {
        val identity = newIdentity("Dana")
        val vm = model()
        settle()
        // Every identity write after the save fails: an offer written apart from it would be lost.
        stores.identityWriteFails = 1
        assertEquals(RestoreOffer(lost = true), restoredToHold(vm, identity, lost = true))
        stores.identityWriteFails = null
        owner.clear()
        settle()
        val again = model().also { settle() }
        assertEquals("after a restart", RestoreOffer(lost = true), offered(again, identity.fingerprint))
        setups.resetFails = CoreException.Refused("no_registrar_reached", "", null)
        again.resetDevices(identity.fingerprint, stores.keys.authorizer())
        settle()
        assertEquals("refused before posting", RestoreOffer(lost = true), offered(again, identity.fingerprint))
        again.resetDevices(identity.fingerprint, stores.keys.authorizer())
        settle()
        assertTrue(again.resetting.value is Resetting.Done)
        assertNull(offered(again, identity.fingerprint))
        assertNull(keptIdentities().single().restored)
    }

    @Test
    fun aRestoresOfferDeclinedIsGoneAndOneOfAPhoneNotLostIsKeptAsSuch() {
        val identity = newIdentity("Dana")
        val vm = model()
        settle()
        assertEquals(RestoreOffer(lost = false), restoredToHold(vm, identity, lost = false))
        vm.declineRestoreReset(identity.fingerprint)
        settle()
        assertNull(offered(vm, identity.fingerprint))
        assertEquals("nothing reset", emptyList<Long>(), setups.resets)
    }

    @Test
    fun aRestoreWhoseHoldWasRefusedLeavesNoOffer() {
        val identity = newIdentity("Dana")
        val vm = model()
        settle()
        assertNull(restoredToHold(vm, identity, lost = true, stores.keys.authorizer { false }))
        assertEquals(Restoring.NotHeld(identity.fingerprint), vm.restore.value)
        assertNull("none on disk either", keptIdentities().single().restored)
    }

    @Test
    fun aRefusedHoldOnARestoreOfAnIdentityStillHeldKeepsItsOffer() {
        val identity = newIdentity("Dana")
        val vm = model()
        settle()
        restoredToHold(vm, identity, lost = true)
        vm.restoreSeen()
        restoredToHold(vm, identity, lost = true, stores.keys.authorizer { false })
        assertEquals(Restoring.NotHeld(identity.fingerprint), vm.restore.value)
        assertTrue("the key held before is still held", stores.held.isHeld(identity.fingerprint))
        assertEquals(RestoreOffer(lost = true), offered(vm, identity.fingerprint))
    }

    @Test
    fun noOfferIsShownForAnIdentityWhoseOwnDeviceKeyIsKnownRevoked() {
        val identity = newIdentity("Dana")
        val vm = model()
        settle()
        assertEquals(RestoreOffer(lost = true), restoredToHold(vm, identity, lost = true))
        setups.verified(identity.card, keptIdentities().single().info.device)
        assertNull("every reset would be refused this_device_revoked", offered(vm, identity.fingerprint))
    }

    @Test
    fun anOfferStandsThroughANewDeviceAndASecondRestoreOfAPhoneNotLost() {
        val identity = newIdentity("Dana")
        val vm = model()
        settle()
        restoredToHold(vm, identity, lost = true)
        vm.newDeviceHeld(identity.fingerprint, stores.keys.authorizer())
        settle()
        assertEquals(Renewing.Done(identity.fingerprint), vm.renewing.value)
        assertEquals("through the new device's save", RestoreOffer(lost = true), offered(vm, identity.fingerprint))
        vm.restoreSeen()
        assertEquals("a second restore does not make it less urgent", RestoreOffer(lost = true), restoredToHold(vm, identity, lost = false))
    }

    @Test
    fun aRestoredFieldThatDoesNotReadIsOfferedAsAfterALostPhone() {
        val identity = newIdentity("Dana")
        val vm = model()
        settle()
        restoredToHold(vm, identity, lost = false)
        val file =
            stores.identityDir
                .listFiles()
                .orEmpty()
                .single { it.name.startsWith("identity-") && !it.name.contains('.') }
        file.writeText(
            org.json
                .JSONObject(file.readText())
                .put("restored", "garbled")
                .toString(),
        )
        assertEquals(RestoreOffer(lost = true), offered(vm, identity.fingerprint))
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
        resumed.answers += CoreException.Refused("handle_taken", "", null)
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
    fun aHeldIdentitysDeviceIsRenewedInTheEpochKeptWhichOutlivesTheProcess() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        outside { identities.learned(fingerprint, 3) }
        vm.renewHeld(fingerprint, stores.keys.authorizer())
        settle()
        assertEquals(Renewing.Done(fingerprint), vm.renewing.value)
        assertEquals("renewed in it", 3uL, keptIdentities().single().info.epoch)
        val started = Identities(app, secrets, stores.identityDir)
        assertEquals("read again from the disk", 3L, outside { started.list().single().epoch })
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
        setups.nextIdentity = NewIdentity(CAROL_SEED, CAROL_CARD, CAROL)
        val vm = model()
        settle()
        val setup = throughTheCodes(vm)
        setup.answers += CoreException.Connect("unreachable")
        vm.holdSetup(stores.keys.authorizer())
        settle()
        val fingerprint = setup.fingerprint()
        vm.newDeviceHeld(
            fingerprint,
            stores.keys.authorizer {
                // The commit a retry made, landing while the prompt is up, with the card the registrar gave back.
                outside { identities.committed(fingerprint, CAROL_COMMITTED, "carol2") }
                true
            },
        )
        settle()
        assertEquals(Renewing.Done(fingerprint), vm.renewing.value)
        val now = keptIdentities().single()
        assertFalse("committed, not unfinished again", now.unfinished)
        assertEquals("carol2", now.handle)
        assertArrayEquals("the committed card", CAROL_COMMITTED, now.card)
    }

    private companion object {
        // An identity and two cards of it, a commit's the later, made with hl-identity.
        val CAROL_SEED = hex("0303030303030303030303030303030303030303030303030303030303030303")
        const val CAROL = "prq8czx2ycxfwrpnttrp8bgp47am6c3r8tsaayw9fsrgj6dqcw4g"
        val CAROL_CARD =
            hex(
                "a56176016373696758403ffc78c9c8e4fdb6a5af71d3ff062f5f506f9ca4b07e4b3d070d394200b59bcba28cf38a6a3f239a3bf1337f11e2ef35eb748ba808a797fac17e0e63f0c5cb09646e616d65654361726f6c67757064617465641a6b49d200686964656e746974795820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
            )
        val CAROL_COMMITTED =
            hex(
                "a5617601637369675840382b67d240417ae6a60bbc51bbba90d1ff501f0738c33e137406c1afa6ad55648e7627d49e3ec6adf348b3c09e070231ddbc63de0490a8af7a8132ff1fb7ac03646e616d65654361726f6c67757064617465641a6b49d264686964656e746974795820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
            )
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
