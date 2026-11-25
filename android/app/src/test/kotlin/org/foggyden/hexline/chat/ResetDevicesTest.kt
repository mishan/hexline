package org.foggyden.hexline.chat

import androidx.work.NetworkType
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.foggyden.hexline.core.Caps
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.HeldRenewal
import org.foggyden.hexline.core.HolderRequest
import org.foggyden.hexline.core.NotYet
import org.foggyden.hexline.core.NotYetReset
import org.foggyden.hexline.core.ResetRetried
import org.foggyden.hexline.core.deviceFingerprintOf
import org.foggyden.hexline.core.holderRenew
import org.foggyden.hexline.core.shortHash
import org.foggyden.hexline.identity.Absorbing
import org.foggyden.hexline.identity.Certifying
import org.foggyden.hexline.identity.Renewing
import org.foggyden.hexline.identity.ResetRetrier
import org.foggyden.hexline.identity.Resetting
import org.foggyden.hexline.identity.Revoked
import org.foggyden.hexline.identity.SetupProblem
import org.foggyden.hexline.identity.WorkResetRetries
import org.foggyden.hexline.servers.StoreQueue
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(application = android.app.Application::class)
class ResetDevicesTest : ViewModelHarness() {
    private val tablet: HolderRequest =
        ByteArray(32) { 7 }.let { device ->
            val lm = Caps(login = true, message = true, manage = false, vouch = false)
            HolderRequest(device, deviceFingerprintOf(device), "Tablet", false, false, null, null, lm, true, 90uL * 86_400uL)
        }

    /** An identity set up and held here, as the person would; its fingerprint. */
    private fun heldHere(vm: ChatViewModel): String {
        vm.startHolderSetup("reg.example", "carol", null, "Pixel")
        settle()
        val setup = setups.made.last()
        vm.successorWritten()
        vm.confirmSuccessor("SUCCE-SSORC-ODE00".toByteArray())
        vm.recoveryWritten()
        vm.confirmRecovery(setup.recovery.toByteArray())
        vm.holdSetup(stores.keys.authorizer())
        settle()
        return setup.fingerprint()
    }

    /** A code shown at a mailbox for [fingerprint], and the session showing it. */
    private fun shown(
        vm: ChatViewModel,
        fingerprint: String,
    ): FakeSetups.FakeSession {
        vm.startCertifying(fingerprint, "mail.example")
        settle()
        return setups.sessions.last()
    }

    /** The tablet certified for [fingerprint] by code, as the person would. */
    private fun certified(
        vm: ChatViewModel,
        fingerprint: String,
    ) {
        val session = shown(vm, fingerprint)
        session.next.complete(tablet)
        settle()
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertTrue(vm.certify.value is Certifying.Approved)
    }

    private fun model2(): ChatViewModel {
        owner.clear()
        settle()
        return model().also { settle() }
    }

    private fun kept(fingerprint: String) = outside { identities.list().single { it.fingerprint == fingerprint } }

    private fun reset(
        vm: ChatViewModel,
        fingerprint: String,
    ) {
        vm.resetDevices(fingerprint, stores.keys.authorizer())
        settle()
    }

    private fun retrier() = ResetRetrier(identities, setups, StoreQueue(disk), Absorbing(identities, setups)) { now }

    /** [fingerprint]'s retry run as the work would run it, on the harness's threads. */
    private fun retry(fingerprint: String): Job = CoroutineScope(main).launch { retrier().run(fingerprint) }

    private fun retried(
        epoch: Long,
        later: List<String>,
        notDone: List<NotYetReset> = later.map { NotYetReset(it, NotYet.UNREACHABLE, null, null) },
        done: List<String> = emptyList(),
        retry: ByteArray? = later.takeIf { it.isNotEmpty() }?.let { "retry for $epoch".toByteArray() },
    ) = ResetRetried(epoch.toULong(), epoch.toULong(), done, notDone, emptyList(), retry, retry?.let { 900uL }, later, retry?.let { 900uL })

    private fun downAtReset(blob: String = "kept") {
        setups.resetNotDone = listOf(NotYetReset("other.example", NotYet.UNREACHABLE, null, null))
        setups.resetLater = listOf("other.example")
        setups.resetRetry = blob.toByteArray()
        setups.resetRetryIn = 900
    }

    private fun key(b: Int) = android.util.Base64.encodeToString(ByteArray(32) { b.toByte() }, android.util.Base64.NO_WRAP)

    /** [fingerprint]'s list written as [text], which does not read, and read so it is set aside. */
    private fun setAside(
        vm: ChatViewModel,
        fingerprint: String,
        text: String,
    ) {
        File(stores.identityDir, "minted-" + shortHash(fingerprint.toByteArray())).writeText(text)
        vm.openDevices(fingerprint)
        settle()
        assertTrue(checkNotNull(vm.devices.value).setAside)
    }

    private fun copies() =
        stores.identityDir
            .list()
            .orEmpty()
            .filter { it.contains(".unread-") }

    /** The tablet asking at a code shown for [fingerprint], judged [revoked]. */
    private fun asks(
        vm: ChatViewModel,
        fingerprint: String,
        revoked: Revoked,
    ) {
        shown(vm, fingerprint).next.complete(tablet)
        settle()
        assertEquals(Certifying.Asked(fingerprint, tablet, revoked), vm.certify.value)
        vm.cancelCertifying()
        settle()
    }

    @Test
    fun aResetLetsGoOfAListSetAsideThatAllReadsCarryingWhatItSaysAndApprovingIsUnblocked() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        // Every key reads; the device's entry, with no expiry, does not.
        setAside(
            vm,
            fingerprint,
            """{"devices":[{"device":"${key(6)}"}],"revoked":["${key(5)}"],"certified":[{"device":"${key(4)}","epoch":0}]}""",
        )
        asks(vm, fingerprint, Revoked.Unknown)
        reset(vm, fingerprint)
        assertTrue(vm.resetting.value is Resetting.Done)
        assertEquals(emptyList<String>(), copies())
        assertFalse(checkNotNull(vm.devices.value).setAside)
        assertEquals(listOf(ByteArray(32) { 5 }.toList()), outside { identities.seenRevoked(fingerprint) }.map { it.toList() })
        assertEquals(
            setOf(4, 6).map { b -> ByteArray(32) { b.toByte() }.toList() }.toSet(),
            outside { identities.everCertified(fingerprint) }.map { it.first.toList() }.toSet(),
        )
        asks(vm, fingerprint, Revoked.No)
    }

    @Test
    fun aResetKeepsAListSetAsideThatDoesNotAllReadAndItsBlock() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        setAside(vm, fingerprint, """[{"device":"${key(5)}","revoked":true},{"device":12}]""")
        reset(vm, fingerprint)
        assertTrue(vm.resetting.value is Resetting.Done)
        assertEquals("a revoked key it cannot read would go with it", 1, copies().size)
        assertTrue(checkNotNull(vm.devices.value).setAsideLoses)
        asks(vm, fingerprint, Revoked.Unknown)
    }

    @Test
    fun aDiscardOfWholeCopiesOnlyLetsNoneGoWhileACopyItHoldsDoesNotReadWhole() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        setAside(vm, fingerprint, """{"devices":[{"device":"${key(6)}"}],"revoked":["${key(5)}"]}""")
        // Set aside after any check made apart from the discard, as another reader of the list can.
        setAside(vm, fingerprint, """[{"device":"${key(4)}","revoked":true},{"device":12}]""")
        outside { identities.discardUnread(fingerprint, onlyIfWhole = true) }
        assertEquals(2, copies().size)
        File(stores.identityDir, copies().single { it.endsWith("-1") }).delete()
        outside { identities.discardUnread(fingerprint, onlyIfWhole = true) }
        assertEquals("once every copy reads whole, they go", emptyList<String>(), copies())
    }

    @Test
    fun aListSetAsideThatCannotBeCarriedAfterAResetStaysAndTheResetIsKept() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        setAside(vm, fingerprint, """{"devices":[{"device":"${key(6)}"}],"revoked":["${key(5)}"]}""")
        // Once it has posted: the disk refuses the list from then on.
        setups.onReset = { _, _, _, _ -> stores.listsFail = 100 }
        reset(vm, fingerprint)
        stores.listsFail = 0
        assertTrue("${vm.resetting.value}", vm.resetting.value is Resetting.Done)
        assertTrue(kept(fingerprint).reset!!.epoch > 0)
        assertEquals(1, copies().size)
        asks(vm, fingerprint, Revoked.Unknown)
    }

    @Test
    fun aDeviceCertifiedBeforeAResetIsHandedToTheCoreBelowTheFloorAfterARestart() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        certified(vm, fingerprint)
        reset(vm, fingerprint)
        assertTrue(vm.resetting.value is Resetting.Done)
        // A new process: the core's own floor is gone with the old one.
        setups.floor = 0
        val again = model2()
        val session = shown(again, fingerprint)
        assertEquals("the floor the reset raised", 1uL, session.kept.epoch)
        val listed = session.kept.devices.single { it.device.contentEquals(tablet.device) }
        assertEquals("below it, so the core refuses it signed_out_request", 0uL, listed.epoch)
        assertEquals(1uL, kept(fingerprint).info.epoch)
    }

    @Test
    fun aResetsOutcomeIsKeptWhateverCertificateStandsAndARenewalBelowItIsReplaced() {
        for (renewedAt in listOf(1L, 0L)) {
            fresh()
            setups = FakeSetups()
            val vm = model()
            settle()
            val fingerprint = heldHere(vm)
            val before = kept(fingerprint).cert
            downAtReset()
            var renewed: ByteArray? = null
            setups.onReset = { seed, card, device, cert ->
                // A renewal landing while the reset posts, at its epoch or below it; a second on, so
                // one below it is not the very certificate the reset began from.
                Thread.sleep(1_100)
                renewed = holderRenew(seed, card, device, cert, renewedAt.toULong(), emptyList())
                assertFalse(checkNotNull(renewed).contentEquals(before))
                outside { identities.renewed(fingerprint, checkNotNull(renewed), replacing = before) }
            }
            reset(vm, fingerprint)
            val stored = kept(fingerprint)
            if (renewedAt == 1L) {
                assertArrayEquals("one at the reset's epoch stands", renewed, stored.cert)
            } else {
                assertEquals("one below it is the reset's", 1uL, stored.info.epoch)
                assertFalse(stored.cert.contentEquals(renewed))
            }
            val reset = checkNotNull(stored.reset)
            assertEquals(1L, reset.epoch)
            assertArrayEquals("the retry kept either way", "kept".toByteArray(), reset.retry)
            assertEquals(listOf("other.example"), reset.pending)
            assertEquals(1L, outside { identities.epoch(stored) })
            assertEquals(Triple("schedule", fingerprint, 900L), retries.asked.last())
        }
    }

    @Test
    fun aRetryOutlivedByANewResetLeavesTheNewOnesRetry() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        downAtReset("first")
        reset(vm, fingerprint)
        now += 900
        setups.retryWaits = CompletableDeferred()
        setups.retryAnswers += { retried(1, listOf("other.example")) }
        var next: Long? = null
        CoroutineScope(main).launch { next = retrier().run(fingerprint) }
        settle()
        downAtReset("second")
        setups.resetRetryIn = 3600
        reset(vm, fingerprint)
        setups.retryWaits!!.complete(Unit)
        settle()
        val reset = checkNotNull(kept(fingerprint).reset)
        assertEquals(2L, reset.epoch)
        assertArrayEquals("second".toByteArray(), reset.retry)
        assertEquals("the next run when the newer retry is due", 3600L, next)
    }

    @Test
    fun theRetryPostsWhatIsKeptWhenItRunsNotWhatWasKeptWhenItWasMade() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        downAtReset("first")
        reset(vm, fingerprint)
        val retrier = retrier()
        downAtReset("second")
        reset(vm, fingerprint)
        now += 900
        setups.retryAnswers += { retried(2, emptyList(), done = listOf("other.example")) }
        CoroutineScope(main).launch { retrier.run(fingerprint) }
        settle()
        assertEquals(listOf("second"), setups.retried.map { String(it) })
        val reset = checkNotNull(kept(fingerprint).reset)
        assertEquals((null to emptyList<String>()), reset.retry to reset.pending)
    }

    @Test
    fun aWriteTheDiskWillNotTakeIsNeverToldAsDoneNorRetriedWithoutTheBackoff() {
        // Each identity write a reset makes, refused in turn.
        var write = 0
        while (true) {
            fresh()
            setups = FakeSetups()
            val vm = model()
            settle()
            val fingerprint = heldHere(vm)
            downAtReset()
            val asked = retries.asked.size
            stores.identityWriteFails = write
            reset(vm, fingerprint)
            if (stores.identityWriteFails != null) break
            val kept = kept(fingerprint).reset
            val saved = kept?.epoch == 1L && kept.retry != null && !kept.uncertain
            if (vm.resetting.value is Resetting.Done) {
                assertTrue("write $write: told done, and not kept", saved)
            } else {
                assertTrue("write $write: posted, and not offered again", setups.resets.isEmpty() || kept?.uncertain == true)
            }
            if (!saved) {
                assertTrue("write $write: retried, and not kept", retries.asked.drop(asked).none { it.first == "schedule" })
            }
            write++
        }
        assertTrue("the reset's writes all refused in turn", write >= 2)
        // Each identity write a retry makes, refused in turn.
        write = 0
        while (true) {
            fresh()
            setups = FakeSetups()
            val vm = model()
            settle()
            val fingerprint = heldHere(vm)
            downAtReset()
            reset(vm, fingerprint)
            now += 900
            setups.retryAnswers += { retried(1, listOf("other.example")) }
            stores.identityWriteFails = write
            var next: Long? = null
            CoroutineScope(main).launch { next = retrier().run(fingerprint) }
            settle()
            if (stores.identityWriteFails != null) break
            assertTrue("write $write: the next run in $next", next.let { it == null || it >= 900 })
            write++
        }
        assertTrue("the retry's writes all refused in turn", write >= 1)
    }

    @Test
    fun aRetryWhoseOutcomeIsNotKeptAsksNoRegistrarSoonerThanItAsked() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        downAtReset()
        reset(vm, fingerprint)
        now += 900
        // One registrar asks for a day, the other is due again in the backoff's first wait.
        setups.retryAnswers += { retried(1, listOf("slow.example", "other.example")).copy(retryLastIn = 86_400uL) }
        stores.identityWriteFails = 0
        var next: Long? = null
        CoroutineScope(main).launch { next = retrier().run(fingerprint) }
        settle()
        assertNull("the write refused", stores.identityWriteFails)
        assertEquals(86_400L, next)
    }

    @Test
    fun aReadThatAnswersAsAResetComesBackKeepsNoWholeRead() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val other = heldHere(vm)
        val held = CompletableDeferred<Unit>()
        setups.standingWaits = held
        vm.openDevices(fingerprint)
        settle()
        setups.standingWaits = null
        // The screen on another identity, so nothing reads this one again after the reset.
        vm.openDevices(other)
        settle()
        vm.resetDevices(fingerprint, stores.keys.authorizer())
        // Up to the reset's return, what it came to asked of the store and not yet kept.
        while (true) {
            onMain()
            if (setups.resets.isNotEmpty()) break
            onDisk()
        }
        // It answers now, its turn on the store behind what the reset came to.
        held.complete(Unit)
        settle()
        assertTrue(vm.resetting.value is Resetting.Done)
        assertNull(outside { identities.lastRead(fingerprint) })
    }

    @Test
    fun aRegistrarARetryFindsIsNoRegistrarIsKeptSoAndNotAsReset() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        downAtReset()
        reset(vm, fingerprint)
        now += 900
        setups.retryAnswers += { retried(1, emptyList(), notDone = emptyList()).copy(notRegistrars = listOf("other.example")) }
        retry(fingerprint)
        settle()
        val reset = checkNotNull(kept(fingerprint).reset)
        assertEquals(listOf("other.example"), reset.notRegistrars)
        assertEquals("only what the registrars said was done", listOf("reg.example"), reset.done)
        assertEquals(emptyList<String>(), reset.pending)
    }

    @Test
    fun thisPhonesDeviceKeySeenRevokedIsHandedToEveryCertificateTheCoreSignsForIt() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val own = kept(fingerprint).info.device
        // Seen revoked by a read in an earlier process: the core of this one has not read it.
        outside { identities.recordsRead(fingerprint, null, listOf(own)) }
        setups.resetFails = CoreException.Refused("this_device_revoked", "", null)
        reset(vm, fingerprint)
        assertTrue("the reset handed it", setups.resetRevoked.single().any { it.contentEquals(own) })
        assertEquals(Resetting.Failed(fingerprint, SetupProblem.ThisDeviceRevoked), vm.resetting.value)
        assertNull("refused before posting: nothing under way", kept(fingerprint).reset)
        vm.renewHeld(fingerprint, stores.keys.authorizer())
        settle()
        assertTrue("the renewal handed it", setups.renewRevoked.single().any { it.contentEquals(own) })
        assertEquals(Renewing.Failed(SetupProblem.RenewRevoked), vm.renewing.value)
        val held = vm.identityList.value.single { it.fingerprint == fingerprint }
        assertEquals("Renew again makes a new device", HeldRenewal.NEW_DEVICE, heldRenewal(held, emptyMap()))
    }

    @Test
    fun aResetThatLearnsThisPhonesDeviceKeyRevokedAfterPostingStaysOfferedAgain() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        setups.resetFailsAfterPosting = CoreException.Refused("revoked_while_resetting", "", null)
        reset(vm, fingerprint)
        assertEquals(Resetting.Failed(fingerprint, SetupProblem.ThisDeviceRevoked), vm.resetting.value)
        assertTrue("what was posted stands", checkNotNull(kept(fingerprint).reset).uncertain)
        assertEquals("its floor kept", 1L, kept(fingerprint).epoch)
    }

    @Test
    fun aHeldDeviceWhoseKeyIsKnownRevokedIsRenewedAsANewDeviceWhateverNoServerSaid() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val own = kept(fingerprint).info.device
        outside { identities.recordsRead(fingerprint, null, listOf(own)) }
        // Its certificate run out, and nothing saved of any server's refusal.
        now = kept(fingerprint).info.expires.toLong() + DAY
        val again = model2()
        val held = again.identityList.value.single { it.fingerprint == fingerprint }
        assertEquals(HeldRenewal.NEW_DEVICE, heldRenewal(held, emptyMap()))
    }

    @Test
    fun aReadOfTheDevicesThatFindsThisPhonesKeyRevokedIsRenewedAsANewDeviceAtOnce() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        setups.revokedElsewhere(kept(fingerprint).card, kept(fingerprint).info.device)
        vm.openDevices(fingerprint)
        settle()
        val held = vm.identityList.value.single { it.fingerprint == fingerprint }
        assertEquals(HeldRenewal.NEW_DEVICE, heldRenewal(held, emptyMap()))
    }

    @Test
    fun aRetryIsMadeOnlyWithANetwork() {
        val request = WorkResetRetries.request("fp", 900)
        assertEquals(NetworkType.CONNECTED, request.workSpec.constraints.requiredNetworkType)
        assertEquals(900_000L, request.workSpec.initialDelay)
    }

    @Test
    fun aWholeReadFromBeforeAResetWaivesNothingWhileItsOutcomeIsUnknown() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        settle()
        assertNotNull(outside { identities.lastRead(fingerprint) })
        setups.resetWaits = CompletableDeferred()
        vm.resetDevices(fingerprint, stores.keys.authorizer())
        settle()
        // A read landing while it is under way keeps no whole read either.
        vm.openDevices(fingerprint)
        settle()
        assertNull(outside { identities.lastRead(fingerprint) })
        // The process gone mid-reset, in the same boot.
        val again = model2()
        assertNull(shown(again, fingerprint).kept.read)
        assertTrue(checkNotNull(kept(fingerprint).reset).uncertain)
    }

    @Test
    fun aRetryForAnIdentityDeletedMeanwhileWritesNothingBackAndItsWorkIsCanceled() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        downAtReset()
        reset(vm, fingerprint)
        now += 900
        setups.retryWaits = CompletableDeferred()
        setups.retryAnswers += { retried(1, listOf("other.example")) }
        retry(fingerprint)
        settle()
        vm.deleteIdentity(fingerprint)
        settle()
        assertEquals(Triple("cancel", fingerprint, 0L), retries.asked.last())
        setups.retryWaits!!.complete(Unit)
        settle()
        val name = shortHash(fingerprint.toByteArray())
        assertEquals(
            emptyList<String>(),
            stores.identityDir
                .list()
                .orEmpty()
                .filter { name in it },
        )
    }

    @Test
    fun anIdentityHeldAgainWhileARetryIsAskedForIsPostedNothingOfTheOld() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        downAtReset()
        reset(vm, fingerprint)
        val retrier = retrier()
        val stored = kept(fingerprint)
        val seed = outside { checkNotNull(identities.device(fingerprint)).second }
        vm.deleteIdentity(fingerprint)
        settle()
        outside { identities.save(seed, stored.cert, stored.card, "carol", "reg.example") }
        now += 900
        var next: Long? = -1
        CoroutineScope(main).launch { next = retrier.run(fingerprint) }
        settle()
        assertEquals(emptyList<ByteArray>(), setups.retried)
        assertNull("none asked for after it", next)
    }

    @Test
    fun aRetryCanceledAsItWritesStillKeepsWhatItCameToAndWhatItRead() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        downAtReset()
        reset(vm, fingerprint)
        now += 900
        setups.retryAnswers += {
            // What the retry's reads verified: a floor past the reset, by another holder.
            setups.floor = 5
            retried(1, emptyList(), done = listOf("other.example"))
        }
        val job = retry(fingerprint)
        // Up to the write it asks of the store, and canceled before the store makes it.
        onMain()
        onDisk()
        onMain()
        job.cancel()
        settle()
        val stored = kept(fingerprint)
        assertEquals(emptyList<String>(), stored.reset?.pending)
        assertEquals(5L, stored.epoch)
    }

    @Test
    fun aRegistrarGivenUpOnIsStillShownAsNotResetAfterARestart() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        downAtReset()
        reset(vm, fingerprint)
        now += 900
        setups.retryAnswers += {
            retried(1, emptyList(), notDone = listOf(NotYetReset("other.example", NotYet.GAVE_UP, null, null)))
        }
        retry(fingerprint)
        settle()
        val again = model2()
        again.openDevices(fingerprint)
        settle()
        val reset = checkNotNull(again.devices.value?.reset)
        assertEquals(emptyList<String>(), reset.pending)
        assertEquals(listOf("other.example"), reset.givenUp)
        assertNull(reset.retry)
    }

    @Test
    fun aResetCutShortAfterPostingOffersAnotherWhichARefusalBeforePostingDoesNotTakeBack() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        setups.resetFails = CoreException.Refused("busy", "", null)
        reset(vm, fingerprint)
        assertEquals(Resetting.Failed(fingerprint, SetupProblem.ResetUnderWay), vm.resetting.value)
        assertNull("refused before posting: nothing under way", kept(fingerprint).reset)
        setups.resetFailsAfterPosting = CoreException.Protocol("the reset stopped")
        reset(vm, fingerprint)
        assertTrue(vm.resetting.value is Resetting.Failed)
        val cut = checkNotNull(kept(fingerprint).reset?.underWay) { "may have posted" }
        assertEquals("its floor kept all the same", 1L, kept(fingerprint).epoch)
        now += 60
        for (refusal in listOf("no_registrar_reached", "busy")) {
            setups.resetFails = CoreException.Refused(refusal, "", null)
            reset(vm, fingerprint)
            assertEquals("the reset cut short still may have posted", cut, kept(fingerprint).reset?.underWay)
        }
        assertEquals(Resetting.Failed(fingerprint, SetupProblem.ResetUnderWay), vm.resetting.value)
    }

    @Test
    fun aResetUnderWayThatDoesNotReadStillKeepsAWholeReadFromStandingIn() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        owner.clear()
        settle()
        val file = File(stores.identityDir, "identity-" + shortHash(fingerprint.toByteArray()))
        outside {
            val json = JSONObject(String(file.readBytes()))
            json.put("reset", JSONObject().put("under_way", "not a time"))
            org.foggyden.hexline.identity
                .writeAtomically(file, json.toString().toByteArray())
        }
        val again = model().also { settle() }
        assertTrue(checkNotNull(kept(fingerprint).reset).uncertain)
        again.openDevices(fingerprint)
        settle()
        assertNull(outside { identities.lastRead(fingerprint) })
    }

    @Test
    fun aReadBegunBeforeAResetKeepsNoWholeReadWhenItAnswersAfter() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val other = heldHere(vm)
        val held = CompletableDeferred<Unit>()
        setups.standingWaits = held
        vm.openDevices(fingerprint)
        settle()
        setups.standingWaits = null
        // The screen on another identity, so nothing reads this one again after the reset.
        vm.openDevices(other)
        settle()
        reset(vm, fingerprint)
        held.complete(Unit)
        settle()
        assertNull(outside { identities.lastRead(fingerprint) })
    }

    @Test
    fun aKeptRetryThatDoesNotReadIsShownAsAResetThatMayNotHaveFinished() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        downAtReset()
        reset(vm, fingerprint)
        owner.clear()
        settle()
        val file = File(stores.identityDir, "identity-" + shortHash(fingerprint.toByteArray()))
        outside {
            val json = JSONObject(String(file.readBytes()))
            json.getJSONObject("reset").put("retry", 5)
            org.foggyden.hexline.identity
                .writeAtomically(file, json.toString().toByteArray())
        }
        val again = model().also { settle() }
        again.openDevices(fingerprint)
        settle()
        val reset = checkNotNull(again.devices.value?.reset)
        assertTrue(reset.uncertain)
        assertNull(reset.retry)
        assertEquals("the rest still read", listOf("other.example"), reset.pending)
    }

    @Test
    fun offlineAfterAResetADeviceCertifiedBeforeItShowsSignedOut() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        certified(vm, fingerprint)
        vm.cancelCertifying()
        setups.standingFails = CoreException.Connect("offline")
        reset(vm, fingerprint)
        vm.openDevices(fingerprint)
        settle()
        val list = checkNotNull(vm.devices.value)
        val device = list.devices.single { it.device.contentEquals(tablet.device) }
        assertTrue(list.signedOut(device))
        assertFalse("known to be signed out, so not unchecked", list.unchecked)
        val own = list.devices.single { it.own }
        assertFalse("this phone certified again past it", list.signedOut(own))
        assertEquals(1uL, kept(fingerprint).info.epoch)
    }
}
