package org.foggyden.hexline.chat

import kotlinx.coroutines.CompletableDeferred
import org.foggyden.hexline.core.Caps
import org.foggyden.hexline.core.CertifyEnd
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.HolderRequest
import org.foggyden.hexline.core.RevokeReason
import org.foggyden.hexline.core.deviceFingerprintOf
import org.foggyden.hexline.core.shortHash
import org.foggyden.hexline.identity.Certifying
import org.foggyden.hexline.identity.DeviceList
import org.foggyden.hexline.identity.MintedDevice
import org.foggyden.hexline.identity.Revoked
import org.foggyden.hexline.identity.Revoking
import org.foggyden.hexline.identity.SetupProblem
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(application = android.app.Application::class)
class CertifyFlowTest : ViewModelHarness() {
    /** What the fake session's device asks, as the core would show it. */
    private fun asking(name: String = "Tablet"): HolderRequest {
        val device = ByteArray(32) { 7 }
        val lm = Caps(login = true, message = true, manage = false, vouch = false)
        return HolderRequest(device, deviceFingerprintOf(device), name, false, false, null, null, lm, true, 90uL * 86_400uL)
    }

    private val tablet = asking()

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
        val session = setups.sessions.last()
        assertEquals(Certifying.Showing(fingerprint, "3f2a8c1d", "K7PM-QX2D", "mail.example", 600, null), vm.certify.value)
        return session
    }

    private fun asked(
        vm: ChatViewModel,
        fingerprint: String,
        session: FakeSetups.FakeSession,
        revoked: Revoked = Revoked.No,
    ) {
        session.next.complete(tablet)
        settle()
        assertEquals(Certifying.Asked(fingerprint, tablet, revoked), vm.certify.value)
    }

    /** [fingerprint]'s device certified by code, as the person would. */
    private fun certified(
        vm: ChatViewModel,
        fingerprint: String,
    ): FakeSetups.FakeSession {
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        return session
    }

    private fun devices(vm: ChatViewModel) = checkNotNull(vm.devices.value).devices

    private fun own(vm: ChatViewModel) = devices(vm).single { it.own }

    private fun onDisk(fingerprint: String) = outside { identities.minted(fingerprint) }

    private fun minted(fingerprint: String) = File(stores.identityDir, "minted-" + shortHash(fingerprint.toByteArray()))

    private fun revoked(device: MintedDevice) =
        MintedDevice(device.device, device.fingerprint, device.name, device.expires, device.canManage, revoked = true)

    @Test
    fun aDeviceAskingByTheCodeShownIsCertifiedBehindThePromptListedThenSent() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        settle()
        assertEquals("this phone's own device alone", 1, devices(vm).size)
        val session = shown(vm, fingerprint)
        assertArrayEquals("for the identity's card", stored()!!.card, session.card)
        asked(vm, fingerprint, session)
        vm.approveDevice(fingerprint, manage = true, stores.keys.authorizer { false })
        settle()
        assertEquals("a prompt refused leaves it asked", Certifying.Asked(fingerprint, tablet), vm.certify.value)
        assertEquals(emptyList<Any>(), session.approvals)
        val certified = MintedDevice(session.device, tablet.fingerprint, "Tablet", session.expires.toLong(), canManage = true)
        session.onDeliver = { assertEquals("listed before it is sent", listOf(certified), onDisk(fingerprint)) }
        vm.approveDevice(fingerprint, manage = true, stores.keys.authorizer())
        settle()
        assertEquals(Certifying.Approved(fingerprint, certified), vm.certify.value)
        assertTrue(session.delivered)
        val (seed, manage) = session.approvals.single()
        assertTrue(manage)
        assertTrue("the identity's seed wiped", seed.all { it == 0.toByte() })
        assertTrue("given back", session.canceled && session.closed)
        assertEquals(listOf(own(vm), certified), devices(vm))
        // Kept: a model made again lists it.
        val again = model2()
        again.openDevices(fingerprint)
        settle()
        assertEquals(vm.devices.value, again.devices.value)
    }

    /** Another model on the same stores, as a process started again would make. */
    private fun model2(): ChatViewModel {
        owner.clear()
        settle()
        return model().also { settle() }
    }

    @Test
    fun aDeviceSaidNoToIsToldSoAndNotListed() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        vm.denyDevice(fingerprint)
        settle()
        assertEquals(Certifying.Denied(fingerprint), vm.certify.value)
        assertEquals(1, session.denials.size)
        assertTrue(session.canceled && session.closed)
        assertEquals(listOf(own(vm)), devices(vm))
    }

    @Test
    fun aWaitTheMailboxEndsSaysWhyAndANewCodeIsAnotherSession() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        for ((code, why) in listOf(
            "expired" to CertifyEnd.EXPIRED,
            "used" to CertifyEnd.EXPIRED,
            "unpaired_request" to CertifyEnd.UNPAIRED,
            "stale_request" to CertifyEnd.STALE,
            "unreadable_request" to CertifyEnd.UNREADABLE,
            "no_login_request" to CertifyEnd.NO_LOGIN,
        )) {
            val session = shown(vm, fingerprint)
            session.next.completeExceptionally(CoreException.Refused(code, ""))
            settle()
            assertEquals(code, Certifying.Ended(fingerprint, why), vm.certify.value)
            assertTrue("$code: let go of", session.closed)
        }
        setups.openFails = CoreException.Refused("no_mailbox", "")
        vm.startCertifying(fingerprint, "chat.example")
        settle()
        assertEquals(Certifying.Ended(fingerprint, CertifyEnd.NO_MAILBOX), vm.certify.value)
        setups.openFails = CoreException.Connect("down")
        vm.startCertifying(fingerprint, "chat.example")
        settle()
        assertEquals(Certifying.Failed(fingerprint, SetupProblem.Unreachable), vm.certify.value)
        vm.certifySeen()
        assertEquals(Certifying.Idle, vm.certify.value)
    }

    @Test
    fun aCodeCanceledAdmitsNobodyEvenOneStillOpeningAsItWas() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val first = shown(vm, fingerprint)
        vm.cancelCertifying()
        settle()
        assertEquals(Certifying.Idle, vm.certify.value)
        assertTrue("given back", first.canceled && first.closed)
        val opening = CompletableDeferred<Unit>()
        setups.opening = opening
        vm.startCertifying(fingerprint, "mail.example")
        settle()
        vm.cancelCertifying()
        opening.complete(Unit)
        settle()
        val second = setups.sessions.last()
        assertNotSame("a second session opened", first, second)
        assertTrue("let go of as it arrived", second.canceled && second.closed)
        assertEquals(Certifying.Idle, vm.certify.value)
    }

    @Test
    fun aDeviceCertifiedHereIsRevokedForItsReasonBehindThePromptAndThisPhonesOwnIsNot() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        val session = certified(vm, fingerprint)
        val tablet = devices(vm).single { !it.own }
        vm.revokeDevice(fingerprint, tablet, RevokeReason.STOLEN, stores.keys.authorizer { false })
        settle()
        assertEquals(Revoking.Idle, vm.revoking.value)
        assertEquals(emptyList<Any>(), setups.revocations)
        vm.revokeDevice(fingerprint, tablet, RevokeReason.STOLEN, stores.keys.authorizer())
        settle()
        assertEquals(Revoking.Done(fingerprint, tablet), vm.revoking.value)
        val revocation = setups.revocations.single()
        assertEquals("reg.example", revocation.registrar)
        assertArrayEquals(session.device, revocation.device)
        assertEquals(RevokeReason.STOLEN, revocation.reason)
        // The core makes it last at least as long as a renewal elsewhere could.
        assertEquals("the latest expiry known here", tablet.expires, revocation.until)
        assertTrue("the identity's seed wiped", revocation.seed.all { it == 0.toByte() })
        assertEquals(listOf(own(vm), revoked(tablet)), devices(vm))
        vm.revokingSeen()
        vm.revokeDevice(fingerprint, own(vm), RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(Revoking.Failed(fingerprint, SetupProblem.OwnDevice), vm.revoking.value)
        assertEquals(1, setups.revocations.size)
    }

    @Test
    fun anIdentityDeletedTakesItsListsOfDevicesWithIt() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        certified(vm, fingerprint)
        File(stores.identityDir, minted(fingerprint).name + ".unread-0").writeText("kept aside")
        assertFalse(onDisk(fingerprint).isEmpty())
        vm.deleteIdentity(fingerprint)
        settle()
        assertEquals(
            emptyList<String>(),
            stores.identityDir
                .list()
                .orEmpty()
                .filter { it.startsWith("minted-") },
        )
    }

    @Test
    fun aCodeShownForOneIdentityIsPutAwayWhenAnothersDevicesAreOpenedAndAnsweredForNoOther() {
        val vm = model()
        settle()
        val other = heldHere(vm)
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        vm.approveDevice(other, manage = false, stores.keys.authorizer())
        vm.denyDevice(other)
        settle()
        assertEquals("answered for no other", Certifying.Asked(fingerprint, tablet), vm.certify.value)
        vm.openDevices(fingerprint)
        settle()
        assertFalse("its own devices leave it shown", session.closed)
        vm.openDevices(other)
        assertNull("no list until the other's is read", vm.devices.value)
        settle()
        assertEquals(other, vm.devices.value?.identity)
        assertEquals(Certifying.Idle, vm.certify.value)
        assertTrue("given back", session.canceled && session.closed)
        assertEquals(emptyList<Any>(), session.approvals)
    }

    @Test
    fun aDeviceRevokedHereThatAsksAgainIsShownRevokedAndNotApproved() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        val again = shown(vm, fingerprint)
        asked(vm, fingerprint, again, Revoked.Yes)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(emptyList<Any>(), again.approvals)
    }

    @Test
    fun aDeviceRevokedWhileItAsksIsNotApproved() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        val again = shown(vm, fingerprint)
        asked(vm, fingerprint, again)
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals("shown revoked once it is", Certifying.Asked(fingerprint, tablet, Revoked.Yes), vm.certify.value)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(Certifying.Asked(fingerprint, tablet, Revoked.Yes), vm.certify.value)
        assertEquals(emptyList<Any>(), again.approvals)
    }

    @Test
    fun aListOfDevicesThatDoesNotReadIsKeptAsideAndBlocksApprovalUntilDiscarded() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val list = minted(fingerprint)
        for (n in 0..1) {
            list.writeText("not a list $n")
            vm.openDevices(fingerprint)
            settle()
            assertTrue(checkNotNull(vm.devices.value).setAside)
        }
        for (n in 0..1) {
            assertEquals("kept aside, the first too", "not a list $n", File(stores.identityDir, list.name + ".unread-$n").readText())
        }
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Unknown)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals("not while it cannot tell", emptyList<Any>(), session.approvals)
        vm.discardUnreadable(fingerprint)
        settle()
        assertFalse(checkNotNull(vm.devices.value).setAside)
        assertEquals(
            emptyList<String>(),
            stores.identityDir
                .list()
                .orEmpty()
                .filter { it.contains(".unread-") },
        )
        assertEquals(Certifying.Asked(fingerprint, tablet), vm.certify.value)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(listOf(tablet.fingerprint), onDisk(fingerprint).map { it.fingerprint })
    }

    @Test
    fun aListOfDevicesTheDiskWillNotOpenIsToldAsUnreadAndThrowsAtNothing() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val list = minted(fingerprint)
        list.writeText("[]")
        list.setReadable(false)
        try {
            assertFalse("a file's permissions hold, as they do not for root", list.canRead())
            vm.openDevices(fingerprint)
            settle()
            assertEquals("not opened, and nothing set aside", DeviceList(fingerprint, listOf(own(vm)), unreadable = true), vm.devices.value)
            val session = shown(vm, fingerprint)
            asked(vm, fingerprint, session, Revoked.Unknown)
            vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
            settle()
            assertEquals(emptyList<Any>(), session.approvals)
        } finally {
            list.setReadable(true)
        }
        // Read again once it opens, it blocks nothing.
        vm.openDevices(fingerprint)
        settle()
        assertEquals(DeviceList(fingerprint, listOf(own(vm))), vm.devices.value)
        assertEquals(Certifying.Asked(fingerprint, tablet), vm.certify.value)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertTrue(setups.sessions.last().delivered)
    }

    /** [work] with the identities' directory refusing writes, as a full disk would. */
    private fun <T> unwritable(work: () -> T): T {
        val dir = stores.identityDir
        dir.setWritable(false)
        try {
            assertFalse("a directory's permissions hold, as they do not for root", dir.canWrite())
            return work()
        } finally {
            dir.setWritable(true)
        }
    }

    @Test
    fun aDeviceThisPhoneCannotListIsNotSent() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        settle()
        val session = unwritable { certified(vm, fingerprint) }
        assertEquals(Certifying.Failed(fingerprint, SetupProblem.NotKept), vm.certify.value)
        assertFalse("nothing left the phone", session.delivered)
        assertTrue(session.canceled && session.closed)
        vm.openDevices(fingerprint)
        settle()
        assertEquals("nor is it listed later", listOf(own(vm)), devices(vm))
        assertEquals(emptyList<MintedDevice>(), onDisk(fingerprint))
    }

    @Test
    fun aRevocationTheDiskWillNotMarkIsMarkedFromMemoryAndWrittenLater() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        val dir = stores.identityDir
        // The mark that it is being revoked made, the disk refuses the one that it is.
        setups.onRevoke = { dir.setWritable(false) }
        try {
            vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
            settle()
        } finally {
            dir.setWritable(true)
        }
        assertEquals(Revoking.Done(fingerprint, device), vm.revoking.value)
        assertEquals(listOf(own(vm), revoked(device)), devices(vm))
        vm.openDevices(fingerprint)
        settle()
        assertEquals(listOf(revoked(device)), onDisk(fingerprint))
        assertEquals("the registrar asked once", 1, setups.revocations.size)
    }

    @Test
    fun aCertificateWhoseSendingDropsIsSentAgainOnce() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val first = shown(vm, fingerprint)
        first.deliverFails += CoreException.Connect("dropped")
        asked(vm, fingerprint, first)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertTrue(vm.certify.value is Certifying.Approved)
        assertTrue(first.delivered)
        val second = shown(vm, fingerprint)
        repeat(2) { second.deliverFails += CoreException.Connect("dropped") }
        asked(vm, fingerprint, second)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(Certifying.Failed(fingerprint, SetupProblem.Unreachable), vm.certify.value)
        assertFalse(second.delivered)
        assertEquals("tried twice, no more", 2, second.sends)
        assertEquals("perhaps delivered: listed, revocable", listOf(tablet.fingerprint), onDisk(fingerprint).map { it.fingerprint })
    }

    @Test
    fun aRequestThatEndsWhileItsPromptIsUpEndsOnceThePromptIsCanceled() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        vm.approveDevice(
            fingerprint,
            manage = false,
            stores.keys.authorizer {
                session.ends.complete(Unit)
                false
            },
        )
        settle()
        assertEquals(Certifying.Ended(fingerprint, CertifyEnd.EXPIRED), vm.certify.value)
    }

    @Test
    fun anIdentityDeletedOnceItsDeviceIsListedHasNothingSentFor() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        session.beforeDeliver = { vm.deleteIdentity(fingerprint) }
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertFalse(session.delivered)
        assertFalse("no list written back", minted(fingerprint).exists())
    }

    @Test
    fun aRevocationTheRegistrarMayHaveTakenKeepsItsMark() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        setups.revokeFails = CoreException.Refused("server_error", "")
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(listOf(device.with(revoking = true)), onDisk(fingerprint))
    }

    @Test
    fun aDeviceAskingUnderAnEmptyNameIsListedAndSent() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val session = shown(vm, fingerprint)
        val nameless = asking("")
        session.next.complete(nameless)
        settle()
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertTrue(session.delivered)
        assertEquals(listOf(null), onDisk(fingerprint).map { it.name })
    }

    @Test
    fun aRevocationThatFailsOnceTheRegistrarIsAskedKeepsItsMarkWhateverTheFailure() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        // Not the core's refusal: an error of the binding itself, the call under way.
        setups.revokeFails = IllegalStateException("the core panicked")
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(Revoking.Failed(fingerprint, SetupProblem.RevocationUnconfirmed), vm.revoking.value)
        assertEquals(listOf(device.with(revoking = true)), onDisk(fingerprint))
    }

    @Test
    fun aRevocationTheKeyFailsBeforeTheRegistrarIsAskedLeavesTheDeviceAsItWas() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        stores.keys.trouble = { java.security.ProviderException("the Keystore busy") }
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        stores.keys.trouble = null
        assertEquals(Revoking.Failed(fingerprint, SetupProblem.NotKept), vm.revoking.value)
        assertEquals(emptyList<Any>(), setups.revocations)
        assertEquals(listOf(device), onDisk(fingerprint))
    }

    @Test
    fun aRevocationTheKeyFailsInAWayItsHandlingDoesNotKnowIsToldAndThrowsAtNothing() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        stores.keys.trouble = { IllegalStateException("the prompt broke") }
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        stores.keys.trouble = null
        assertEquals(Revoking.Failed(fingerprint, SetupProblem.Other), vm.revoking.value)
        assertEquals(listOf(device), onDisk(fingerprint))
    }

    @Test
    fun aDevicePastItsCertificateIsLetGoOfUnlessRevoked() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        val session = certified(vm, fingerprint)
        val other = heldHere(vm)
        vm.openDevices(other)
        certified(vm, other)
        val revoked = devices(vm).single { !it.own }
        vm.revokeDevice(other, revoked, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        now = session.expires.toLong() + 1
        vm.openDevices(fingerprint)
        settle()
        assertEquals("its certificate dead", listOf(own(vm)), devices(vm))
        vm.openDevices(other)
        settle()
        assertEquals("kept, to refuse its key", 1, devices(vm).count { it.revoked })
        val again = shown(vm, other)
        asked(vm, other, again, Revoked.Yes)
    }

    @Test
    fun aListLeftForAnIdentityNoLongerHereIsLetGoOfAtStart() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        certified(vm, fingerprint)
        val orphan = File(stores.identityDir, "minted-0123456789abcdef01234567")
        orphan.writeText("[]")
        File(stores.identityDir, orphan.name + ".unread-0").writeText("kept aside")
        model2()
        assertFalse(orphan.exists())
        assertEquals(
            listOf(minted(fingerprint).name),
            stores.identityDir
                .list()
                .orEmpty()
                .filter { it.startsWith("minted-") },
        )
    }

    @Test
    fun anIdentityDeletedOnceItsCertificateIsMadeHasNothingSentFor() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        session.onCertify = { vm.deleteIdentity(fingerprint) }
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(1, session.approvals.size)
        assertFalse(session.delivered)
    }

    @Test
    fun aRequestUnansweredWhenTheMailboxLetsItGoEnds() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        session.ends.complete(Unit)
        settle()
        assertEquals(Certifying.Ended(fingerprint, CertifyEnd.EXPIRED), vm.certify.value)
        assertTrue(session.canceled && session.closed)
    }

    @Test
    fun aListTheDiskSaysItWroteAndDidNotKeepIsNotSentFor() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        stores.losesLists = true
        val session = certified(vm, fingerprint)
        stores.losesLists = false
        assertEquals(Certifying.Failed(fingerprint, SetupProblem.NotKept), vm.certify.value)
        assertFalse(session.delivered)
    }

    @Test
    fun aDeviceIsMarkedBeingRevokedBeforeTheRegistrarIsAskedAndCountsAsRevoked() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        setups.revokeFails = CoreException.Connect("its answer lost")
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(Revoking.Failed(fingerprint, SetupProblem.Unreachable), vm.revoking.value)
        assertEquals(listOf(device.with(revoking = true)), onDisk(fingerprint))
        // Tried again and not done, by the person or by the registrar, the mark stands,
        // whatever the copy of the device the screen held said.
        val marked = device.with(revoking = true)
        vm.revokingSeen()
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer { false })
        settle()
        assertEquals(listOf(marked), onDisk(fingerprint))
        vm.revokingSeen()
        vm.revokeDevice(fingerprint, marked, RevokeReason.LOST, stores.keys.authorizer { false })
        settle()
        assertEquals(listOf(marked), onDisk(fingerprint))
        setups.revokeFails = CoreException.Refused("bad_time", "")
        vm.revokingSeen()
        vm.revokeDevice(fingerprint, marked, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(listOf(marked), onDisk(fingerprint))
        // As a process started again finds it.
        val again = model2()
        again.openDevices(fingerprint)
        settle()
        val session = shown(again, fingerprint)
        asked(again, fingerprint, session, Revoked.Yes)
        again.cancelCertifying()
        again.revokingSeen()
        again.revokeDevice(fingerprint, device.with(revoking = true), RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(listOf(device.with(revoked = true)), onDisk(fingerprint))
        assertEquals(1, setups.revocations.size)
    }

    @Test
    fun aRevocationTheRegistrarRefusesLeavesNoMarkAndOneUnmarkedIsNotAsked() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        setups.revokeFails = CoreException.Refused("bad_record", "")
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(listOf(device), onDisk(fingerprint))
        vm.revokingSeen()
        unwritable {
            vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
            settle()
        }
        assertEquals(Revoking.Failed(fingerprint, SetupProblem.NotKept), vm.revoking.value)
        assertEquals("the registrar not asked", emptyList<Any>(), setups.revocations)
    }

    @Test
    fun aCodeOnScreenIsNotWrittenToALog() {
        val vm = model()
        settle()
        shown(vm, heldHere(vm))
        assertFalse(
            vm.certify.value
                .toString()
                .contains("K7PM"),
        )
    }
}
