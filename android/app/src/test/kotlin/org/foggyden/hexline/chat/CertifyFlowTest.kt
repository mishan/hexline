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
        return HolderRequest(device, deviceFingerprintOf(device), name, false, false, null, null, lm, true, 90u)
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
        assertEquals(Revoking.Failed(fingerprint, SetupProblem.Other), vm.revoking.value)
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
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(Certifying.Asked(fingerprint, tablet, Revoked.Yes), vm.certify.value)
        assertEquals(emptyList<Any>(), again.approvals)
    }

    @Test
    fun aListOfDevicesThatDoesNotReadIsKeptAsideAndMakesWhatWasRevokedUnknown() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val list = minted(fingerprint)
        for (n in 0..1) {
            list.writeText("not a list $n")
            vm.openDevices(fingerprint)
            settle()
            assertTrue(checkNotNull(vm.devices.value).unreadable)
        }
        for (n in 0..1) {
            assertEquals("kept aside, the first too", "not a list $n", File(stores.identityDir, list.name + ".unread-$n").readText())
        }
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Unknown)
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
            vm.openDevices(fingerprint)
            settle()
            assertEquals(DeviceList(fingerprint, listOf(own(vm)), unreadable = true), vm.devices.value)
            val session = shown(vm, fingerprint)
            asked(vm, fingerprint, session, Revoked.Unknown)
        } finally {
            list.setReadable(true)
        }
    }

    @Test
    fun aDeviceCertifiedOrRevokedWhileTheDiskWillNotTakeItIsListedFromMemoryAndWrittenLater() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        settle()
        val dir = stores.identityDir
        dir.setWritable(false)
        val session =
            try {
                certified(vm, fingerprint)
            } finally {
                dir.setWritable(true)
            }
        val certified = MintedDevice(session.device, tablet.fingerprint, "Tablet", session.expires.toLong(), canManage = false)
        assertEquals(Certifying.Approved(fingerprint, certified, kept = false), vm.certify.value)
        assertTrue("sent all the same", session.delivered)
        assertEquals("revocable from memory", listOf(own(vm), certified), devices(vm))
        vm.openDevices(fingerprint)
        settle()
        assertEquals("written at the next read", listOf(certified), onDisk(fingerprint))
        dir.setWritable(false)
        try {
            vm.revokeDevice(fingerprint, certified, RevokeReason.LOST, stores.keys.authorizer())
            settle()
        } finally {
            dir.setWritable(true)
        }
        assertEquals(Revoking.Done(fingerprint, certified, kept = false), vm.revoking.value)
        assertEquals(listOf(own(vm), revoked(certified)), devices(vm))
        vm.openDevices(fingerprint)
        settle()
        assertEquals(listOf(revoked(certified)), onDisk(fingerprint))
        assertEquals("the registrar asked once", 1, setups.revocations.size)
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
