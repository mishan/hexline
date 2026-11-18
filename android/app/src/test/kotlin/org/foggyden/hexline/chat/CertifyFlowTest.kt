package org.foggyden.hexline.chat

import org.foggyden.hexline.core.Caps
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.HolderRequest
import org.foggyden.hexline.core.deviceFingerprintOf
import org.foggyden.hexline.core.shortHash
import org.foggyden.hexline.identity.CertifyEnd
import org.foggyden.hexline.identity.Certifying
import org.foggyden.hexline.identity.MintedDevice
import org.foggyden.hexline.identity.RevokeReason
import org.foggyden.hexline.identity.Revoking
import org.foggyden.hexline.identity.SetupProblem
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

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
        request: HolderRequest = tablet,
    ) {
        session.next.complete(request)
        settle()
        assertEquals(Certifying.Asked(fingerprint, request), vm.certify.value)
    }

    private fun own(vm: ChatViewModel) = vm.devices.value.single { it.own }

    @Test
    fun aDeviceAskingByTheCodeShownIsCertifiedBehindThePromptAndListed() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        settle()
        assertEquals("this phone's own device alone", 1, vm.devices.value.size)
        val session = shown(vm, fingerprint)
        assertArrayEquals("for the identity's card", stored()!!.card, session.card)
        asked(vm, fingerprint, session)
        vm.approveDevice(fingerprint, manage = true, stores.keys.authorizer { false })
        settle()
        assertEquals("a prompt refused leaves it asked", Certifying.Asked(fingerprint, tablet), vm.certify.value)
        assertEquals(emptyList<Any>(), session.approvals)
        vm.approveDevice(fingerprint, manage = true, stores.keys.authorizer())
        settle()
        val certified = MintedDevice(session.device, tablet.fingerprint, "Tablet", session.expires.toLong(), canManage = true)
        assertEquals(Certifying.Approved(certified), vm.certify.value)
        val (seed, manage) = session.approvals.single()
        assertTrue(manage)
        assertTrue("the identity's seed wiped", seed.all { it == 0.toByte() })
        assertTrue("given back", session.canceled && session.closed)
        assertEquals(listOf(own(vm), certified), vm.devices.value)
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
        assertEquals(Certifying.Denied, vm.certify.value)
        assertEquals(1, session.denials.size)
        assertTrue(session.canceled && session.closed)
        assertEquals(listOf(own(vm)), vm.devices.value)
    }

    @Test
    fun aWaitTheMailboxEndsSaysWhyAndANewCodeIsAnotherSession() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        for ((code, why) in listOf(
            "expired" to CertifyEnd.Expired,
            "used" to CertifyEnd.Expired,
            "unpaired_request" to CertifyEnd.Unpaired,
            "stale_request" to CertifyEnd.Stale,
            "unreadable_request" to CertifyEnd.Unreadable,
            "no_login_request" to CertifyEnd.NoLogin,
        )) {
            val session = shown(vm, fingerprint)
            session.next.completeExceptionally(CoreException.Refused(code, ""))
            settle()
            assertEquals(code, Certifying.Ended(why), vm.certify.value)
            assertTrue("$code: let go of", session.closed)
        }
        setups.openFails = CoreException.Refused("no_mailbox", "")
        vm.startCertifying(fingerprint, "chat.example")
        settle()
        assertEquals(Certifying.Ended(CertifyEnd.NoMailbox), vm.certify.value)
        setups.openFails = CoreException.Connect("down")
        vm.startCertifying(fingerprint, "chat.example")
        settle()
        assertEquals(Certifying.Failed(SetupProblem.Unreachable), vm.certify.value)
        vm.certifySeen()
        assertEquals(Certifying.Idle, vm.certify.value)
    }

    @Test
    fun aCodeCanceledAdmitsNobodyAndARequestAfterIsNotAsked() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val session = shown(vm, fingerprint)
        vm.cancelCertifying()
        settle()
        assertEquals(Certifying.Idle, vm.certify.value)
        assertTrue("given back", session.canceled && session.closed)
        // One opened as it was canceled is let go of as it arrives.
        vm.startCertifying(fingerprint, "mail.example")
        vm.cancelCertifying()
        settle()
        assertEquals(Certifying.Idle, vm.certify.value)
        assertTrue(setups.sessions.last().closed)
    }

    @Test
    fun aDeviceCertifiedHereIsRevokedForItsReasonBehindThePromptAndThisPhonesOwnIsNot() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        val tablet = vm.devices.value.single { !it.own }
        vm.revokeDevice(fingerprint, tablet, RevokeReason.Stolen, stores.keys.authorizer { false })
        settle()
        assertEquals(Revoking.Idle, vm.revoking.value)
        assertEquals(emptyList<Any>(), setups.revocations)
        vm.revokeDevice(fingerprint, tablet, RevokeReason.Stolen, stores.keys.authorizer())
        settle()
        val revoked = MintedDevice(tablet.device, tablet.fingerprint, tablet.name, tablet.expires, tablet.canManage, revoked = true)
        assertEquals(Revoking.Done(tablet), vm.revoking.value)
        val revocation = setups.revocations.single()
        assertEquals("reg.example", revocation.registrar)
        assertArrayEquals(session.device, revocation.device)
        assertEquals(RevokeReason.Stolen, revocation.reason)
        // The core makes it last at least as long as a renewal elsewhere could.
        assertEquals("the latest expiry known here", tablet.expires, revocation.until)
        assertTrue("the identity's seed wiped", revocation.seed.all { it == 0.toByte() })
        assertEquals(listOf(own(vm), revoked), vm.devices.value)
        vm.revokingSeen()
        vm.revokeDevice(fingerprint, own(vm), RevokeReason.Lost, stores.keys.authorizer())
        settle()
        assertEquals(Revoking.Failed(SetupProblem.Other), vm.revoking.value)
        assertEquals(1, setups.revocations.size)
    }

    @Test
    fun anIdentityDeletedTakesItsListOfDevicesWithIt() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertFalse(outside { identities.minted(fingerprint) }.isEmpty())
        vm.deleteIdentity(fingerprint)
        settle()
        assertEquals(emptyList<MintedDevice>(), outside { identities.minted(fingerprint) })
    }

    @Test
    fun aCodeShownForOneIdentityIsPutAwayWhenAnothersDevicesAreOpenedAndAnsweredForNoOther() {
        val vm = model()
        settle()
        val other = heldHere(vm)
        val fingerprint = heldHere(vm)
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
        settle()
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
        val first = shown(vm, fingerprint)
        asked(vm, fingerprint, first)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        val device = vm.devices.value.single { !it.own }
        vm.revokeDevice(fingerprint, device, RevokeReason.Lost, stores.keys.authorizer())
        settle()
        val again = shown(vm, fingerprint)
        again.next.complete(tablet)
        settle()
        assertEquals(Certifying.Asked(fingerprint, tablet, revoked = true), vm.certify.value)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(emptyList<Any>(), again.approvals)
    }

    @Test
    fun aListOfDevicesThatDoesNotReadIsMovedAsideNotWrittenOver() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val name = "minted-" + shortHash(fingerprint.toByteArray())
        val list = java.io.File(stores.identityDir, name)
        list.writeText("not a list")
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals("kept aside", "not a list", java.io.File(stores.identityDir, "$name.unread").readText())
        assertEquals(listOf(tablet.fingerprint), outside { identities.minted(fingerprint) }.map { it.fingerprint })
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
