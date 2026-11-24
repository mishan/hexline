package org.foggyden.hexline.chat

import kotlinx.coroutines.CompletableDeferred
import org.foggyden.hexline.core.Caps
import org.foggyden.hexline.core.CertifyEnd
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.DeviceStanding
import org.foggyden.hexline.core.HolderRequest
import org.foggyden.hexline.core.RevokeReason
import org.foggyden.hexline.core.WholeRead
import org.foggyden.hexline.core.certTimeChanges
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
import org.junit.Assert.assertNotNull
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

    private fun cardOf(fingerprint: String) = outside { identities.list().single { it.fingerprint == fingerprint }.card }

    /** Whether [session] was opened with [device] marked revoked, for the core to refuse. */
    private fun handedRevoked(
        session: FakeSetups.FakeSession,
        device: MintedDevice,
    ) = handed(session, device.device)

    private fun handed(
        session: FakeSetups.FakeSession,
        key: ByteArray,
    ) = session.kept.devices
        .single { it.device.contentEquals(key) }
        .revoked

    private fun standing(
        vm: ChatViewModel,
        device: MintedDevice,
    ) = checkNotNull(vm.devices.value).standing[device.fingerprint]

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
    fun aDeviceIsKeptAtTheEpochItWasCertifiedInAndTheNextSessionIsOpenedWithIt() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val first = shown(vm, fingerprint)
        assertEquals(listOf("reg.example", 0uL, 0), first.kept.let { listOf(it.registrar, it.epoch, it.devices.size) })
        first.epoch = 4uL
        asked(vm, fingerprint, first)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(4L, (vm.certify.value as Certifying.Approved).device.epoch)
        assertEquals("the identity's epoch raised", 4L, stored()!!.epoch)
        // A process started again opens the next session with what was kept.
        val again = model2()
        val next = shown(again, fingerprint)
        assertEquals(4uL, next.kept.epoch)
        val listed = next.kept.devices.single()
        assertArrayEquals(first.device, listed.device)
        assertEquals(4uL, listed.epoch)
    }

    @Test
    fun aFloorReadForARequestIsKeptWhateverTheRequestCameTo() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        setups.floor = 6
        val session = shown(vm, fingerprint)
        session.next.completeExceptionally(CoreException.Refused("signed_out_request", "", null))
        settle()
        assertEquals(Certifying.Ended(fingerprint, CertifyEnd.SIGNED_OUT), vm.certify.value)
        assertEquals(6L, stored()!!.epoch)
    }

    @Test
    fun aFloorReadForARequestIsKeptWhenTheModelGoesWhileItWaits() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        setups.floor = 6
        shown(vm, fingerprint)
        owner.clear()
        settle()
        assertEquals(6L, stored()!!.epoch)
    }

    @Test
    fun aFloorTheDeviceListAloneKeptIsTheOneASessionIsOpenedWith() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        // As a crash between the list's write and the identity's leaves it: the identity's not made.
        val device = ByteArray(32) { 9 }
        stores.identitiesFail = true
        outside {
            identities.minted(
                fingerprint,
                MintedDevice(device, deviceFingerprintOf(device), null, 2_000_000_000, false, epoch = 7),
                now,
            )
        }
        stores.identitiesFail = false
        assertEquals(0L, stored()!!.epoch)
        assertEquals(7uL, shown(vm, fingerprint).kept.epoch)
    }

    @Test
    fun aDeviceListThatDidNotOpenForTheSessionIsReadAgainForTheApproval() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val other = ByteArray(32) { 9 }
        outside {
            identities.minted(
                fingerprint,
                MintedDevice(other, deviceFingerprintOf(other), null, 2_000_000_000, false, epoch = 1),
                now,
            )
        }
        val list = minted(fingerprint)
        list.setReadable(false)
        val session =
            try {
                assertFalse("a file's permissions hold, as they do not for root", list.canRead())
                shown(vm, fingerprint)
            } finally {
                list.setReadable(true)
            }
        assertEquals("opened knowing none", 0, session.kept.devices.size)
        asked(vm, fingerprint, session)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(listOf(1uL), session.listed?.map { it.epoch })
    }

    @Test
    fun aFloorOnlyTheDeviceListHeldOutlivesItsEntryLapsing() {
        for (identitiesFail in listOf(false, true)) {
            fresh()
            val vm = model()
            settle()
            val fingerprint = heldHere(vm)
            stores.identitiesFail = identitiesFail
            val lapsed = ByteArray(32) { 9 }
            val other = ByteArray(32) { 8 }
            outside {
                identities.minted(fingerprint, MintedDevice(lapsed, deviceFingerprintOf(lapsed), null, 1_000, false, epoch = 7), now)
                // A write that lets the lapsed entry go.
                identities.minted(fingerprint, MintedDevice(other, deviceFingerprintOf(other), null, 2_000_000_000, false), now)
            }
            assertEquals("$identitiesFail", 7L, outside { identities.epoch(identities.list().single()) })
        }
    }

    @Test
    fun aFloorOnlyTheDeviceListHoldsOutlivesAnOlderEntryForTheSameKey() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        stores.identitiesFail = true
        val device = ByteArray(32) { 9 }
        val listed = MintedDevice(device, deviceFingerprintOf(device), null, 2_000_000_000, false, epoch = 7)
        outside {
            identities.minted(fingerprint, listed, now)
            // As a screen read before the latest certificate would revoke it.
            identities.minted(
                fingerprint,
                MintedDevice(device, deviceFingerprintOf(device), null, 2_000_000_000, false, revoked = true),
                now,
            )
        }
        stores.identitiesFail = false
        val kept = outside { identities.minted(fingerprint) }.single()
        assertEquals(listOf(true, 7L), listOf(kept.revoked, kept.epoch))
        assertEquals(7L, outside { identities.epoch(identities.list().single()) })
    }

    @Test
    fun aFloorTheIdentityCannotTakeOutlivesItsEntryLapsing() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val file = File(stores.identityDir, "identity-" + shortHash(fingerprint.toByteArray()))
        val kept = file.readBytes()
        // An identity's file that does not read: the floor has nowhere else to go.
        file.writeText("not an identity")
        val lapsed = ByteArray(32) { 9 }
        val other = ByteArray(32) { 8 }
        try {
            outside {
                identities.minted(fingerprint, MintedDevice(lapsed, deviceFingerprintOf(lapsed), null, 1_000, false, epoch = 7), now)
                identities.minted(fingerprint, MintedDevice(other, deviceFingerprintOf(other), null, 2_000_000_000, false), now)
            }
        } finally {
            file.writeBytes(kept)
        }
        assertEquals(listOf(7L, 0L), onDisk(fingerprint).map { it.epoch })
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
            "signed_out_request" to CertifyEnd.SIGNED_OUT,
        )) {
            val session = shown(vm, fingerprint)
            session.next.completeExceptionally(CoreException.Refused(code, "", null))
            settle()
            assertEquals(code, Certifying.Ended(fingerprint, why), vm.certify.value)
            assertTrue("$code: let go of", session.closed)
        }
        setups.openFails = CoreException.Refused("no_mailbox", "", null)
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
        assertEquals("the registrar not asked", 0, setups.revokeCalls)
        assertEquals("nor marked here", listOf(tablet), onDisk(fingerprint))
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
    fun aListDiscardedCarriesEachRevokedKeyItCanStillReadAndWarnsOnlyWhereItCannotReadAll() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val list = minted(fingerprint)
        val key = { b: Byte -> android.util.Base64.encodeToString(ByteArray(32) { b }, android.util.Base64.NO_WRAP) }
        // Set aside for want of an expiry, every key read; then another with a key that does not.
        for ((text, loses) in listOf(
            """[{"device":"${key(7)}","revoked":true},{"device":"${key(8)}"}]""" to false,
            """[{"device":"${key(5)}","revoked":true},{"device":12}]""" to true,
        )) {
            list.writeText(text)
            vm.openDevices(fingerprint)
            settle()
            val shown = checkNotNull(vm.devices.value)
            assertTrue(shown.setAside)
            assertEquals(text, loses, shown.setAsideLoses)
        }
        vm.discardUnreadable(fingerprint)
        settle()
        assertEquals(
            "only the revoked, carried",
            listOf(true, true),
            listOf(7, 5).map { b -> onDisk(fingerprint).single { it.device.contentEquals(ByteArray(32) { b.toByte() }) }.revoked },
        )
        assertEquals(2, onDisk(fingerprint).size)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Yes)
    }

    @Test
    fun aKeyMarkedRevokedStaysSoWhateverIsWrittenForItLater() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val ends = now + DAY
        outside {
            identities.minted(fingerprint, entry(7, ends, revoked = true), now)
            identities.minted(fingerprint, entry(7, ends + DAY), now)
        }
        assertEquals(listOf(entry(7, ends + DAY, revoked = true)), onDisk(fingerprint))
    }

    @Test
    fun aWholeReadOfTheRecordsIsKeptWithTheListAndHandedToTheSession() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        outside { identities.minted(fingerprint, entry(9, now + DAY), now) }
        val first = shown(vm, fingerprint)
        assertNull("never read", first.kept.read)
        vm.cancelCertifying()
        setups.revokedElsewhere(cardOf(fingerprint), ByteArray(32) { 3 })
        vm.openDevices(fingerprint)
        settle()
        val read = WholeRead(now.toULong(), uptime.toULong(), boot, listOf("reg.example"), 0uL)
        setups.listsRead = false
        now += 60
        uptime += 60
        vm.openDevices(fingerprint)
        settle()
        val again = model2()
        val session = shown(again, fingerprint)
        assertEquals("the last whole read, not the later one", read, session.kept.read)
        assertEquals(uptime.toULong(), session.kept.uptime)
        assertEquals(boot, session.kept.boot)
        assertTrue(handed(session, ByteArray(32) { 3 }))
    }

    @Test
    fun aKeyTheRecordsShowedRevokedIsRefusedListedHereOrNotAndAfterARestartWithNoRead() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        settle()
        // Revoked by another holder that certified it: never listed here.
        setups.revokedElsewhere(cardOf(fingerprint), tablet.device)
        vm.openDevices(fingerprint)
        settle()
        assertEquals("not listed", emptyList<MintedDevice>(), onDisk(fingerprint))
        setups.listsRead = false
        val again = model2()
        again.openDevices(fingerprint)
        settle()
        val session = shown(again, fingerprint)
        asked(again, fingerprint, session, Revoked.Yes)
        assertTrue("handed to the core marked", handed(session, tablet.device))
    }

    @Test
    fun aKeyARecordsReadShowsRevokedWhileItAsksIsNotApproved() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session)
        setups.revokedElsewhere(cardOf(fingerprint), tablet.device)
        vm.openDevices(fingerprint)
        settle()
        assertEquals(Certifying.Asked(fingerprint, tablet, Revoked.Yes), vm.certify.value)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(emptyList<Any>(), session.approvals)
    }

    @Test
    fun aWholeReadKeptMalformedIsNoneAndTheListAndItsKeysSeenRevokedStand() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val key = { b: Byte -> android.util.Base64.encodeToString(ByteArray(32) { b }, android.util.Base64.NO_WRAP) }
        minted(fingerprint).writeText(
            """{"devices":[{"device":"${key(9)}","expires":${now + DAY}}],"revoked":["${key(7)}"],"read":{"at":1}}""",
        )
        // No read of the records lands to write another.
        setups.standingWaits = CompletableDeferred()
        vm.openDevices(fingerprint)
        settle()
        assertFalse("not set aside", checkNotNull(vm.devices.value).setAside)
        assertEquals(listOf(entry(9, now + DAY)), onDisk(fingerprint))
        val session = shown(vm, fingerprint)
        assertNull("no read to stand in", session.kept.read)
        asked(vm, fingerprint, session, Revoked.Yes)
    }

    @Test
    fun aListWithAKeySeenRevokedThatDoesNotReadIsSetAsideAndTheOneBesideItStillRefused() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val key = { b: Byte -> android.util.Base64.encodeToString(ByteArray(32) { b }, android.util.Base64.NO_WRAP) }
        minted(fingerprint).writeText("""{"devices":[],"revoked":[12,"${key(7)}"]}""")
        setups.standingWaits = CompletableDeferred()
        vm.openDevices(fingerprint)
        settle()
        val list = checkNotNull(vm.devices.value)
        assertTrue("set aside", list.setAside)
        assertTrue("warned", list.setAsideLoses)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Yes)
        assertTrue(handed(session, tablet.device))
        assertNull("no read stands in from it", session.kept.read)
    }

    @Test
    fun revocationsAReadFindsThatTheDiskWillNotTakeAreHeldAndWrittenWithTheNext() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        setups.revokedElsewhere(cardOf(fingerprint), tablet.device)
        unwritable {
            vm.openDevices(fingerprint)
            settle()
        }
        assertEquals("not on disk", emptyList<ByteArray>(), outside { identities.seenRevoked(fingerprint) })
        // Asked before any other read lands.
        val held = CompletableDeferred<Unit>()
        setups.standingWaits = held
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Yes)
        assertTrue("handed to the core", handed(session, tablet.device))
        // No read from now on finds it: only what the core held of the read refused can reach the disk.
        setups.listsRead = false
        setups.standingWaits = null
        held.complete(Unit)
        settle()
        assertEquals(listOf(tablet.device.toList()), outside { identities.seenRevoked(fingerprint) }.map { it.toList() })
    }

    @Test
    fun theRevocationsARecordsReadOvertakenFoundAreKeptAndNothingElseOfIt() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val earlier = CompletableDeferred<Unit>()
        setups.standingWaits = earlier
        vm.openDevices(fingerprint)
        settle()
        // A newer read, not whole and finding nothing, lands first.
        setups.standingWaits = null
        setups.listsRead = false
        vm.openDevices(fingerprint)
        settle()
        setups.listsRead = true
        setups.revokedElsewhere(cardOf(fingerprint), tablet.device)
        earlier.complete(Unit)
        settle()
        setups.standingWaits = CompletableDeferred()
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Yes)
        assertNull("the overtaken read stands in for nothing", session.kept.read)
    }

    @Test
    fun aListSetAsideIsKeptWhereTheListDoesNotHoldWhatIsCarriedFromIt() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val key = { b: Byte -> android.util.Base64.encodeToString(ByteArray(32) { b }, android.util.Base64.NO_WRAP) }
        minted(fingerprint).writeText("""{"devices":[{"device":12}],"revoked":["${key(7)}"]}""")
        setups.standingWaits = CompletableDeferred()
        vm.openDevices(fingerprint)
        settle()
        stores.losesLists = true
        vm.discardUnreadable(fingerprint)
        settle()
        stores.losesLists = false
        assertTrue("still set aside", checkNotNull(vm.devices.value).setAside)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Yes)
    }

    @Test
    fun aListSetAsideCarriesItsRevokedDevicesAtTheirEpochAndMarksThoseItsKeysSeenRevokedName() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val key = { b: Byte -> android.util.Base64.encodeToString(ByteArray(32) { b }, android.util.Base64.NO_WRAP) }
        val ends = now + DAY
        outside { identities.minted(fingerprint, entry(8, ends), now) }
        File(stores.identityDir, minted(fingerprint).name + ".unread-0").writeText(
            """{"devices":[{"device":"${key(9)}","expires":$ends,"revoked":true,"epoch":5}],"revoked":["${key(8)}"]}""",
        )
        vm.discardUnreadable(fingerprint)
        settle()
        val kept = onDisk(fingerprint)
        assertEquals(5L, kept.single { it.device[0] == 9.toByte() }.epoch)
        assertTrue(kept.single { it.device[0] == 9.toByte() }.revoked)
        assertTrue("marked by a key seen revoked", kept.single { it.device[0] == 8.toByte() }.revoked)
    }

    @Test
    fun aKeyCertifiedHereIsHandedToTheCoreLongAfterItsEntryIsLetGo() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        val first = certified(vm, fingerprint)
        now = lapsed(first.expires.toLong())
        outside { identities.minted(fingerprint, entry(9, now + DAY), now) }
        assertFalse("let go of", onDisk(fingerprint).any { it.device.contentEquals(tablet.device) })
        setups.listsRead = false
        val again = model2()
        val session = shown(again, fingerprint)
        val handedIt = session.kept.devices.find { it.device.contentEquals(tablet.device) }
        assertEquals("known, for the core to judge", false, handedIt?.revoked)
        assertEquals("at the epoch it was certified in", first.epoch, handedIt?.epoch)
    }

    @Test
    fun aListSetAsideMeanwhileIsNotDiscardedUnread() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val key = { b: Byte -> android.util.Base64.encodeToString(ByteArray(32) { b }, android.util.Base64.NO_WRAP) }
        File(stores.identityDir, minted(fingerprint).name + ".unread-0").writeText("""{"devices":[],"revoked":["${key(7)}"]}""")
        // The list itself turns unreadable after the copy was looked at.
        minted(fingerprint).writeText("""{"devices":[],"revoked":[12,"${key(5)}"]}""")
        setups.standingWaits = CompletableDeferred()
        vm.discardUnreadable(fingerprint)
        settle()
        assertEquals(
            listOf(5, 7),
            outside { identities.seenRevoked(fingerprint) }.map { it[0].toInt() }.sorted(),
        )
    }

    @Test
    fun aWholeReadKeptIsLetGoOfWhenALaterReadsRevocationsCannotBeKept() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        settle()
        assertNotNull(outside { identities.lastRead(fingerprint) })
        setups.revokedElsewhere(cardOf(fingerprint), tablet.device)
        stores.listsFail = 1
        vm.openDevices(fingerprint)
        settle()
        assertNull("a read from before stands in no more", outside { identities.lastRead(fingerprint) })
    }

    @Test
    fun aDeviceRevokedInAListSetAsideIsHandedToTheCoreRevoked() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val key = { b: Byte -> android.util.Base64.encodeToString(ByteArray(32) { b }, android.util.Base64.NO_WRAP) }
        File(stores.identityDir, minted(fingerprint).name + ".unread-0").writeText(
            """{"devices":[{"device":"${key(9)}","expires":${now + DAY},"revoked":true}]}""",
        )
        setups.standingWaits = CompletableDeferred()
        val session = shown(vm, fingerprint)
        assertTrue(handed(session, ByteArray(32) { 9 }))
    }

    @Test
    fun whatTheCoreVerifiedReachesTheDiskFromEveryCallThatReadsTheRecordsWhateverItComesTo() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val card = cardOf(fingerprint)
        val key = { b: Int -> ByteArray(32) { b.toByte() } }
        val onDisk = { outside { identities.seenRevoked(fingerprint) }.map { it[0].toInt() }.toSet() }
        // A read of the devices.
        setups.verified(card, key(1))
        vm.openDevices(fingerprint)
        settle()
        assertTrue("a read of the devices", 1 in onDisk())
        // A request the session refused.
        val refused = shown(vm, fingerprint)
        setups.verified(card, key(2))
        refused.next.completeExceptionally(CoreException.Refused("signed_out_request", "", null))
        settle()
        assertTrue("a request refused", 2 in onDisk())
        // A request shown, and its certifying failing.
        val failing = shown(vm, fingerprint)
        setups.verified(card, key(3))
        asked(vm, fingerprint, failing)
        assertTrue("a request shown", 3 in onDisk())
        failing.onCertify = {
            setups.verified(card, key(4))
            throw CoreException.Refused("signed_out_request", "", null)
        }
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertTrue("a certifying refused", 4 in onDisk())
    }

    @Test
    fun aListWhoseEvidenceIsNotAListIsSetAside() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        minted(fingerprint).writeText("""{"devices":[],"revoked":"not a list"}""")
        setups.standingWaits = CompletableDeferred()
        vm.openDevices(fingerprint)
        settle()
        assertTrue(checkNotNull(vm.devices.value).setAside)
    }

    @Test
    fun aReadOfTheRecordsLandingOnceItsIdentityIsDeletedWritesNothingBack() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        setups.revokedElsewhere(cardOf(fingerprint), tablet.device)
        val held = CompletableDeferred<Unit>()
        setups.standingWaits = held
        vm.openDevices(fingerprint)
        settle()
        vm.deleteIdentity(fingerprint)
        settle()
        assertFalse(minted(fingerprint).exists())
        setups.standingWaits = null
        held.complete(Unit)
        settle()
        assertFalse("no list written back", minted(fingerprint).exists())
    }

    @Test
    fun theFloorAWholeReadSawOutlivesItsListSetAsideAndDiscarded() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        outside { identities.learned(fingerprint, 1) }
        minted(fingerprint).writeText(
            """{"devices":[],"revoked":"not a list","read":{"at":1,"uptime":1,"boot":"1","registrars":[],"floor":7}}""",
        )
        setups.standingWaits = CompletableDeferred()
        vm.openDevices(fingerprint)
        settle()
        assertTrue(checkNotNull(vm.devices.value).setAside)
        vm.discardUnreadable(fingerprint)
        settle()
        assertFalse(checkNotNull(vm.devices.value).setAside)
        val session = shown(vm, fingerprint)
        assertEquals("the core sees the floor", 7uL, session.kept.epoch)
    }

    @Test
    fun aWholeReadIsNotKeptToStandInWhereNoBootIsKnown() {
        boot = ""
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        settle()
        val session = shown(vm, fingerprint)
        assertNull(session.kept.read)
    }

    @Test
    fun aListSetAsideCarriesItsKeysSeenRevokedWhenDiscardedAndWarnsOfWhatItCannotRead() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val key = { b: Byte -> android.util.Base64.encodeToString(ByteArray(32) { b }, android.util.Base64.NO_WRAP) }
        // Set aside for a device that does not read; its key seen revoked reads.
        minted(fingerprint).writeText("""{"devices":[{"device":12}],"revoked":["${key(7)}"]}""")
        setups.standingWaits = CompletableDeferred()
        vm.openDevices(fingerprint)
        settle()
        val shown = checkNotNull(vm.devices.value)
        assertTrue(shown.setAside)
        assertTrue("warned", shown.setAsideLoses)
        vm.discardUnreadable(fingerprint)
        settle()
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Yes)
        assertTrue(handed(session, tablet.device))
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
    fun aRevocationTheDiskWillNotMarkIsNotAskedOfTheRegistrar() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        unwritable {
            vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
            settle()
        }
        assertEquals(Revoking.Failed(fingerprint, SetupProblem.NotKept), vm.revoking.value)
        assertEquals("the registrar not asked", 0, setups.revokeCalls)
        assertEquals(listOf(device), onDisk(fingerprint))
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
    fun aRevocationTheRegistrarTookWithItsAnswerLostIsShownRevokedFromItsRecordsAndNotApproved() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        setups.revokeAnswerLost = CoreException.Connect("its answer lost")
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(Revoking.Failed(fingerprint, SetupProblem.Unreachable), vm.revoking.value)
        assertEquals("marked from its records", listOf(revoked(device)), onDisk(fingerprint))
        assertEquals(DeviceStanding.REVOKED, standing(vm, device))
        // As a process started again finds it, its records read with nothing else kept.
        val again = model2()
        again.openDevices(fingerprint)
        settle()
        val session = shown(again, fingerprint)
        asked(again, fingerprint, session, Revoked.Yes)
        again.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(emptyList<Any>(), session.approvals)
        setups.listsRead = false
        again.openDevices(fingerprint)
        settle()
        assertTrue("told when no list reads", checkNotNull(again.devices.value).unchecked)
        assertEquals("a read not whole takes back no revocation", DeviceStanding.REVOKED, standing(again, device))
        assertEquals(Certifying.Asked(fingerprint, tablet, Revoked.Yes), again.certify.value)
    }

    @Test
    fun aDeviceRevokedElsewhereIsMarkedFromTheRecordsAndKeptPastItsCertificateAndAListWritten() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        setups.revokedElsewhere(cardOf(fingerprint), device.device)
        vm.openDevices(fingerprint)
        settle()
        assertEquals("marked from the records", listOf(revoked(device)), onDisk(fingerprint))
        // Past its certificate, another entry written, and no list read after a restart.
        now = lapsed(device.expires)
        outside { identities.minted(fingerprint, entry(9, now + DAY), now) }
        setups.listsRead = false
        val again = model2()
        again.openDevices(fingerprint)
        settle()
        assertTrue(revoked(device) in onDisk(fingerprint))
        val session = shown(again, fingerprint)
        asked(again, fingerprint, session, Revoked.Yes)
        assertTrue("handed to the core marked", handedRevoked(session, device))
    }

    @Test
    fun aRevocationWhoseAnswerIsLostStaysMarkedPastItsCertificateAndAListWrittenWithNoListReading() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        setups.listsRead = false
        setups.revokeFails = CoreException.Connect("its answer lost")
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        now = lapsed(device.expires)
        outside { identities.minted(fingerprint, entry(9, now + DAY), now) }
        val again = model2()
        again.openDevices(fingerprint)
        settle()
        val session = shown(again, fingerprint)
        asked(again, fingerprint, session, Revoked.Yes)
        assertTrue(handedRevoked(session, device))
    }

    @Test
    fun aDeviceListedSinceTheLastRecordsReadIsShownUnchecked() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        outside { identities.minted(fingerprint, entry(9, now + DAY), now) }
        vm.openDevices(fingerprint)
        settle()
        assertFalse(checkNotNull(vm.devices.value).unchecked)
        outside { identities.minted(fingerprint, entry(7, now + DAY), now) }
        setups.standingWaits = CompletableDeferred()
        vm.openDevices(fingerprint)
        settle()
        assertTrue(checkNotNull(vm.devices.value).unchecked)
    }

    @Test
    fun aRevocationUnconfirmedLeavesARequestFromItRevokedWhateverTheRecordsSay() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        val read = CompletableDeferred<Unit>()
        setups.standingWaits = read
        setups.revokeFails = CoreException.Refused("server_error", "", null)
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Yes)
        setups.standingWaits = null
        read.complete(Unit)
        settle()
        assertEquals("the records, in force, take back nothing", Certifying.Asked(fingerprint, tablet, Revoked.Yes), vm.certify.value)
        assertEquals("shown as not confirmed", DeviceStanding.IN_FORCE, standing(vm, device))
    }

    @Test
    fun aDeviceBelowTheFloorThisPhoneLearnedIsSignedOutWithNoListReading() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        setups.floor = 6
        setups.listsRead = false
        vm.openDevices(fingerprint)
        settle()
        assertEquals(DeviceStanding.SIGNED_OUT, standing(vm, device))
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
    fun aRevocationThatFailsOnceTheRegistrarIsAskedIsToldUnconfirmedWhateverTheFailure() {
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
        assertEquals(listOf(revoked(device)), onDisk(fingerprint))
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
        assertEquals("the registrar not asked", 0, setups.revokeCalls)
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
        assertEquals("the registrar not asked", 0, setups.revokeCalls)
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
        now = lapsed(session.expires.toLong())
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
    fun aListLeftForAnIdentityNoLongerHereIsLetGoOfAtStartWithItsCopiesAndNothingElse() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        certified(vm, fingerprint)
        val dir = stores.identityDir
        val orphan = File(dir, "minted-0123456789abcdef01234567")
        val aside = File(dir, orphan.name + ".unread-0")
        val lookalike = File(dir, "minted-notes.txt")
        for (f in listOf(orphan, aside, lookalike)) f.writeText("[]")
        val live = File(dir, minted(fingerprint).name + ".unread-0").apply { writeText("kept aside") }
        model2()
        assertFalse("the list", orphan.exists())
        assertFalse("its copy set aside", aside.exists())
        assertTrue("a name this store never gives", lookalike.exists())
        assertTrue("a live identity's list", minted(fingerprint).exists())
        assertTrue("and its copy", live.exists())
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

    /** A device of key [key] listed until [expires], as this phone keeps one. */
    private fun entry(
        key: Byte,
        expires: Long,
        revoked: Boolean = false,
    ): MintedDevice {
        val device = ByteArray(32) { key }
        return MintedDevice(device, deviceFingerprintOf(device), null, expires, false, revoked)
    }

    /** The first instant the core takes a certificate ending at [expires] for expired. */
    private fun lapsed(expires: Long) = checkNotNull(certTimeChanges(0uL, expires.toULong(), expires.toULong())).toLong()

    @Test
    fun aListWrittenLetsGoOfEntriesPastTheirTimeButNotRevokedOnes() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val ends = now + DAY
        val expired = entry(1, ends)
        val revoked = entry(2, ends, revoked = true)
        val later = entry(4, ends + 10 * DAY)
        outside {
            for (e in listOf(expired, revoked)) identities.minted(fingerprint, e, now)
            identities.minted(fingerprint, later, lapsed(ends))
        }
        assertEquals(listOf(revoked, later), onDisk(fingerprint))
    }

    @Test
    fun aDeviceIsListedAndRevocableUntilTheCoreTakesItsCertificateForExpired() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        val ends = now + DAY
        val device = entry(7, ends)
        val other = entry(9, ends)
        outside { for (e in listOf(device, other)) identities.minted(fingerprint, e, now) }
        now = lapsed(ends) - 1
        vm.openDevices(fingerprint)
        settle()
        assertTrue("past its nominal end, inside the skew", device in devices(vm))
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(Revoking.Done(fingerprint, device), vm.revoking.value)
        now = lapsed(ends)
        vm.openDevices(fingerprint)
        settle()
        assertFalse("its certificate dead", devices(vm).any { it.device.contentEquals(other.device) })
        assertTrue("revoked, it stays", device.with(revoked = true) in devices(vm))
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Yes)
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
    fun aRevocationWhoseAnswerIsLostIsMarkedHereShownUnconfirmedAndRevokedAgain() {
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
        assertEquals(listOf(revoked(device)), onDisk(fingerprint))
        assertEquals("not confirmed by the records", DeviceStanding.IN_FORCE, standing(vm, device))
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Yes)
        vm.cancelCertifying()
        vm.revokingSeen()
        vm.revokeDevice(fingerprint, revoked(device), RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(Revoking.Done(fingerprint, revoked(device)), vm.revoking.value)
        assertEquals(listOf(revoked(device)), onDisk(fingerprint))
        assertEquals(DeviceStanding.REVOKED, standing(vm, device))
        assertEquals(listOf(1, 2), listOf(setups.revocations.size, setups.revokeCalls))
    }

    @Test
    fun aRevocationWhoseAnswerIsLostWithNoListReadingLeavesARequestFromItRevoked() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        setups.listsRead = false
        setups.revokeAnswerLost = CoreException.Connect("its answer lost")
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertTrue(checkNotNull(vm.devices.value).unchecked)
        val session = shown(vm, fingerprint)
        asked(vm, fingerprint, session, Revoked.Yes)
        vm.approveDevice(fingerprint, manage = false, stores.keys.authorizer())
        settle()
        assertEquals(emptyList<Any>(), session.approvals)
    }

    @Test
    fun devicesAreUncheckedUntilARecordsReadLandsAndWhenOneFails() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        certified(vm, fingerprint)
        setups.standingFails = CoreException.Connect("down")
        val again = model2()
        again.openDevices(fingerprint)
        settle()
        assertTrue(checkNotNull(again.devices.value).unchecked)
        setups.standingFails = null
        again.openDevices(fingerprint)
        settle()
        assertFalse(checkNotNull(again.devices.value).unchecked)
    }

    @Test
    fun aServerErrorOnceTheRevocationIsSentIsUnconfirmed() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        setups.revokeFails = CoreException.Refused("server_error", "", null)
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertEquals(Revoking.Failed(fingerprint, SetupProblem.RevocationUnconfirmed), vm.revoking.value)
    }

    @Test
    fun aRevocationTheRegistrarRefusesStaysMarkedHere() {
        val vm = model()
        settle()
        val fingerprint = heldHere(vm)
        vm.openDevices(fingerprint)
        certified(vm, fingerprint)
        val device = devices(vm).single { !it.own }
        setups.revokeFails = CoreException.Refused("bad_record", "", null)
        vm.revokeDevice(fingerprint, device, RevokeReason.LOST, stores.keys.authorizer())
        settle()
        assertTrue(vm.revoking.value is Revoking.Failed)
        assertEquals(listOf(revoked(device)), onDisk(fingerprint))
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
