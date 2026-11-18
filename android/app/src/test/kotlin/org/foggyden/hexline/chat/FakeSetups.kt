package org.foggyden.hexline.chat

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.yield
import org.foggyden.hexline.core.Certified
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.HeldRestore
import org.foggyden.hexline.core.HolderCommitted
import org.foggyden.hexline.core.HolderRequest
import org.foggyden.hexline.core.NewIdentity
import org.foggyden.hexline.core.Restored
import org.foggyden.hexline.core.RevokeReason
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.certForDevice
import org.foggyden.hexline.core.deviceFingerprintOf
import org.foggyden.hexline.core.holderMint
import org.foggyden.hexline.core.holderRenew
import org.foggyden.hexline.core.newIdentity
import org.foggyden.hexline.identity.CertifySession
import org.foggyden.hexline.identity.HolderSetups
import org.foggyden.hexline.identity.NewRecoveryCode
import org.foggyden.hexline.identity.Setup

/**
 * Holders' setups as the core makes them, the registrar's answers the
 * test's: a real identity, card and device each, so the stores take them,
 * and gates the core holds them to.
 */
class FakeSetups : HolderSetups {
    val made = mutableListOf<FakeSetup>()

    /** What the registrar's check throws, if anything. */
    var checkFails: CoreException? = null

    /** What a restore to hold restores, the identity's seed beside it. */
    var restores: NewIdentity? = null

    /** Every identity seed handed out, as handed: each the model's to wipe. */
    val handed = mutableListOf<ByteArray>()

    /** The identity the next setup makes, in place of a new one. */
    var nextIdentity: NewIdentity? = null

    override fun new(name: String) =
        FakeSetup(nextIdentity?.also { nextIdentity = null } ?: newIdentity(name), resumed = null).also { made += it }

    override fun resume(
        identitySeed: ByteArray,
        card: ByteArray,
        registrar: String,
        handle: String,
        deviceSeed: ByteArray,
        deviceCert: ByteArray,
    ): Setup {
        val fingerprint = certForDevice(deviceCert, card, deviceSeed).fingerprint
        return FakeSetup(NewIdentity(identitySeed.copyOf(), card, fingerprint), resumed = registrar to handle).also { made += it }
    }

    override fun checkDeviceName(name: String) =
        org.foggyden.hexline.core
            .checkDeviceName(name)

    /** Every code handed out, as handed: each the model's to wipe. */
    val codes = mutableListOf<ByteArray>()

    override suspend fun check(registrar: String) {
        checkFails?.let { throw it }
    }

    override suspend fun restoreToHold(
        registrar: String,
        handle: String,
        kind: SecretKind,
        secret: String,
        deviceName: String,
    ): HeldRestore {
        val identity = checkNotNull(restores)
        val minted = holderMint(identity.seed, identity.card, deviceName)
        val seed = identity.seed.copyOf().also { handed += it }
        return HeldRestore(Restored(minted.deviceSeed, minted.cert, identity.card, identity.fingerprint, false, true), seed)
    }

    /** Each renewal asked for: the identity seed it was handed, and the certificate it renews. */
    val renewals = mutableListOf<Pair<ByteArray, ByteArray>>()

    override fun renew(
        identitySeed: ByteArray,
        card: ByteArray,
        deviceSeed: ByteArray,
        cert: ByteArray,
    ): ByteArray {
        renewals += identitySeed.copyOf() to cert
        return holderRenew(identitySeed, card, deviceSeed, cert)
    }

    /** Each backup the registrar was asked for, as what and the registrar. */
    val backups = mutableListOf<Pair<String, String>>()

    /** What the registrar answers the next backup asked for, if not that it is done. */
    var backupFails: CoreException? = null

    private fun backedUp(
        what: String,
        registrar: String,
    ) {
        backupFails?.let {
            backupFails = null
            throw it
        }
        backups += what to registrar
    }

    override suspend fun putPassphrase(
        identitySeed: ByteArray,
        registrar: String,
        passphrase: String,
    ) {
        if (passphrase.trim().length < 10) throw CoreException.Refused("bad_passphrase", "")
        backedUp("passphrase $passphrase", registrar)
    }

    override suspend fun deleteBackup(
        identitySeed: ByteArray,
        registrar: String,
        kind: SecretKind,
    ) = backedUp("delete $kind", registrar)

    val newCodes = mutableListOf<FakeRecoveryCode>()

    override fun newRecoveryCode() = FakeRecoveryCode().also { newCodes += it }

    val sessions = mutableListOf<FakeSession>()

    /** What the next session's opening throws, if anything. */
    var openFails: CoreException? = null

    /** Held open until completed, where set: a session opened while the model waits. */
    var opening: CompletableDeferred<Unit>? = null

    override suspend fun openSession(
        mailbox: String,
        card: ByteArray,
    ): CertifySession {
        opening?.await()
        openFails?.let {
            openFails = null
            throw it
        }
        return FakeSession(mailbox, card).also { sessions += it }
    }

    class Revocation(
        val seed: ByteArray,
        val registrar: String,
        val device: ByteArray,
        val reason: RevokeReason,
        val until: Long,
    )

    val revocations = mutableListOf<Revocation>()

    /** What the next revocation throws, if anything, the registrar's answer not had. */
    var revokeFails: CoreException? = null

    /** Called as each revocation reaches the registrar. */
    var onRevoke: () -> Unit = {}

    override suspend fun revoke(
        identitySeed: ByteArray,
        registrar: String,
        device: ByteArray,
        reason: RevokeReason,
        until: Long,
        thisDevice: ByteArray,
    ) {
        yield()
        if (device.contentEquals(thisDevice)) throw CoreException.Refused("own_device", "")
        onRevoke()
        revokeFails?.let {
            revokeFails = null
            throw it
        }
        revocations += Revocation(identitySeed, registrar, device, reason, until)
    }

    override fun deviceFingerprint(device: ByteArray) = deviceFingerprintOf(device)

    /** A session at a mailbox: what a device asks it, and how it ends, the test's; answered once, as the core's. */
    inner class FakeSession(
        val mailbox: String,
        val card: ByteArray,
    ) : CertifySession {
        /** The request a device makes, or what the mailbox ends the wait with. */
        val next = CompletableDeferred<HolderRequest>()

        /** Each certificate's seed, as handed (the model's to wipe), and whether it lets the device manage. */
        val approvals = mutableListOf<Pair<ByteArray, Boolean>>()
        val denials = mutableListOf<String>()
        var delivered = false
        var canceled = false
        var closed = false
        private var asked: HolderRequest? = null
        private var certified = false

        /** Called as the certificate is made. */
        var onCertify: () -> Unit = {}

        /** Called as the certificate is sent. */
        var onDeliver: () -> Unit = {}

        /** What the next sends throw, in turn, before one goes through. */
        val deliverFails = ArrayDeque<CoreException>()

        /** Each send tried. */
        var sends = 0
        private var maybeDelivered = false

        override fun mayHaveDelivered() = delivered || maybeDelivered

        /** Completed when the request asked about can no longer be answered. */
        val ends = CompletableDeferred<Unit>()

        override suspend fun answerEnds() = ends.await()

        /** The device certified: its key and when its certificate ends. */
        val device = ByteArray(32) { 7 }
        val expires = 2_000_000_000uL

        override fun code() = "K7PM-QX2D"

        override fun identity() = "3f2a8c1d"

        override fun host() = mailbox

        override fun expiresIn() = 600uL

        override fun qr() = null

        override suspend fun nextRequest(): HolderRequest {
            check(!closed) { "a closed session called" }
            return next.await().also { asked = it }
        }

        private fun answerable() {
            if (canceled) throw CoreException.Refused("canceled", "")
            if (certified || denials.isNotEmpty()) throw CoreException.Refused("used", "")
        }

        override suspend fun certify(
            identitySeed: ByteArray,
            manage: Boolean,
            device: ByteArray,
        ): Certified {
            yield()
            answerable()
            if (!device.contentEquals(checkNotNull(asked).device)) throw CoreException.Refused("not_asked", "")
            certified = true
            onCertify()
            approvals += identitySeed to manage
            return Certified(device, checkNotNull(asked).name, manage, expires)
        }

        /** Called as a send is begun, before anything is checked. */
        var beforeDeliver: () -> Unit = {}

        override suspend fun deliver() {
            beforeDeliver()
            yield()
            if (canceled) throw CoreException.Refused("canceled", "")
            if (!certified) throw CoreException.Refused("nothing_certified", "")
            if (delivered) throw CoreException.Refused("used", "")
            sends++
            deliverFails.removeFirstOrNull()?.let {
                // As the core reckons it: all but the mailbox's refusals before it stores an answer,
                // and a rate limit, may have arrived.
                val beforeStored =
                    (it is CoreException.Refused && it.code in setOf("expired", "bad_request", "request_too_large")) ||
                        it is CoreException.RateLimited
                if (!beforeStored) maybeDelivered = true
                throw it
            }
            onDeliver()
            delivered = true
        }

        override suspend fun deny(reason: String) {
            yield()
            answerable()
            denials += reason
        }

        override fun cancel() {
            canceled = true
            if (!next.isCompleted) next.completeExceptionally(CoreException.Refused("canceled", ""))
        }

        override fun close() {
            closed = true
        }
    }

    inner class FakeRecoveryCode : NewRecoveryCode {
        val code = "NEWRC-0DE00-00000-00002"
        private var confirmed = false
        var closed = false

        override fun code() = code.toByteArray().takeIf { !confirmed }?.also { codes += it }

        override fun confirm(typed: ByteArray) = (String(typed) == code).also { confirmed = confirmed || it }

        override suspend fun put(
            identitySeed: ByteArray,
            registrar: String,
        ) {
            if (!confirmed) throw CoreException.Refused("unconfirmed", "")
            backedUp("recovery", registrar)
        }

        override fun close() {
            closed = true
        }
    }

    inner class FakeSetup(
        private val identity: NewIdentity,
        /** The registrar and handle it was resumed as, for a setup finished again. */
        val resumed: Pair<String, String>?,
    ) : Setup {
        private var successor: String? = if (resumed == null) "SUCCE-SSORC-ODE00" else null
        val recovery = "RECOV-ERYCO-DE000-00001"
        private var recoveryConfirmed = false
        private var minted = resumed != null
        private var held = resumed != null
        var closed = false
        val commits = mutableListOf<Triple<String, String, String?>>()

        /** Each commit's answer in turn: a refusal, or null to commit. */
        val answers = ArrayDeque<CoreException?>()

        /** Called as each commit is answered for. */
        var onCommit: () -> Unit = {}

        override fun card() = identity.card

        override suspend fun commit(
            registrar: String,
            handle: String,
            invite: String?,
        ): HolderCommitted {
            check(!closed) { "a closed setup called" }
            // As the core's: answered later, not as it is asked.
            yield()
            if (!held) throw CoreException.Refused("unheld", "")
            commits += Triple(registrar, handle, invite)
            onCommit()
            answers.removeFirstOrNull()?.let { throw it }
            return HolderCommitted(identity.card)
        }

        override fun confirmRecovery(typed: ByteArray) = (String(typed) == recovery).also { recoveryConfirmed = recoveryConfirmed || it }

        override fun confirmSuccessor(typed: ByteArray) =
            (successor != null && String(typed) == successor).also { if (it) successor = null }

        override fun fingerprint() = identity.fingerprint

        override fun held() {
            if (!minted) throw CoreException.Refused("unminted", "")
            held = true
        }

        override fun identitySeed(): ByteArray {
            if (successor != null || !recoveryConfirmed) throw CoreException.Refused("unconfirmed", "")
            return identity.seed.copyOf().also { handed += it }
        }

        override fun mint(deviceName: String): org.foggyden.hexline.core.HolderMinted {
            if (successor != null || !recoveryConfirmed) throw CoreException.Refused("unconfirmed", "")
            // As the core does: a device minted again is not yet the one held.
            held = false
            return holderMint(identity.seed, identity.card, deviceName).also { minted = true }
        }

        override fun recoveryCode() = recovery.toByteArray().takeIf { !recoveryConfirmed }?.also { codes += it }

        override fun successorCode() = successor?.toByteArray()?.also { codes += it }

        override fun close() {
            closed = true
        }
    }
}
