package org.foggyden.hexline.chat

import kotlinx.coroutines.yield
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.HeldRestore
import org.foggyden.hexline.core.HolderCommitted
import org.foggyden.hexline.core.NewIdentity
import org.foggyden.hexline.core.Restored
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.certForDevice
import org.foggyden.hexline.core.holderMint
import org.foggyden.hexline.core.holderRenew
import org.foggyden.hexline.core.newIdentity
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
