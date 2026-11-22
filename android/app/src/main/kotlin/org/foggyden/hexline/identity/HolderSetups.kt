package org.foggyden.hexline.identity

import org.foggyden.hexline.core.HeldRestore
import org.foggyden.hexline.core.HolderKept
import org.foggyden.hexline.core.HolderSession
import org.foggyden.hexline.core.HolderSessionInterface
import org.foggyden.hexline.core.HolderSetup
import org.foggyden.hexline.core.HolderSetupInterface
import org.foggyden.hexline.core.PostOutcome
import org.foggyden.hexline.core.RecoveryCodeSetup
import org.foggyden.hexline.core.RecoveryCodeSetupInterface
import org.foggyden.hexline.core.RevokeReason
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.backupDelete
import org.foggyden.hexline.core.backupPassphrase
import org.foggyden.hexline.core.checkHolderRegistrar
import org.foggyden.hexline.core.deviceFingerprintOf
import org.foggyden.hexline.core.heldFloor
import org.foggyden.hexline.core.holderRenew
import org.foggyden.hexline.core.openHolderSession
import org.foggyden.hexline.core.restoreIdentityToHold
import org.foggyden.hexline.core.revokeDevice

/** A holder's setup the model drives (the core's, or a test's), closed to wipe it. */
interface Setup :
    HolderSetupInterface,
    AutoCloseable

/** A new recovery code the model drives, closed to wipe it. */
interface NewRecoveryCode :
    RecoveryCodeSetupInterface,
    AutoCloseable

/** Where holder setups and holding restores come from: the core, or a test standing in for it. */
interface HolderSetups {
    /** A new identity, named [name]. */
    fun new(name: String): Setup

    /** A setup this phone holds the seed of, kept unfinished, committed again (the core's `resume`). */
    fun resume(
        identitySeed: ByteArray,
        card: ByteArray,
        registrar: String,
        handle: String,
        deviceSeed: ByteArray,
        deviceCert: ByteArray,
    ): Setup

    /** Throws the core's refusal unless [name] makes a certificate a server reads. */
    fun checkDeviceName(name: String)

    /** Throws the core's refusal unless [registrar] can take a holder's identity. */
    suspend fun check(registrar: String)

    suspend fun restoreToHold(
        registrar: String,
        handle: String,
        kind: SecretKind,
        secret: String,
        deviceName: String,
    ): HeldRestore

    /** A new certificate for this phone's device (the core's `holder_renew`), [epoch] the device epoch kept. */
    fun renew(
        identitySeed: ByteArray,
        card: ByteArray,
        deviceSeed: ByteArray,
        cert: ByteArray,
        epoch: Long,
    ): ByteArray

    suspend fun putPassphrase(
        identitySeed: ByteArray,
        registrar: String,
        passphrase: String,
    )

    suspend fun deleteBackup(
        identitySeed: ByteArray,
        registrar: String,
        kind: SecretKind,
    )

    fun newRecoveryCode(): NewRecoveryCode

    /** A session at [mailbox] to certify another device for the identity whose card is [card], of which this phone keeps [kept]. */
    suspend fun openSession(
        mailbox: String,
        card: ByteArray,
        kept: HolderKept,
    ): CertifySession

    /** [device] revoked at [registrar] by the identity's key, for [reason], its certificate ending at [until]. */
    suspend fun revoke(
        identitySeed: ByteArray,
        registrar: String,
        device: ByteArray,
        reason: RevokeReason,
        until: Long,
        thisDevice: ByteArray,
    )

    /** [device]'s key as a holder's prompt shows it. */
    fun deviceFingerprint(device: ByteArray): String

    /** The highest device epoch the core has learned for the identity whose card is [card] (the core's `held_floor`). */
    fun floor(card: ByteArray): Long

    /** A rotation's [record], as signed, posted to [registrar]'s records. */
    suspend fun postRotation(
        registrar: String,
        record: ByteArray,
    ): PostOutcome
}

object CoreHolderSetups : HolderSetups {
    override fun new(name: String): Setup = CoreSetup(HolderSetup(name))

    override fun resume(
        identitySeed: ByteArray,
        card: ByteArray,
        registrar: String,
        handle: String,
        deviceSeed: ByteArray,
        deviceCert: ByteArray,
    ): Setup = CoreSetup(HolderSetup.resume(identitySeed, card, registrar, handle, deviceSeed, deviceCert))

    override fun checkDeviceName(name: String) =
        org.foggyden.hexline.core
            .checkDeviceName(name)

    override suspend fun check(registrar: String) = checkHolderRegistrar(registrar)

    override suspend fun restoreToHold(
        registrar: String,
        handle: String,
        kind: SecretKind,
        secret: String,
        deviceName: String,
    ) = restoreIdentityToHold(registrar, handle, kind, secret, deviceName)

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
    ) = backupPassphrase(identitySeed, registrar, passphrase)

    override suspend fun deleteBackup(
        identitySeed: ByteArray,
        registrar: String,
        kind: SecretKind,
    ) = backupDelete(identitySeed, registrar, kind)

    override fun newRecoveryCode(): NewRecoveryCode = CoreRecoveryCode(RecoveryCodeSetup())

    override suspend fun openSession(
        mailbox: String,
        card: ByteArray,
        kept: HolderKept,
    ): CertifySession = CoreSession(openHolderSession(mailbox, card, kept))

    override suspend fun revoke(
        identitySeed: ByteArray,
        registrar: String,
        device: ByteArray,
        reason: RevokeReason,
        until: Long,
        thisDevice: ByteArray,
    ) = revokeDevice(identitySeed, registrar, device, reason, until.toULong(), thisDevice)

    override fun deviceFingerprint(device: ByteArray) = deviceFingerprintOf(device)

    override fun floor(card: ByteArray) = heldFloor(card).toLong()

    override suspend fun postRotation(
        registrar: String,
        record: ByteArray,
    ) = org.foggyden.hexline.core
        .postRotation(registrar, record)
}

private class CoreSession(
    private val session: HolderSession,
) : CertifySession,
    HolderSessionInterface by session {
    override fun close() = session.close()
}

private class CoreRecoveryCode(
    private val code: RecoveryCodeSetup,
) : NewRecoveryCode,
    RecoveryCodeSetupInterface by code {
    override fun close() = code.close()
}

private class CoreSetup(
    private val setup: HolderSetup,
) : Setup,
    HolderSetupInterface by setup {
    override fun close() = setup.close()
}
