package org.foggyden.hexline.identity

import org.foggyden.hexline.core.HeldRestore
import org.foggyden.hexline.core.HolderSetup
import org.foggyden.hexline.core.HolderSetupInterface
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.checkHolderRegistrar
import org.foggyden.hexline.core.restoreIdentityToHold

/** A holder's setup the model drives (the core's, or a test's), closed to wipe it. */
interface Setup :
    HolderSetupInterface,
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
}

private class CoreSetup(
    private val setup: HolderSetup,
) : Setup,
    HolderSetupInterface by setup {
    override fun close() = setup.close()
}
