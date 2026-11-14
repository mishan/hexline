package org.foggyden.hexline.identity

import android.content.Context
import android.util.AtomicFile
import android.util.Base64
import org.foggyden.hexline.core.CertInfo
import org.foggyden.hexline.core.certForDevice
import org.foggyden.hexline.core.certInfo
import org.foggyden.hexline.core.shortHash
import org.foggyden.hexline.secrets.SecretStore
import org.foggyden.hexline.secrets.SecretUnavailable
import org.foggyden.hexline.secrets.SecretUnreadable
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException

/** An identity this phone is a device of: what a server is shown, and what the core read of it. */
class StoredIdentity(
    val handle: String?,
    val cert: ByteArray,
    val card: ByteArray,
    val info: CertInfo,
) {
    /** The identity, in the form the core gives it: the only one to pass back. */
    val fingerprint: String get() = info.fingerprint
}

/**
 * The identities this phone is a device of. Each is its device's seed, a
 * secret in the [SecretStore] named by the identity and the device, and a
 * file named by the identity alone: the certificate, the card, the handle,
 * and the device's public keys, which say whose seed it is.
 *
 * Certificate and card are checked by the core, against the device, before
 * anything is written and whenever they are read back, so a file altered
 * or planted lists as nothing. Only [seed] unwraps a seed, as a login needs
 * it.
 *
 * Calls block on the Keystore and the disk: not on the main thread. The
 * store is for one process, as [SecretStore] is: a second (a push service
 * of its own) would need a lock across processes.
 */
class Identities(
    context: Context,
    private val secrets: SecretStore = SecretStore(context),
    private val dir: File = File(context.filesDir, "identities"),
) {
    init {
        dir.mkdirs()
    }

    /**
     * Keeps [seed] with [cert] and [card], in place of whatever device was
     * kept for the same identity. Throws the core's refusal if they do not
     * hold for that seed, [SecretUnavailable] if the Keystore cannot take
     * it now. The caller wipes [seed].
     */
    fun save(
        seed: ByteArray,
        cert: ByteArray,
        card: ByteArray,
        handle: String?,
    ): StoredIdentity =
        synchronized(LOCK) {
            val info = certForDevice(cert, card, seed)
            val file = file(info.fingerprint)
            val before = load(file)
            // The new device's seed under a name of its own, then the file
            // that points at it, then the old one's seed: a crash anywhere
            // leaves one whole device or the other.
            val secret = secretName(info.fingerprint, info.device)
            secrets.put(secret, seed)
            val stored = StoredIdentity(handle?.ifEmpty { null }, cert, card, info)
            write(file, stored)
            before?.let { old ->
                secretName(old.fingerprint, old.info.device).takeIf { it != secret }?.let(secrets::delete)
            }
            stored
        }

    /** Every identity kept whose certificate and card still hold. */
    fun list(): List<StoredIdentity> =
        synchronized(LOCK) {
            // On API 29 a write cut short leaves only `.bak`, which reading
            // the plain name restores.
            dir
                .listFiles()
                .orEmpty()
                .map { it.name.removeSuffix(".bak") }
                .filter { !it.contains('.') }
                .distinct()
                .mapNotNull { load(File(dir, it)) }
        }

    /**
     * [fingerprint]'s identity and its device's seed, read together so the
     * seed is the device the certificate is for, or null if none is kept.
     * One that will never open is forgotten with its identity; one the
     * Keystore cannot open now is [SecretUnavailable], and still there. The
     * caller wipes the seed.
     */
    fun device(fingerprint: String): Pair<StoredIdentity, ByteArray>? =
        synchronized(LOCK) {
            val stored = load(file(fingerprint)) ?: return null
            val secret = secretName(stored.fingerprint, stored.info.device)
            try {
                secrets.get(secret)?.let { stored to it }
            } catch (_: SecretUnreadable) {
                delete(fingerprint)
                null
            }
        }

    fun delete(fingerprint: String): Unit =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file)
            AtomicFile(file).delete()
            stored?.let { secrets.delete(secretName(it.fingerprint, it.info.device)) }
        }

    /** What a file holds, if it is whole and the core says it holds. */
    private fun load(file: File): StoredIdentity? {
        val bytes =
            try {
                AtomicFile(file).readFully()
            } catch (_: FileNotFoundException) {
                return null
            }
        return try {
            val json = JSONObject(String(bytes))
            val info =
                certInfo(
                    unb64(json.getString("cert")),
                    unb64(json.getString("card")),
                    unb64(json.getString("device")),
                    unb64(json.getString("device_enc")),
                )
            // The file a fingerprint names holds that identity's device only.
            if (file(info.fingerprint).name != file.name) return null
            StoredIdentity(json.optString("handle").ifEmpty { null }, unb64(json.getString("cert")), unb64(json.getString("card")), info)
        } catch (_: Exception) {
            null
        }
    }

    private fun write(
        file: File,
        stored: StoredIdentity,
    ) {
        val json =
            JSONObject()
                .put("cert", b64(stored.cert))
                .put("card", b64(stored.card))
                .put("device", b64(stored.info.device))
                .put("device_enc", b64(stored.info.deviceEnc))
                .apply { stored.handle?.let { put("handle", it) } }
        val atomic = AtomicFile(file)
        val out = atomic.startWrite()
        try {
            out.write(json.toString().toByteArray())
            atomic.finishWrite(out)
        } catch (e: Exception) {
            atomic.failWrite(out)
            throw e
        }
    }

    /** Names from the identity, and the device: never anything typed. */
    private fun file(fingerprint: String) = File(dir, "identity-" + shortHash(fingerprint.toByteArray()))

    private fun secretName(
        fingerprint: String,
        device: ByteArray,
    ) = "device-" + shortHash(fingerprint.toByteArray()) + "-" + shortHash(device)

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)

    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)

    private companion object {
        /** One for the process: AtomicFile is not safe for two writers of one name. */
        val LOCK = Any()
    }
}
