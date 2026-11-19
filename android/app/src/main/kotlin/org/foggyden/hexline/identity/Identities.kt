package org.foggyden.hexline.identity

import android.content.Context
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import android.util.Base64
import android.util.Log
import org.foggyden.hexline.core.CertInfo
import org.foggyden.hexline.core.certForDevice
import org.foggyden.hexline.core.certInfo
import org.foggyden.hexline.core.deviceFingerprintOf
import org.foggyden.hexline.core.shortHash
import org.foggyden.hexline.secrets.SecretStore
import org.foggyden.hexline.secrets.SecretUnavailable
import org.foggyden.hexline.secrets.SecretUnreadable
import org.foggyden.hexline.secrets.Secrets
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException

/**
 * An identity this phone is a device of: what a server is shown, and what
 * the core read of it. Changed by [copy], so a field added here is kept by
 * every write that does not mean to change it; [Identities.save] alone
 * makes one anew, and carries over what a successor keeps.
 */
data class StoredIdentity(
    val handle: String?,
    val cert: ByteArray,
    val card: ByteArray,
    val info: CertInfo,
    /** Where it was restored from, to renew it at. */
    val registrar: String? = null,
    /** The mailbox its holder certified it through, to renew it at. */
    val mailbox: String? = null,
    /** When a quiet renewal was last asked for, in seconds; 0 for never. */
    val renewTried: Long = 0,
    /** That renewal found no holder standing by: a code is to be asked for. */
    val noHolder: Boolean = false,
    /**
     * A holder's setup not known to be committed at its registrar (design
     * §2.1): the seed is held, and [handle] at [registrar] is still to be
     * registered, with the recovery code, to resume it by.
     */
    val unfinished: Boolean = false,
    /**
     * A holder's setup whose key went before it was committed: it can be
     * neither finished nor restored, and works as this phone's device
     * alone until its certificate ends.
     */
    val unrecoverable: Boolean = false,
    /** This phone holds the identity's key: never kept, the model says so as it reads the store. */
    val held: Boolean = false,
    /**
     * The identity this one is the successor of, while that rotation is
     * unfinished: the model neither publishes it, so it is offered to sign
     * in with or renew nowhere, nor demotes it.
     */
    val rotatingFrom: String? = null,
    /** The rotation record that made it a successor, shown at each identity login. */
    val rotation: ByteArray? = null,
) {
    /** As held here, the model's word for it. */
    fun held(): StoredIdentity = copy(held = true)

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
    private val secrets: Secrets = SecretStore(context),
    private val dir: File = File(context.filesDir, "identities"),
    /** How [dir]'s entries are synced to the disk: a test's may not, where no directory opens. */
    private val syncDir: (File) -> Unit = ::syncDirectory,
    /** How a file is written whole: a test's may say it wrote what the disk did not keep. */
    private val commit: (File, ByteArray) -> Unit = ::writeAtomically,
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
        registrar: String?,
        mailbox: String? = null,
        unfinished: Boolean = false,
        rotatingFrom: String? = null,
        rotation: ByteArray? = null,
    ): StoredIdentity =
        synchronized(LOCK) {
            val info = certForDevice(cert, card, seed)
            // A successor is kept only once its rotation's file names it, so a
            // start finds it to discard if nothing was sent.
            check(rotatingFrom == null || rotation(rotatingFrom).read?.to == info.fingerprint) { "no rotation names it" }
            val file = file(info.fingerprint)
            val before = load(file)
            // The new device's seed under a name of its own, then the file
            // that points at it, then the old one's seed: a crash anywhere
            // leaves one whole device or the other.
            val secret = secretName(info.fingerprint, info.device)
            secrets.put(secret, seed)
            val stored =
                StoredIdentity(
                    handle?.ifEmpty { null },
                    cert,
                    card,
                    info,
                    registrar?.ifEmpty { null },
                    mailbox?.ifEmpty { null },
                    unfinished = unfinished,
                    // A new device of a successor, as a renewal makes, is still one.
                    rotatingFrom = rotatingFrom ?: before?.rotatingFrom,
                    rotation = rotation ?: before?.rotation,
                )
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
                .filter { it.startsWith("identity-") && !it.contains('.') }
                .distinct()
                // In one order whatever the file system lists them in.
                .sorted()
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

    /**
     * Notes a quiet renewal of [fingerprint]'s certificate [cert] asked for
     * [at], and whether a holder stood by to answer it; nothing if another
     * certificate has taken its place since, the same device's included.
     */
    fun renewTried(
        fingerprint: String,
        cert: ByteArray,
        at: Long,
        noHolder: Boolean,
    ): Unit =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file)?.takeIf { it.cert.contentEquals(cert) } ?: return
            write(file, stored.copy(renewTried = at, noHolder = noHolder))
        }

    /** [fingerprint]'s unfinished setup now to be committed as [handle]; nothing once it is finished. */
    fun intends(
        fingerprint: String,
        handle: String,
    ): Unit =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file)?.takeIf { it.unfinished } ?: return
            write(file, stored.copy(handle = handle))
        }

    /**
     * [fingerprint]'s device certified again: [cert] in place of
     * [replacing], the certificate the renewal began from, and no renewal
     * through a mailbox tried since; as it was in all else. Throws the
     * core's refusal if it is not that device's under the identity's card;
     * null, writing nothing, if the identity is no longer kept or another
     * certificate has taken [replacing]'s place since.
     */
    fun renewed(
        fingerprint: String,
        cert: ByteArray,
        replacing: ByteArray,
    ): StoredIdentity? =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file)?.takeIf { it.cert.contentEquals(replacing) } ?: return null
            val info = certInfo(cert, stored.card, stored.info.device, stored.info.deviceEnc)
            stored.copy(cert = cert, info = info, renewTried = 0, noHolder = false).also { write(file, it) }
        }

    /** [fingerprint]'s setup, its key gone before it was committed: no longer to be finished. */
    fun unrecoverable(fingerprint: String): Unit =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file)?.takeIf { it.unfinished } ?: return
            write(file, stored.copy(unfinished = false, unrecoverable = true))
        }

    /**
     * [fingerprint]'s setup committed as [handle]: [card], the card its
     * registrar attested, in place of the one kept. Throws the core's
     * refusal if it is not that identity's card for the device; null if the
     * identity is no longer kept.
     */
    fun committed(
        fingerprint: String,
        card: ByteArray,
        handle: String,
    ): StoredIdentity? =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file) ?: return null
            val info = certInfo(stored.cert, card, stored.info.device, stored.info.deviceEnc)
            stored
                .copy(
                    handle = handle,
                    card = card,
                    info = info,
                    renewTried = 0,
                    noHolder = false,
                    unfinished = false,
                    unrecoverable = false,
                ).also { write(file, it) }
        }

    /**
     * [fingerprint], a successor, now the identity: [card], the card its
     * registrars attested, in place of the one kept, and the rotation it
     * came by no longer unfinished. Throws the core's refusal if it is not
     * that identity's card for the device; null if it is not kept.
     */
    fun rotated(
        fingerprint: String,
        card: ByteArray,
    ): StoredIdentity? =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file) ?: return null
            val info = certInfo(stored.cert, card, stored.info.device, stored.info.deviceEnc)
            stored.copy(card = card, info = info, rotatingFrom = null).also {
                write(file, it)
                // In the same call, so no rotation is left that a start could take for one under way.
                stored.rotatingFrom?.takeIf { from -> rotation(from).read?.to == fingerprint }?.let { from ->
                    AtomicFile(rotationFile(from)).delete()
                }
            }
        }

    /** The rotation of [from]'s identity under way, as last kept: none, one that does not read, or it. */
    fun rotation(from: String): FoundRotation =
        synchronized(LOCK) {
            val bytes =
                try {
                    AtomicFile(rotationFile(from)).readFully()
                } catch (_: FileNotFoundException) {
                    return FoundRotation.None
                }
            KeptRotation.decode(bytes)?.takeIf { it.from == from }?.let(FoundRotation::Read) ?: FoundRotation.Unreadable
        }

    /**
     * [rotation] kept whole in place of the one before, and read back: one
     * the disk does not give back as written is an [java.io.IOException],
     * so the step after it is not taken. [IllegalStateException] for one
     * that would write over a file that does not read, unsend one sent or
     * move it to another successor or record, or be sent while its
     * successor is not kept: a start may have discarded it.
     */
    fun keep(rotation: KeptRotation): Unit =
        synchronized(LOCK) {
            when (val found = rotation(rotation.from)) {
                FoundRotation.Unreadable -> error("a rotation's file that does not read is not written over")
                is FoundRotation.Read ->
                    if (found.rotation.state == RotationState.Sent) {
                        check(
                            rotation.state == RotationState.Sent &&
                                rotation.to == found.rotation.to &&
                                rotation.record.contentEquals(found.rotation.record),
                        ) { "a rotation sent is only finished" }
                    }
                FoundRotation.None -> {}
            }
            if (rotation.state == RotationState.Sent) {
                check(load(file(rotation.to))?.rotatingFrom == rotation.from) { "its successor is not kept" }
            }
            val file = rotationFile(rotation.from)
            val bytes = rotation.encode()
            commit(file, bytes)
            if (!AtomicFile(file).readFully().contentEquals(bytes)) throw java.io.IOException("rotation not kept")
            // So a power cut cannot take the rename back, and the rotation with it to before it was sent.
            if (rotation.state == RotationState.Sent) syncDir(dir)
        }

    /**
     * The rotation of [from]'s identity let go of: discarded before it was
     * sent. [IllegalStateException] for one that may have been sent while a
     * successor waits on it: [rotated] lets go of that one.
     */
    fun forgetRotation(from: String): Unit =
        synchronized(LOCK) {
            check(forgettable(from)) { "a rotation sent is only finished" }
            AtomicFile(rotationFile(from)).delete()
        }

    /** Whether [from]'s rotation can go: nothing waits on it, or it was never sent. */
    private fun forgettable(from: String): Boolean {
        val found = rotation(from)
        return list().none { it.rotatingFrom == from } ||
            found == FoundRotation.None ||
            (found as? FoundRotation.Read)?.rotation?.state?.let { it != RotationState.Sent } == true
    }

    /**
     * The successors a start is to discard, with their holds, each beside
     * its predecessor: each whose rotation was never sent, whose rotation's
     * file is gone or names another, and each a rotation's unsent file
     * names that is not kept as an identity at all, its hold alone left.
     * Nothing it signed left the phone, and a successor's key beside its
     * predecessor's behind one screen lock would hand whoever unlocks the
     * phone both. A file there that does not read discards nothing: it may
     * say the rotation was sent.
     */
    fun unsentRotations(): List<Pair<String, String>> =
        synchronized(LOCK) {
            val kept = list()
            val successors = kept.filter { it.rotatingFrom != null }
            val orphans =
                successors.filter { k ->
                    when (val found = rotation(k.rotatingFrom!!)) {
                        FoundRotation.None -> true
                        FoundRotation.Unreadable -> false.also { Log.w(TAG, "a rotation's file does not read: its successor is kept") }
                        is FoundRotation.Read -> found.rotation.to != k.fingerprint || found.rotation.state != RotationState.Sent
                    }
                }
            val unkept =
                rotationFiles()
                    .mapNotNull { file ->
                        KeptRotation.decode(AtomicFile(file).readFully()).also {
                            if (it == null) Log.w(TAG, "a rotation's file does not read: kept")
                        }
                    }.filter { r -> r.state != RotationState.Sent && kept.none { it.fingerprint == r.to } }
            (orphans.map { it.rotatingFrom!! to it.fingerprint } + unkept.map { it.from to it.to }).distinct()
        }

    private fun rotationFiles() =
        dir
            .listFiles()
            .orEmpty()
            .map { it.name.removeSuffix(".bak") }
            .filter { it.startsWith("rotation-") && !it.contains('.') }
            .distinct()
            .map { File(dir, it) }

    /**
     * [successor], [from]'s, discarded, its hold already let go of: its
     * identity, if it is that successor, then [from]'s rotation's file, if
     * that names it and was never sent.
     */
    fun discardRotation(
        from: String,
        successor: String,
    ): Unit =
        synchronized(LOCK) {
            if (load(file(successor))?.rotatingFrom == from) delete(successor)
            (rotation(from).read)?.takeIf { it.to == successor && it.state != RotationState.Sent }?.let { forgetRotation(from) }
        }

    /**
     * The devices [fingerprint]'s key certified on this phone, as it keeps
     * them, its own device apart: public keys and names, nothing secret. A
     * list that does not read is moved aside, kept for whoever can make
     * sense of it, rather than written over, and [mintedUnreadable] says so
     * from then on. Throws an [java.io.IOException] the disk gives.
     */
    fun minted(fingerprint: String): List<MintedDevice> =
        synchronized(LOCK) {
            val file = mintedFile(fingerprint)
            val bytes =
                try {
                    AtomicFile(file).readFully()
                } catch (e: FileNotFoundException) {
                    // One that is there and will not open is the disk's trouble, not an empty list.
                    if (file.exists()) throw e
                    return emptyList()
                }
            try {
                val list = JSONArray(String(bytes))
                (0 until list.length()).map { i ->
                    val json = list.getJSONObject(i)
                    val device = unb64(json.getString("device"))
                    MintedDevice(
                        device,
                        deviceFingerprintOf(device),
                        json.optString("name").ifEmpty { null },
                        json.getLong("expires"),
                        json.optBoolean("manage"),
                        json.optBoolean("revoked"),
                        revoking = json.optBoolean("revoking"),
                    )
                }
            } catch (e: Exception) {
                // What was read did not parse: the disk's own trouble is the caller's.
                if (e is java.io.IOException) throw e
                aside(file, bytes)
                emptyList()
            }
        }

    /** [fingerprint]'s lists of devices kept aside as unread, let go of. */
    fun discardUnread(fingerprint: String): Unit = synchronized(LOCK) { unread(fingerprint).forEach { it.delete() } }

    /** Whether a list of [fingerprint]'s devices did not read and was kept aside: what it said is not known here. */
    fun mintedUnreadable(fingerprint: String): Boolean = synchronized(LOCK) { unread(fingerprint).isNotEmpty() }

    /** [bytes], [file]'s, under a name of their own beside any kept before, and then [file] gone. */
    private fun aside(
        file: File,
        bytes: ByteArray,
    ) {
        var n = 0
        while (File(dir, "${file.name}.unread-$n").exists()) n++
        val copy = File(dir, "${file.name}.unread-$n")
        commit(copy, bytes)
        // The original goes only once its copy is known to be there.
        if (!AtomicFile(copy).readFully().contentEquals(bytes)) throw java.io.IOException("not set aside")
        AtomicFile(file).delete()
    }

    private fun unread(fingerprint: String) =
        dir.listFiles().orEmpty().filter { it.name.startsWith(mintedFile(fingerprint).name + ".unread-") }

    /**
     * [device] certified by [fingerprint]'s key, in place of any it certified
     * before for the same key. Read back once written: one the list does not
     * hold, whatever the write said (a rename that did not land), is an
     * [java.io.IOException]. That says nothing of the data reaching the disk.
     */
    fun minted(
        fingerprint: String,
        given: MintedDevice,
        now: Long,
    ): Unit =
        synchronized(LOCK) {
            // An empty name kept as none, as it reads back.
            val device =
                given.name?.takeIf { it.isEmpty() }?.let {
                    MintedDevice(
                        given.device,
                        given.fingerprint,
                        null,
                        given.expires,
                        given.canManage,
                        given.revoked,
                        given.own,
                        given.revoking,
                    )
                } ?: given
            // A certificate past [now] is let go of as the list is written, a revoked one kept.
            val live = minted(fingerprint).filter { it.listed(now) }
            writeMinted(fingerprint, live.filter { !it.device.contentEquals(device.device) } + device)
            if (minted(fingerprint).none { it == device }) throw java.io.IOException("not kept")
        }

    private fun writeMinted(
        fingerprint: String,
        devices: List<MintedDevice>,
    ) {
        val list = JSONArray()
        for (d in devices) {
            list.put(
                JSONObject()
                    .put("device", b64(d.device))
                    .put("expires", d.expires)
                    .apply {
                        d.name?.let { put("name", it) }
                        if (d.canManage) put("manage", true)
                        if (d.revoked) put("revoked", true)
                        if (d.revoking) put("revoking", true)
                    },
            )
        }
        commit(mintedFile(fingerprint), list.toString().toByteArray())
    }

    /** Lists of devices, and copies set aside, kept for an identity no longer here: let go of. */
    fun sweepOrphans(): Unit =
        synchronized(LOCK) {
            val identities =
                dir
                    .list()
                    .orEmpty()
                    .map { it.removeSuffix(".bak") }
                    .filter { it.startsWith("identity-") }
                    .toSet()
            for (file in dir.listFiles().orEmpty()) {
                // Only a name this store gives a list, or a copy of one set aside.
                val hash = MINTED.matchEntire(file.name)?.groupValues?.get(1) ?: continue
                if ("identity-$hash" !in identities) file.delete()
            }
            // A rotation sent whose successor is the identity now: one a finish cut short left.
            val kept = list()
            for (file in rotationFiles()) {
                val r = runCatching { KeptRotation.decode(AtomicFile(file).readFully()) }.getOrNull() ?: continue
                if (r.state == RotationState.Sent &&
                    kept.any { it.fingerprint == r.to && it.rotatingFrom == null }
                ) {
                    AtomicFile(file).delete()
                }
            }
        }

    fun delete(fingerprint: String): Unit =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file)
            AtomicFile(mintedFile(fingerprint)).delete()
            unread(fingerprint).forEach { it.delete() }
            AtomicFile(file).delete()
            // Its own rotation goes with it, but not one a successor waits on.
            if (forgettable(fingerprint)) AtomicFile(rotationFile(fingerprint)).delete()
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
            StoredIdentity(
                json.optString("handle").ifEmpty { null },
                unb64(json.getString("cert")),
                unb64(json.getString("card")),
                info,
                json.optString("registrar").ifEmpty { null },
                json.optString("mailbox").ifEmpty { null },
                json.optLong("renew_tried"),
                json.optBoolean("no_holder"),
                json.optBoolean("unfinished"),
                json.optBoolean("unrecoverable"),
                rotatingFrom = json.optString("rotating_from").ifEmpty { null },
                rotation = json.optString("rotation").ifEmpty { null }?.let(::unb64),
            )
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
                .apply {
                    stored.handle?.let { put("handle", it) }
                    stored.registrar?.let { put("registrar", it) }
                    stored.mailbox?.let { put("mailbox", it) }
                    if (stored.renewTried != 0L) put("renew_tried", stored.renewTried)
                    if (stored.noHolder) put("no_holder", true)
                    if (stored.unfinished) put("unfinished", true)
                    if (stored.unrecoverable) put("unrecoverable", true)
                    stored.rotatingFrom?.let { put("rotating_from", it) }
                    stored.rotation?.let { put("rotation", b64(it)) }
                }
        commit(file, json.toString().toByteArray())
    }

    /** Names from the identity, and the device: never anything typed. */
    private fun file(fingerprint: String) = File(dir, "identity-" + shortHash(fingerprint.toByteArray()))

    private fun mintedFile(fingerprint: String) = File(dir, "minted-" + shortHash(fingerprint.toByteArray()))

    private fun rotationFile(from: String) = File(dir, "rotation-" + shortHash(from.toByteArray()))

    private fun secretName(
        fingerprint: String,
        device: ByteArray,
    ) = "device-" + shortHash(fingerprint.toByteArray()) + "-" + shortHash(device)

    private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)

    private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)

    private companion object {
        /** One for the process: AtomicFile is not safe for two writers of one name. */
        val LOCK = Any()

        const val TAG = "hexline"

        val MINTED = Regex("minted-([0-9a-f]{24})(\\.unread-[0-9]+)?(\\.bak|\\.new)?")
    }
}

/** [dir]'s entries to the disk, as [AtomicFile] syncs a file's contents but not its rename. */
fun syncDirectory(dir: File) {
    try {
        val fd = Os.open(dir.path, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    } catch (e: ErrnoException) {
        throw java.io.IOException("not synced", e)
    }
}

/** [bytes] written as [file] whole, or not at all, as [AtomicFile] writes. */
fun writeAtomically(
    file: File,
    bytes: ByteArray,
) {
    val atomic = AtomicFile(file)
    val out = atomic.startWrite()
    try {
        out.write(bytes)
        atomic.finishWrite(out)
    } catch (e: Exception) {
        atomic.failWrite(out)
        throw e
    }
}
