package org.foggyden.hexline.identity

import android.content.Context
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import android.util.Base64
import android.util.Log
import org.foggyden.hexline.core.CertInfo
import org.foggyden.hexline.core.KeptRotation
import org.foggyden.hexline.core.RotationState
import org.foggyden.hexline.core.WholeRead
import org.foggyden.hexline.core.certForDevice
import org.foggyden.hexline.core.certInfo
import org.foggyden.hexline.core.decodeRotation
import org.foggyden.hexline.core.deviceFingerprintOf
import org.foggyden.hexline.core.encodeRotation
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
     * This phone's own device key is known revoked, as the core is told and
     * has read: never kept, the model says so as it reads the store, and only
     * a new device is certified for it.
     */
    val ownRevoked: Boolean = false,
    /**
     * The identity this one is the successor of, while that rotation is
     * unfinished: the model neither publishes it, so it is offered to sign
     * in with or renew nowhere, nor renews it quietly, nor demotes it.
     */
    val rotatingFrom: String? = null,
    /** The rotation record that made it a successor, shown at each identity login. */
    val rotation: ByteArray? = null,
    /**
     * The highest device epoch learned for it: what a holder mints at
     * while it cannot ask its registrars, a cache they correct. Only rises.
     */
    val epoch: Long = 0,
    /** This phone's last reset of the identity's devices, as far as it knows it. */
    val reset: ResetKept? = null,
) {
    /** As held here, the model's word for it. */
    fun held(): StoredIdentity = copy(held = true)

    /** The identity, in the form the core gives it: the only one to pass back. */
    val fingerprint: String get() = info.fingerprint
}

/**
 * A reset of an identity's devices made here: its epoch, what is left to
 * post later and when, and the registrars it has not reached. Kept so a
 * reset that a registrar has not taken is never shown as one it has.
 */
data class ResetKept(
    /** The epoch reset to (the core's `DevicesReset.epoch`); 0 before one has come back. */
    val epoch: Long = 0,
    /** What `retry_reset` posts to [pending], opaque; null with nothing to post. */
    val retry: ByteArray? = null,
    /** When [retry] is next worth posting, in seconds. */
    val retryAt: Long = 0,
    /** Registrars [retry] is kept for, by the address the core named them by. */
    val pending: List<String> = emptyList(),
    /** Registrars the reset is not at and no retry will reach: only a new reset does. */
    val unreset: List<String> = emptyList(),
    /** Of the registrars no retry will reach, those retried until they were given up on. */
    val givenUp: List<String> = emptyList(),
    /** Registrars whose list shows the reset, as each said: never taken from one missing elsewhere. */
    val done: List<String> = emptyList(),
    /** Registrars another holder's reset went past this one at, as each said. */
    val overtaken: List<String> = emptyList(),
    /** Origins that answered as no registrar, as each did. */
    val notRegistrars: List<String> = emptyList(),
    /**
     * When a reset was begun whose outcome is not kept: it may have posted
     * anything, so the screen offers another. Null when none is.
     */
    val underWay: Long? = null,
    /** Part of what was kept did not read: a reset may not have finished, as with [underWay]. */
    val unread: Boolean = false,
) {
    /** Whether a reset may have gone further than this phone knows. */
    val uncertain: Boolean get() = underWay != null || unread
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
                    epoch = maxOf(info.epoch.toLong(), before?.epoch ?: 0),
                    // A reset is the identity's: another device of it here still has one to finish.
                    reset = before?.reset,
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
            stored
                .copy(cert = cert, info = info, renewTried = 0, noHolder = false, epoch = maxOf(stored.epoch, info.epoch.toLong()))
                .also { write(file, it) }
        }

    /**
     * The device epoch to mint [stored]'s certificates at: its own, or one a
     * device certified for it here was certified in, listed or let go of,
     * whichever is higher, so a floor written to the list and not yet to
     * the identity is not lost.
     */
    fun epoch(stored: StoredIdentity): Long =
        synchronized(LOCK) {
            // At least the epoch of each device certified here, its entry let go of or not.
            val listed =
                try {
                    val kept = kept(stored.fingerprint)
                    maxOf(kept.devices.maxOfOrNull { it.epoch } ?: 0, kept.certified.maxOfOrNull { it.second } ?: 0)
                } catch (_: java.io.IOException) {
                    0
                }
            // And of its own certificate, which a reset mints past the floor before the floor is written.
            maxOf(stored.epoch, listed, stored.info.epoch.toLong())
        }

    /** [fingerprint]'s device epoch raised to [epoch], learned from its registrars; nothing if it is not kept or knew it. */
    fun learned(
        fingerprint: String,
        epoch: Long,
    ): Unit =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file)?.takeIf { it.epoch < epoch } ?: return
            write(file, stored.copy(epoch = epoch))
        }

    /**
     * A reset of [fingerprint]'s devices begun at [at], before anything is
     * posted: its last whole read let go of first, so no read from before
     * the reset waives a check while the reset's outcome is unknown, then
     * the reset noted as under way, unless an earlier one whose outcome is
     * unknown is noted already: it may still have posted. Whether this
     * noted it, or null, with nothing begun, if the identity is not kept;
     * throws an [java.io.IOException] the disk gives.
     */
    fun resetBegun(
        fingerprint: String,
        at: Long,
    ): Boolean? =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file) ?: return null
            val kept = kept(fingerprint)
            if (kept.read != null) writeMinted(fingerprint, Kept(kept.devices, kept.seen, kept.certified, null))
            if (stored.reset?.underWay != null) return false
            write(file, stored.copy(reset = (stored.reset ?: ResetKept()).copy(underWay = at)))
            true
        }

    /** [fingerprint]'s reset, which [resetBegun] noted, noted as under way no longer: it was refused before anything was posted. */
    fun resetNotBegun(fingerprint: String): Unit =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file) ?: return
            val reset = stored.reset?.takeIf { it.underWay != null } ?: return
            write(file, stored.copy(reset = reset.copy(underWay = null).takeIf { it != ResetKept() }))
        }

    /**
     * What [fingerprint]'s reset came to, in one write: [reset] in place of
     * whatever was kept of an earlier one, and [cert], this phone's own
     * certificate minted again by it, in place of [replacing] or of one
     * below it, a renewal that raced the reset being minted below the
     * floor. One installed meanwhile at the reset's epoch or past it
     * stands. The epoch is left to the floor's own writer. Throws the
     * core's refusal if [cert] is not this device's; null, writing
     * nothing, if the identity is not kept.
     */
    fun resetDone(
        fingerprint: String,
        cert: ByteArray,
        replacing: ByteArray,
        reset: ResetKept,
    ): StoredIdentity? =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file) ?: return null
            val info = certInfo(cert, stored.card, stored.info.device, stored.info.deviceEnc)
            val swap = stored.cert.contentEquals(replacing) || stored.info.epoch < info.epoch
            val cleared = reset.copy(underWay = null, unread = false)
            val done =
                if (swap) {
                    stored.copy(cert = cert, info = info, renewTried = 0, noHolder = false, reset = cleared)
                } else {
                    stored.copy(reset = cleared)
                }
            done.also { write(file, it) }
        }

    /**
     * What a retry of [fingerprint]'s reset to [epoch] came to, as [change]
     * makes it of what is kept: only while that reset is the one kept, so a
     * retry outliving a newer reset writes nothing over it, and never for
     * an identity no longer kept. Throws an [java.io.IOException] the disk
     * gives.
     */
    fun retried(
        fingerprint: String,
        epoch: Long,
        change: (ResetKept) -> ResetKept,
    ): Unit =
        synchronized(LOCK) {
            val file = file(fingerprint)
            val stored = load(file) ?: return
            val reset = stored.reset?.takeIf { epoch != 0L && it.epoch == epoch } ?: return
            write(file, stored.copy(reset = change(reset)))
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
     * that identity's card for the device, an [java.io.IOException] if the
     * disk does not give it back as written; null if it is not kept.
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
                // Its rotation goes only once the disk holds the identity it made, or a
                // start would find a successor with no rotation, and discard it.
                val back = load(file)
                if (back == null || back.rotatingFrom != null || !back.card.contentEquals(card)) {
                    throw java.io.IOException("identity not kept")
                }
                syncDir(dir)
                // In the same call, so no rotation is left that a start could take for one under way.
                stored.rotatingFrom?.takeIf { from -> rotation(from).read?.to == fingerprint }?.let { from ->
                    AtomicFile(rotationFile(from)).delete()
                }
            }
        }

    /** The rotation of [from]'s identity under way, as last kept: none, one that does not read, or it. */
    fun rotation(from: String): FoundRotation =
        synchronized(LOCK) {
            val file = rotationFile(from)
            if (!file.exists() && !File(file.path + ".bak").exists()) return FoundRotation.None
            val bytes =
                try {
                    AtomicFile(file).readFully()
                } catch (_: java.io.IOException) {
                    // There, and not to be opened or read: what it says is not known.
                    return FoundRotation.Unreadable
                }
            decodeRotation(bytes)?.takeIf { it.from == from }?.let(FoundRotation::Read) ?: FoundRotation.Unreadable
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
                    if (found.rotation.state == RotationState.SENT) {
                        check(
                            rotation.state == RotationState.SENT &&
                                rotation.to == found.rotation.to &&
                                rotation.record.contentEquals(found.rotation.record),
                        ) { "a rotation sent is only finished" }
                    }
                FoundRotation.None -> {}
            }
            if (rotation.state == RotationState.SENT) {
                check(load(file(rotation.to))?.rotatingFrom == rotation.from) { "its successor is not kept" }
            }
            val file = rotationFile(rotation.from)
            val bytes = encodeRotation(rotation)
            commit(file, bytes)
            if (!AtomicFile(file).readFully().contentEquals(bytes)) throw java.io.IOException("rotation not kept")
            // So a power cut cannot take the rename back, and the rotation with it to before it was sent.
            if (rotation.state == RotationState.SENT) syncDir(dir)
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
            (found as? FoundRotation.Read)?.rotation?.state?.let { it != RotationState.SENT } == true
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
                        is FoundRotation.Read -> found.rotation.to != k.fingerprint || found.rotation.state != RotationState.SENT
                    }
                }
            val unkept =
                rotationFiles()
                    .mapNotNull { file ->
                        // One file that will not open keeps its own rotation, and no other.
                        runCatching { AtomicFile(file).readFully() }.getOrNull()?.let(::decodeRotation).also {
                            if (it == null) Log.w(TAG, "a rotation's file does not read: kept")
                        }
                    }.filter { r -> r.state != RotationState.SENT && kept.none { it.fingerprint == r.to } }
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
            (rotation(from).read)?.takeIf { it.to == successor && it.state != RotationState.SENT }?.let { forgetRotation(from) }
        }

    /**
     * The devices [fingerprint]'s key certified on this phone, as it keeps
     * them, its own device apart: public keys and names, nothing secret. A
     * list that does not read is moved aside, kept for whoever can make
     * sense of it, rather than written over, and [mintedUnreadable] says so
     * from then on. Throws an [java.io.IOException] the disk gives.
     */
    fun minted(fingerprint: String): List<MintedDevice> = synchronized(LOCK) { kept(fingerprint).devices }

    /** [fingerprint]'s last whole read of its records, kept with its list; null if never, or it does not read. */
    fun lastRead(fingerprint: String): WholeRead? = synchronized(LOCK) { kept(fingerprint).read }

    /**
     * Every key a read of [fingerprint]'s records ever showed revoked, listed
     * here or not: the list's, and what can still be read of each copy of
     * it set aside, which counts until it is discarded.
     */
    fun seenRevoked(fingerprint: String): List<ByteArray> =
        synchronized(LOCK) {
            val copies = unread(fingerprint).map { salvaged(it) }
            distinct(kept(fingerprint).seen + copies.flatMap { c -> c.seen + c.revoked.map { it.device } })
        }

    /** Every key [fingerprint]'s key ever certified here, with the epoch it was certified at, the copies set aside counted too. */
    fun everCertified(fingerprint: String): List<Pair<ByteArray, Long>> =
        synchronized(LOCK) { kept(fingerprint).certified + unread(fingerprint).flatMap { salvaged(it).certified } }

    /**
     * What [fingerprint]'s list file holds: its devices, the keys seen
     * revoked, every key certified here with its epoch, and the last whole
     * read. The last three only ever grow.
     */
    private class Kept(
        val devices: List<MintedDevice>,
        val seen: List<ByteArray> = emptyList(),
        val certified: List<Pair<ByteArray, Long>> = emptyList(),
        val read: WholeRead? = null,
    )

    private fun distinct(keys: List<ByteArray>) = keys.distinctBy { it.toList() }

    /** [fingerprint]'s list file, as [minted] reads it. */
    private fun kept(fingerprint: String): Kept {
        val file = mintedFile(fingerprint)
        val bytes =
            try {
                AtomicFile(file).readFully()
            } catch (e: FileNotFoundException) {
                // One that is there and will not open is the disk's trouble, not an empty list.
                if (file.exists()) throw e
                return Kept(emptyList())
            }
        return try {
            val text = String(bytes)
            // The list alone, as it was first written, or with what reads of the records found beside it.
            if (text.trimStart().startsWith("[")) {
                Kept(JSONArray(text).let { list -> (0 until list.length()).map { device(list.getJSONObject(it)) } })
            } else {
                val json = JSONObject(text)
                val list = json.getJSONArray("devices")
                val (seen, seenWhole) = keys(json, "revoked")
                val (certified, certifiedWhole) = certified(json, "certified")
                // Part of the evidence not reading sets the file aside, where what does read still counts.
                if (!seenWhole || !certifiedWhole) error("evidence that does not read")
                val devices = (0 until list.length()).map { device(list.getJSONObject(it)) }
                Kept(devices, seen, certified, wholeRead(json.optJSONObject("read")))
            }
        } catch (e: Exception) {
            // What was read did not parse: the disk's own trouble is the caller's.
            if (e is java.io.IOException) throw e
            aside(file, bytes)
            Kept(emptyList())
        }
    }

    /** The keys [json] holds under [name] that read, and whether all of them did: none held, or one not a list, being none read. */
    private fun keys(
        json: JSONObject,
        name: String,
    ): Pair<List<ByteArray>, Boolean> {
        val array = json.optJSONArray(name) ?: return emptyList<ByteArray>() to !json.has(name)
        val keys = (0 until array.length()).mapNotNull { i -> key { array.getString(i) } }
        return keys to (keys.size == array.length())
    }

    /** The keys certified here [json] holds under [name] that read, each with its epoch, and whether all of them did. */
    private fun certified(
        json: JSONObject,
        name: String,
    ): Pair<List<Pair<ByteArray, Long>>, Boolean> {
        val array = json.optJSONArray(name) ?: return emptyList<Pair<ByteArray, Long>>() to !json.has(name)
        val keys =
            (0 until array.length()).mapNotNull { i ->
                val entry = array.optJSONObject(i)
                entry?.let { e -> key { e.getString("device") }?.let { it to e.optLong("epoch") } }
            }
        return keys to (keys.size == array.length())
    }

    /** The key [read] gives, if it is one. */
    private fun key(read: () -> String): ByteArray? =
        try {
            unb64(read()).takeIf { it.size == 32 }
        } catch (_: Exception) {
            null
        }

    /** A whole read as kept; one that does not read is none, which stands in for nothing. */
    private fun wholeRead(json: JSONObject?): WholeRead? =
        try {
            json?.let { r ->
                val registrars = r.getJSONArray("registrars")
                WholeRead(
                    r.getLong("at").toULong(),
                    r.getLong("uptime").toULong(),
                    r.getString("boot"),
                    (0 until registrars.length()).map { registrars.getString(it) },
                    r.getLong("floor").toULong(),
                )
            }
        } catch (_: org.json.JSONException) {
            null
        }

    private fun device(json: JSONObject): MintedDevice {
        val device = unb64(json.getString("device"))
        return MintedDevice(
            device,
            deviceFingerprintOf(device),
            json.optString("name").ifEmpty { null },
            json.getLong("expires"),
            json.optBoolean("manage"),
            json.optBoolean("revoked"),
            epoch = json.optLong("epoch"),
        )
    }

    /**
     * [fingerprint]'s lists of devices kept aside as unread, let go of once
     * what can still be read of them is in the list, in one write and read
     * back: each device revoked in them, at the higher epoch where the list
     * has it too, each key seen revoked, a listed device among them marked,
     * and each key certified. The copies stay where the list does not hold
     * it all after.
     */
    fun discardUnread(fingerprint: String): Unit =
        synchronized(LOCK) {
            // Only the copies read here go: one the list is set aside into meanwhile was not.
            val copies = unread(fingerprint)
            val salvaged = copies.map { salvaged(it) }
            val carried = salvaged.flatMap { it.revoked }
            val seen = distinct(salvaged.flatMap { it.seen })
            val certified = salvaged.flatMap { it.certified }
            // The floor a copy's whole read saw goes to the identity, where floors are kept: not
            // as a whole read to stand in by, which it no longer is.
            // So is the epoch of each device it certified: the floor was that high then.
            val floor = salvaged.maxOfOrNull { s -> maxOf(s.floor, s.certified.maxOfOrNull { it.second } ?: 0) } ?: 0
            if (floor > 0) {
                learned(fingerprint, floor)
                if ((load(file(fingerprint))?.epoch ?: 0) < floor) throw java.io.IOException("the floor set aside not kept")
            }
            if (carried.isNotEmpty() || seen.isNotEmpty() || certified.isNotEmpty()) {
                val kept = kept(fingerprint)
                if (unread(fingerprint).size != copies.size) throw java.io.IOException("the list was set aside meanwhile")
                val revokedKeys = carried.map { it.device } + seen
                val marked =
                    kept.devices.map { d ->
                        val epoch = maxOf(d.epoch, carried.filter { it.device.contentEquals(d.device) }.maxOfOrNull { it.epoch } ?: 0)
                        val revoked = d.revoked || revokedKeys.any { it.contentEquals(d.device) }
                        MintedDevice(d.device, d.fingerprint, d.name, d.expires, d.canManage, revoked, d.own, epoch)
                    }
                val more =
                    carried
                        .filter { c -> kept.devices.none { it.device.contentEquals(c.device) } }
                        .groupBy { it.fingerprint }
                        .map { (_, same) -> same.maxBy { it.epoch } }
                val after = Kept(marked + more, distinct(kept.seen + seen), joined(kept.certified, certified), kept.read)
                writeMinted(fingerprint, after)
                val back = kept(fingerprint)
                val held =
                    revokedKeys.all { k ->
                        back.devices.any { it.revoked && it.device.contentEquals(k) } ||
                            back.seen.any { it.contentEquals(k) }
                    } &&
                        seen.all { k -> back.seen.any { it.contentEquals(k) } } &&
                        certified.all { (k, _) -> back.certified.any { it.first.contentEquals(k) } }
                if (!held) throw java.io.IOException("what was set aside not kept")
            }
            copies.forEach { it.delete() }
        }

    /** [a] and [b], each key once at the higher epoch either gives it. */
    private fun joined(
        a: List<Pair<ByteArray, Long>>,
        b: List<Pair<ByteArray, Long>>,
    ) = (a + b).groupBy { it.first.toList() }.map { (_, same) -> same.maxBy { it.second } }

    /** Whether a list of [fingerprint]'s devices did not read and was kept aside: what it said is not known here. */
    fun mintedUnreadable(fingerprint: String): Boolean = synchronized(LOCK) { unread(fingerprint).isNotEmpty() }

    /** Whether part of a list of [fingerprint]'s devices kept aside cannot be read at all: a device revoked there would be let go of. */
    fun unreadLoses(fingerprint: String): Boolean = synchronized(LOCK) { unread(fingerprint).any { !salvaged(it).whole } }

    /**
     * What a list set aside still says that can be read: the devices revoked
     * in it, the keys seen revoked, every key certified with its epoch (its
     * devices' too), and whether all of those could.
     */
    private class Salvaged(
        val revoked: List<MintedDevice>,
        val seen: List<ByteArray>,
        val certified: List<Pair<ByteArray, Long>>,
        val whole: Boolean,
        /** The floor its whole read saw, where that reads. */
        val floor: Long = 0,
    )

    /** What [copy], a list set aside, still says that can be read. */
    private fun salvaged(copy: File): Salvaged {
        var seen: Pair<List<ByteArray>, Boolean> = emptyList<ByteArray>() to true
        var certified: Pair<List<Pair<ByteArray, Long>>, Boolean> = emptyList<Pair<ByteArray, Long>>() to true
        var floor = 0L
        val list =
            try {
                val text = String(AtomicFile(copy).readFully())
                if (text.trimStart().startsWith("[")) {
                    JSONArray(text)
                } else {
                    val json = JSONObject(text)
                    seen = keys(json, "revoked")
                    certified = certified(json, "certified")
                    floor = wholeRead(json.optJSONObject("read"))?.floor?.toLong() ?: 0
                    json.getJSONArray("devices")
                }
            } catch (_: Exception) {
                return Salvaged(emptyList(), seen.first, certified.first, false, floor)
            }
        var whole = seen.second && certified.second
        val devices =
            (0 until list.length()).mapNotNull { i ->
                val json = list.optJSONObject(i)
                val device = json?.let { j -> key { j.getString("device") } }
                if (device == null) whole = false
                device?.let { it to json }
            }
        // Only the key, its epoch and that it was revoked matter: a revoked one is never certified again.
        val revoked =
            devices.filter { (_, json) -> json.optBoolean("revoked") }.map { (device, json) ->
                MintedDevice(device, deviceFingerprintOf(device), null, json.optLong("expires"), false, true, epoch = json.optLong("epoch"))
            }
        val all = certified.first + devices.map { (device, json) -> device to json.optLong("epoch") }
        return Salvaged(revoked, seen.first, all, whole, floor)
    }

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
     * before for the same key; revoked if either is, as a key revoked is
     * never certified again, and its key kept as certified here for good.
     * Read back once written: one the list does not hold, whatever the
     * write said (a rename that did not land), is an [java.io.IOException].
     * That says nothing of the data reaching the disk.
     */
    fun minted(
        fingerprint: String,
        given: MintedDevice,
        now: Long,
    ): Unit =
        synchronized(LOCK) {
            val kept = kept(fingerprint)
            val all = kept.devices
            val before = all.find { it.device.contentEquals(given.device) }
            // A key is never certified again in a lower epoch than its listed one: a lower one
            // given is an entry read before the latest, and the floor that one lists is kept.
            val epoch = maxOf(given.epoch, before?.epoch ?: 0)
            // An empty name kept as none, as it reads back.
            val device =
                MintedDevice(
                    given.device,
                    given.fingerprint,
                    given.name?.ifEmpty { null },
                    given.expires,
                    given.canManage,
                    given.revoked || before?.revoked == true,
                    given.own,
                    epoch,
                )
            // The list may hold the only copy of a floor, after a crash between its write and the
            // identity's: the identity takes it before an entry holding it can go.
            val floor = (all + device).maxOf { it.epoch }
            val raised =
                try {
                    learned(fingerprint, floor)
                    // Kept only if the identity holds it now: one whose file does not read takes nothing.
                    load(file(fingerprint))?.let { it.epoch >= floor } == true
                } catch (e: java.io.IOException) {
                    Log.w(TAG, "device epoch $floor not kept with the identity", e)
                    false
                }
            // A certificate past [now] is let go of as the list is written, a revoked one kept, and
            // one holding a floor kept nowhere else. Its key stays among those certified here.
            val live = all.filter { it.listed(now) || (!raised && it.epoch == floor) }
            val certified = joined(kept.certified + all.map { it.device to it.epoch }, listOf(device.device to epoch))
            writeMinted(
                fingerprint,
                Kept(live.filter { !it.device.contentEquals(device.device) } + device, kept.seen, certified, kept.read),
            )
            if (minted(fingerprint).none { it == device }) throw java.io.IOException("not kept")
        }

    /**
     * What a read of [fingerprint]'s records found, in one write: each key of
     * [revoked] kept as seen revoked for good, listed here or not, each
     * listed device of them marked revoked, and [whole], where the read was
     * whole, kept as its last. Throws an [java.io.IOException] the disk gives.
     */
    fun recordsRead(
        fingerprint: String,
        whole: WholeRead?,
        revoked: List<ByteArray>,
    ): Unit =
        synchronized(LOCK) {
            val kept = kept(fingerprint)
            val all = kept.devices
            val marked = all.map { d -> if (!d.revoked && revoked.any { it.contentEquals(d.device) }) d.with(revoked = true) else d }
            val seen = distinct(kept.seen + revoked)
            if (marked == all && seen.size == kept.seen.size && whole == null) return
            writeMinted(fingerprint, Kept(marked, seen, kept.certified, whole ?: kept.read))
            val back = kept(fingerprint)
            if (!revoked.all { k -> back.seen.any { it.contentEquals(k) } }) throw java.io.IOException("not kept")
        }

    /**
     * [fingerprint]'s last whole read let go of, so it stands in for
     * nothing: for a read whose revocations could not be kept, which an
     * older read predates. Throws an [java.io.IOException] the disk gives.
     */
    fun forgetRead(fingerprint: String): Unit =
        synchronized(LOCK) {
            val kept = kept(fingerprint)
            if (kept.read != null) writeMinted(fingerprint, Kept(kept.devices, kept.seen, kept.certified, null))
        }

    private fun writeMinted(
        fingerprint: String,
        kept: Kept,
    ) {
        val list = JSONArray()
        for (d in kept.devices) {
            list.put(
                JSONObject()
                    .put("device", b64(d.device))
                    .put("expires", d.expires)
                    .apply {
                        d.name?.let { put("name", it) }
                        if (d.canManage) put("manage", true)
                        if (d.revoked) put("revoked", true)
                        if (d.epoch != 0L) put("epoch", d.epoch)
                    },
            )
        }
        val json = JSONObject().put("devices", list)
        if (kept.seen.isNotEmpty()) json.put("revoked", JSONArray(kept.seen.map(::b64)))
        if (kept.certified.isNotEmpty()) {
            json.put("certified", JSONArray(kept.certified.map { (k, e) -> JSONObject().put("device", b64(k)).put("epoch", e) }))
        }
        kept.read?.let { r ->
            json.put(
                "read",
                JSONObject()
                    .put("at", r.at.toLong())
                    .put("uptime", r.uptime.toLong())
                    .put("boot", r.boot)
                    .put("registrars", JSONArray(r.registrars))
                    .put("floor", r.floor.toLong()),
            )
        }
        commit(mintedFile(fingerprint), json.toString().toByteArray())
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
                val r = runCatching { decodeRotation(AtomicFile(file).readFully()) }.getOrNull() ?: continue
                if (r.state == RotationState.SENT &&
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
                epoch = json.optLong("epoch"),
                reset = json.opt("reset")?.let(::resetOf),
            )
        } catch (_: Exception) {
            null
        }
    }

    /**
     * A reset as kept, each part read apart: what does not read is told as
     * [ResetKept.unread] rather than as no reset, so the screen says one may
     * not have finished.
     */
    private fun resetOf(value: Any): ResetKept {
        val json = value as? JSONObject ?: return ResetKept(unread = true)
        var unread = false

        fun <T> part(
            name: String,
            none: T,
            read: () -> T,
        ): T {
            if (!json.has(name)) return none
            return try {
                read()
            } catch (_: Exception) {
                unread = true
                none
            }
        }

        fun names(name: String) =
            part(name, emptyList()) {
                val list = json.getJSONArray(name)
                (0 until list.length()).map { list.getString(it) }
            }
        val reset =
            ResetKept(
                epoch = part("epoch", 0L) { json.getLong("epoch") },
                retry = part("retry", null) { unb64(json.get("retry") as String) },
                retryAt = part("retry_at", 0L) { json.getLong("retry_at") },
                pending = names("pending"),
                unreset = names("unreset"),
                givenUp = names("given_up"),
                done = names("done"),
                overtaken = names("overtaken"),
                notRegistrars = names("not_registrars"),
                underWay = part("under_way", null) { json.getLong("under_way") },
            )
        return reset.copy(unread = unread || json.optBoolean("unread"))
    }

    private fun resetJson(reset: ResetKept) =
        JSONObject().apply {
            if (reset.epoch != 0L) put("epoch", reset.epoch)
            reset.retry?.let { put("retry", b64(it)) }
            if (reset.retryAt != 0L) put("retry_at", reset.retryAt)
            if (reset.pending.isNotEmpty()) put("pending", JSONArray(reset.pending))
            if (reset.unreset.isNotEmpty()) put("unreset", JSONArray(reset.unreset))
            if (reset.givenUp.isNotEmpty()) put("given_up", JSONArray(reset.givenUp))
            if (reset.done.isNotEmpty()) put("done", JSONArray(reset.done))
            if (reset.overtaken.isNotEmpty()) put("overtaken", JSONArray(reset.overtaken))
            if (reset.notRegistrars.isNotEmpty()) put("not_registrars", JSONArray(reset.notRegistrars))
            reset.underWay?.let { put("under_way", it) }
            if (reset.unread) put("unread", true)
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
                    if (stored.epoch != 0L) put("epoch", stored.epoch)
                    stored.reset?.let { put("reset", resetJson(it)) }
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
