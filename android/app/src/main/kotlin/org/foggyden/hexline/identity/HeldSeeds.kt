package org.foggyden.hexline.identity

import android.util.AtomicFile
import android.util.Log
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.foggyden.hexline.core.shortHash
import org.foggyden.hexline.secrets.Authorizer
import org.foggyden.hexline.secrets.HeldKeyLost
import org.foggyden.hexline.secrets.HolderKeys
import org.foggyden.hexline.secrets.SoftwareKeysOnly
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.util.UUID
import kotlin.coroutines.CoroutineContext

/**
 * The identity seeds this phone holds (holder mode, design §2.1), each
 * sealed by a Key B of its own and opened only for one operation the
 * person has just allowed. A seed is never kept open: [use] hands it to
 * its block and fills it with zeros after.
 *
 * Each sealing is under a new key, whose alias the sealed file names: a
 * seed held again is written whole before the key it replaces goes, so a
 * hold refused, canceled or cut short leaves the one before as it was.
 *
 * A Key B is gone for good once the screen lock is removed, and its seed
 * with it. [demoteLost] notices that, on the Keystore's positive word
 * alone, and lets the identity go back to being a device here, as an
 * envelope-restored one is, keeping a notice until the person has read
 * it; holding it again means restoring it from its recovery code. There
 * is no half-held identity.
 *
 * [io] is where the Keystore and the disk are worked; the [Authorizer] is
 * called from the caller's own context, which for the real prompt is the
 * main thread. What one fingerprint's files and keys are is changed under
 * one lock, so two holds, or a hold and a demotion, never cross.
 */
class HeldSeeds(
    private val dir: File,
    private val keys: HolderKeys,
    private val io: CoroutineContext,
    private val softwareKeys: Boolean = false,
    private val readBack: (AtomicFile) -> ByteArray = AtomicFile::readFully,
) {
    init {
        dir.mkdirs()
    }

    fun isHeld(fingerprint: String) = synchronized(LOCK) { runCatching { sealed(fingerprint) }.getOrNull() != null }

    /**
     * Holds [seed] for [fingerprint], in place of any held before. False if
     * the person did not allow it; [org.foggyden.hexline.secrets.NoScreenLock]
     * without a screen lock, and [SoftwareKeysOnly] where the Keystore keeps
     * keys in software alone, unless [softwareKeys]. The caller wipes [seed].
     */
    suspend fun hold(
        fingerprint: String,
        seed: ByteArray,
        authorizer: Authorizer,
    ): Boolean {
        val alias = prefix(fingerprint) + UUID.randomUUID().toString().replace("-", "")
        synchronized(LOCK) { pending += alias }
        var kept = false
        try {
            val seal =
                withContext(io) {
                    made(alias)
                    keys.begin(alias, null)
                }
            if (!authorizer.allow(seal)) return false
            withContext(io) {
                val (iv, sealed) = seal.run(seed)
                synchronized(LOCK) {
                    val before = runCatching { sealed(fingerprint) }.getOrNull()?.alias
                    try {
                        write(file(fingerprint), encode(alias, iv, sealed))
                    } catch (e: UnsureWrite) {
                        // The file may name either key, so both stay, for the sweep to settle.
                        kept = true
                        throw e
                    }
                    kept = true
                    before?.takeIf { it != alias }?.let(keys::delete)
                }
            }
            return true
        } finally {
            withContext(NonCancellable + io) {
                synchronized(LOCK) {
                    pending -= alias
                    if (!kept) runCatching { keys.delete(alias) }
                }
            }
        }
    }

    /**
     * Whether this phone could hold a seed now, asking the person nothing:
     * a key made and let go of at once. [org.foggyden.hexline.secrets.NoScreenLock],
     * [SoftwareKeysOnly] or [org.foggyden.hexline.secrets.HolderUnsupported]
     * if not. Blocks on the Keystore.
     */
    fun probe() {
        val alias = ALIAS + "probe-" + UUID.randomUUID().toString().replace("-", "")
        synchronized(LOCK) { pending += alias }
        try {
            made(alias)
        } finally {
            synchronized(LOCK) {
                pending -= alias
                runCatching { keys.delete(alias) }
            }
        }
    }

    private fun made(alias: String) {
        keys.create(alias)
        // A key in software is no better than a file the app could read; only a debug
        // build, for the emulator, holds a seed behind one.
        if (!softwareKeys && keys.security(alias) == "software") throw SoftwareKeysOnly()
    }

    /**
     * [block] run with [fingerprint]'s seed, once the person has allowed it,
     * the seed wiped after: null if they did not, or nothing is held.
     * [HeldKeyLost] if its key is gone.
     */
    suspend fun <T> use(
        fingerprint: String,
        authorizer: Authorizer,
        block: suspend (ByteArray) -> T,
    ): T? {
        val found = withContext(io) { synchronized(LOCK) { sealed(fingerprint) } } ?: return null
        val seal = withContext(io) { keys.begin(found.alias, found.iv) }
        if (!authorizer.allow(seal)) return null
        var seed: ByteArray? = null
        try {
            // Kept in reach of the wipe even if this is canceled as it returns.
            withContext(io) { seed = seal.run(found.sealed).second }
            return block(checkNotNull(seed))
        } finally {
            seed?.fill(0)
        }
    }

    /**
     * The held identities among [fingerprints] whose key is gone (or whose
     * screen lock is), let go of: each kept as a device alone, with a notice
     * for the person. Asks the person nothing. An identity the Keystore
     * cannot answer for now is left as it is, to be asked again.
     */
    fun demoteLost(fingerprints: List<String>): List<String> =
        fingerprints.filter { fp ->
            try {
                synchronized(LOCK) { demote(fp) }
            } catch (e: Exception) {
                Log.w(TAG, "a held identity left unchecked: ${e.javaClass.simpleName}")
                false
            }
        }

    private fun demote(fingerprint: String): Boolean {
        val held = sealed(fingerprint) ?: return false
        if (keys.secureLock() && !keys.gone(held.alias)) return false
        // The notice first, so a demotion cut short is told and done again.
        write(AtomicFile(File(dir, notice(fingerprint))), fingerprint.toByteArray())
        keys.delete(held.alias)
        file(fingerprint).delete()
        return true
    }

    /**
     * Lets go of every key no held file names (a hold cut short by the
     * process's end leaves one), once the held files here are listed and the
     * keys are; of nothing otherwise. A file not read, or not naming a key
     * its own name allows (a write cut short leaves only its `.new`), spares
     * every key its name's hash is in the alias of. A held file is never let
     * go of here: one whose identity is not kept may be the only copy of an
     * identity key, so only [forget] lets one go.
     */
    fun sweep() =
        synchronized(LOCK) {
            try {
                val files = dir.listFiles() ?: throw IOException("held seeds not listed")
                val named = HashSet<String>()
                val unsure = HashSet<String>()
                for (name in files.map { it.name.substringBefore('.') }.filter { it.startsWith("held-") }.distinct()) {
                    val hash = name.removePrefix("held-")
                    try {
                        val alias = decode(AtomicFile(File(dir, name)).readFully()).alias
                        named += alias
                        if (!alias.startsWith("$ALIAS$hash-")) unsure += hash
                    } catch (_: Exception) {
                        unsure += hash
                    }
                }
                for (alias in keys.aliases(ALIAS)) {
                    if (alias in named || alias in pending || alias.removePrefix(ALIAS).substringBefore('-') in unsure) continue
                    keys.delete(alias)
                }
            } catch (e: Exception) {
                Log.w(TAG, "held keys left to sweep: ${e.javaClass.simpleName}")
            }
        }

    /** The identities let go of whose notice the person has not yet put away. */
    fun notices(): List<String> =
        dir
            .listFiles()
            .orEmpty()
            .filter { it.name.startsWith("lost-") && !it.name.contains('.') }
            .mapNotNull { runCatching { String(AtomicFile(it).readFully()) }.getOrNull() }
            .sorted()

    fun dismiss(fingerprint: String) {
        AtomicFile(File(dir, notice(fingerprint))).delete()
    }

    /**
     * Lets [fingerprint]'s seed go, with its keys: for an identity the person
     * deleted. [IOException] if the Keystore will not let go of one now.
     */
    fun forget(fingerprint: String) =
        synchronized(LOCK) {
            try {
                runCatching { sealed(fingerprint) }.getOrNull()?.let { keys.delete(it.alias) }
                file(fingerprint).delete()
                for (alias in keys.aliases(prefix(fingerprint))) if (alias !in pending) keys.delete(alias)
            } catch (e: Exception) {
                // A store's failure, so the delete is set aside, its identity kept, to be asked again.
                throw IOException("a held seed not let go of", e)
            }
        }

    private class Held(
        val alias: String,
        val iv: ByteArray,
        val sealed: ByteArray,
    )

    /** [fingerprint]'s sealed seed, or null if none is held; [BadHeldFile] if it does not read. */
    private fun sealed(fingerprint: String): Held? {
        val bytes =
            try {
                file(fingerprint).readFully()
            } catch (_: FileNotFoundException) {
                return null
            }
        return decode(bytes).also { if (!it.alias.startsWith(prefix(fingerprint))) throw BadHeldFile() }
    }

    private fun encode(
        alias: String,
        iv: ByteArray,
        sealed: ByteArray,
    ): ByteArray {
        val name = alias.toByteArray()
        return byteArrayOf(VERSION, name.size.toByte()) + name + byteArrayOf(iv.size.toByte()) + iv + sealed
    }

    private fun decode(bytes: ByteArray): Held {
        if (bytes.size < 2 || bytes[0] != VERSION) throw BadHeldFile()
        val nameBytes = bytes[1].toInt() and 0xff
        val at = 2 + nameBytes
        if (nameBytes == 0 || bytes.size < at + 1) throw BadHeldFile()
        val ivBytes = bytes[at].toInt() and 0xff
        // GCM's iv, and a tag after it at least.
        if (ivBytes !in 12..16 || bytes.size < at + 1 + ivBytes + 16) throw BadHeldFile()
        return Held(
            String(bytes, 2, nameBytes),
            bytes.copyOfRange(at + 1, at + 1 + ivBytes),
            bytes.copyOfRange(at + 1 + ivBytes, bytes.size),
        )
    }

    private fun write(
        file: AtomicFile,
        bytes: ByteArray,
    ) {
        val out = file.startWrite()
        try {
            out.write(bytes)
        } catch (e: Exception) {
            file.failWrite(out)
            throw e
        }
        file.finishWrite(out)
        // finishWrite logs a rename that failed and returns as if it had not;
        // a read back that fails says neither.
        val back =
            try {
                readBack(file)
            } catch (e: IOException) {
                throw UnsureWrite(e)
            }
        if (!back.contentEquals(bytes)) throw IOException("${file.baseFile.name} not written")
    }

    private fun file(fingerprint: String) = AtomicFile(File(dir, held(fingerprint)))

    private fun held(fingerprint: String) = "held-" + shortHash(fingerprint.toByteArray())

    private fun notice(fingerprint: String) = "lost-" + shortHash(fingerprint.toByteArray())

    private fun prefix(fingerprint: String) = ALIAS + shortHash(fingerprint.toByteArray()) + "-"

    /** A write that may or may not have replaced its file. */
    private class UnsureWrite(
        cause: IOException,
    ) : IOException("a write not known to be made", cause)

    /** A sealed file that does not read as one: left as it is, never taken for a lost key. */
    class BadHeldFile : Exception("a held seed's file does not read")

    private companion object {
        const val TAG = "HeldSeeds"
        const val ALIAS = "hexline-held-"
        const val VERSION: Byte = 2

        /** One for the process, across stores: what a fingerprint's files and keys are changes under it. */
        val LOCK = Any()

        /** Keys made for a hold not yet written: no sweep takes them. */
        val pending = HashSet<String>()
    }
}
