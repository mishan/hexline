package org.foggyden.hexline.secrets

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Small secrets — session tokens, saved passwords, push keys — sealed by an
 * AES-256-GCM key the Android Keystore holds and never lets out. The key
 * needs no unlock for each use and works with the screen locked once the
 * phone has been unlocked since boot, so a push that wakes the app can open
 * what it needs. It lives in the TEE rather than StrongBox, whose every
 * operation is slow and which turns callers away when busy: a push has
 * seconds, not the patience for that. Each secret is one file in the app's
 * own storage, which backup excludes; on another phone the key does not
 * exist, so a copied file opens nowhere. Root acting as this app opens
 * everything, as it could take the key's use from the app anyway.
 *
 * Calls block on the Keystore: not on the main thread. The store is for
 * one process; a second (a push service of its own) would need a lock
 * across processes. The plaintext arrays handed in and out are the
 * caller's to zero.
 *
 * Two failures are told apart, because the right answer to each is the
 * opposite of the other's: [SecretUnreadable] is for good — forget the
 * secret and ask again — and [SecretUnavailable] is for now, and the
 * secret is still there to try later.
 */
class SecretStore(
    context: Context,
    private val alias: String = "hexline-secrets",
    private val dir: File = File(context.filesDir, "secrets"),
) {
    init {
        dir.mkdirs()
    }

    fun put(
        name: String,
        secret: ByteArray,
    ): Unit =
        synchronized(LOCK) {
            val file = AtomicFile(file(name))
            val cipher = Cipher.getInstance(TRANSFORMATION)
            transient(name) {
                try {
                    cipher.init(Cipher.ENCRYPT_MODE, key() ?: generate())
                } catch (_: KeyPermanentlyInvalidatedException) {
                    // Gone for good, and with it everything it sealed: the
                    // files are left unreadable, so they go too. Nothing
                    // else is taken for this, since a key with no user auth
                    // almost never ends so, and a keystore's passing
                    // trouble must not cost every secret.
                    forget()
                    dir.listFiles()?.forEach { it.delete() }
                    cipher.init(Cipher.ENCRYPT_MODE, generate())
                }
                cipher.updateAAD(aad(name))
                val sealed = byteArrayOf(VERSION) + cipher.iv + cipher.doFinal(secret)
                val out = file.startWrite()
                try {
                    out.write(sealed)
                    file.finishWrite(out)
                } catch (e: Exception) {
                    file.failWrite(out)
                    throw e
                }
            }
        }

    /**
     * The secret, or null if none was put. [SecretUnreadable] if one was and
     * never will open; [SecretUnavailable] if it cannot be opened now.
     */
    fun get(name: String): ByteArray? =
        synchronized(LOCK) {
            val sealed =
                try {
                    // Not `exists()`: on API 29 a write cut short leaves only
                    // the backup, which readFully restores.
                    AtomicFile(file(name)).readFully()
                } catch (_: FileNotFoundException) {
                    return null
                }
            if (sealed.size < HEADER + TAG_BITS / 8 || sealed[0] != VERSION) throw SecretUnreadable(name)
            transient(name) {
                val key = key() ?: throw SecretUnreadable(name)
                val cipher = Cipher.getInstance(TRANSFORMATION)
                try {
                    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, sealed, 1, IV_BYTES))
                    cipher.updateAAD(aad(name))
                    cipher.doFinal(sealed, HEADER, sealed.size - HEADER)
                } catch (e: AEADBadTagException) {
                    throw SecretUnreadable(name, e)
                } catch (e: KeyPermanentlyInvalidatedException) {
                    cached = null
                    throw SecretUnreadable(name, e)
                }
            }
        }

    fun delete(name: String): Unit =
        synchronized(LOCK) {
            AtomicFile(file(name)).delete()
        }

    private fun file(name: String): File {
        // No dots: AtomicFile's own files are a name with `.new` or `.bak`
        // after it, and `.` and `..` are not files at all.
        require(NAME.matches(name)) { "secret names are [a-z0-9][a-z0-9_-]{0,63}: $name" }
        return File(dir, name)
    }

    /** The format and the name are sealed in: a renamed file does not open as another secret. */
    private fun aad(name: String) = byteArrayOf(VERSION) + name.toByteArray()

    /** Anything the Keystore says that is not one of the two permanent answers: for now. */
    private inline fun <T> transient(
        name: String,
        block: () -> T,
    ): T =
        try {
            block()
        } catch (e: SecretUnreadable) {
            throw e
        } catch (e: GeneralSecurityException) {
            cached = null
            throw SecretUnavailable(name, e)
        } catch (e: ProviderException) {
            cached = null
            throw SecretUnavailable(name, e)
        }

    private fun keystore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    /** Held across calls, so a push needing several secrets asks the Keystore once. */
    private var cached: SecretKey?
        get() = KEYS[alias]
        set(key) {
            if (key == null) KEYS.remove(alias) else KEYS[alias] = key
        }

    private fun key(): SecretKey? = cached ?: (keystore().getKey(alias, null) as SecretKey?).also { cached = it }

    private fun forget() {
        cached = null
        keystore().deleteEntry(alias)
    }

    private fun generate(): SecretKey {
        val spec =
            KeyGenParameterSpec
                .Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        return KeyGenerator
            .getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            .run {
                init(spec)
                generateKey()
            }.also { cached = it }
    }

    private companion object {
        /**
         * One for the process: two stores finding no key at once would each
         * make one, the second replacing the first and everything it
         * sealed, and AtomicFile is not safe for two writers of one name.
         */
        val LOCK = Any()
        val KEYS = HashMap<String, SecretKey>()
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val VERSION: Byte = 1
        const val IV_BYTES = 12
        const val HEADER = 1 + IV_BYTES
        const val TAG_BITS = 128
        val NAME = Regex("[a-z0-9][a-z0-9_-]{0,63}")
    }
}

/** A secret that is there and never will open: altered, or sealed by a key this phone no longer has. */
class SecretUnreadable(
    name: String,
    cause: Throwable? = null,
) : Exception("secret $name does not open", cause)

/** A secret that cannot be opened or written now, the Keystore being unable to; it is still there. */
class SecretUnavailable(
    name: String,
    cause: Throwable,
) : Exception("secret $name is not available now", cause)
