package org.foggyden.hexline.secrets

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.annotation.RequiresApi
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Keys B (design §2.2): one Keystore key per held identity, each use of
 * which the person allows there and then, by biometric or by the screen
 * lock. Only a [Seal] the person has let through seals or opens anything,
 * so a seed waits wrapped until someone is there to ask for it.
 *
 * A key is called lost ([HeldKeyLost]) only on the Keystore's positive
 * word that it is gone; any other trouble is thrown as it is, for now,
 * since losing a key loses the identity's seed with it.
 */
interface HolderKeys {
    /** Whether the phone has a screen lock to ask by: without one there is no Key B. */
    fun secureLock(): Boolean

    /** A new key named [alias]. [NoScreenLock] without a lock. */
    fun create(alias: String)

    /**
     * A use of [alias]'s key, waiting for the person: sealing with [iv] null,
     * opening what was sealed under [iv] otherwise.
     */
    fun begin(
        alias: String,
        iv: ByteArray?,
    ): Seal

    /** Where [alias]'s key lives, as the Keystore says: "strongbox", "tee", "software" or another level. */
    fun security(alias: String): String

    /** Whether [alias]'s key is gone for good, asking the person nothing. */
    fun gone(alias: String): Boolean

    /** The keys whose alias starts with [prefix]. */
    fun aliases(prefix: String): List<String>

    fun delete(alias: String)
}

/** One use of a Key B. [run] works only once the person has allowed it. */
interface Seal {
    /** What the prompt asks the person to unlock: the platform's cipher, for the real keys. */
    val cipher: Cipher?

    /** Sealing: the iv and the sealed bytes. Opening: the bytes. [HeldKeyLost] if they never will open. */
    fun run(data: ByteArray): Pair<ByteArray, ByteArray>
}

/** Asks the person to allow one [Seal]: false if they would not (canceled, or failed). */
fun interface Authorizer {
    suspend fun allow(seal: Seal): Boolean
}

/** This phone's Android is older than holder mode needs (API 30, design §9). */
class HolderUnsupported : Exception("holder mode needs Android 11")

/** Keys B on a phone too old for them: nothing is held, so nothing is lost. */
object NoHolderKeys : HolderKeys {
    override fun secureLock() = false

    override fun create(alias: String) = throw HolderUnsupported()

    override fun begin(
        alias: String,
        iv: ByteArray?,
    ): Seal = throw HeldKeyLost(alias)

    override fun security(alias: String) = throw HolderUnsupported()

    override fun gone(alias: String) = true

    override fun aliases(prefix: String) = emptyList<String>()

    override fun delete(alias: String) = Unit
}

/** This phone's Keystore keeps keys in software alone, which a release build holds no seed behind. */
class SoftwareKeysOnly : Exception("the Keystore keeps keys in software alone")

/** No screen lock is set, so nothing can be held behind one. */
class NoScreenLock : Exception("no screen lock is set")

/** A Key B gone for good, and what it sealed with it. */
class HeldKeyLost(
    alias: String,
    cause: Throwable? = null,
) : Exception("held key $alias is gone", cause)

/**
 * The Keystore's Keys B: AES-256-GCM, each use allowed by a strong
 * biometric or the device credential with no window after (API 30+, the
 * least holder mode runs on; design §9), used only while the phone is
 * unlocked, kept through a fingerprint added (so enrolling a finger does
 * not end an identity), in StrongBox where the phone has one: unlike Key
 * A these are used seldom, and by a person who can wait for it.
 */
@RequiresApi(Build.VERSION_CODES.R)
class KeystoreHolderKeys(
    private val context: Context,
) : HolderKeys {
    override fun secureLock() = context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    override fun create(alias: String) {
        if (!secureLock()) throw NoScreenLock()
        try {
            generate(alias, strongBox = context.packageManager.hasSystemFeature("android.hardware.strongbox_keystore"))
        } catch (_: StrongBoxUnavailableException) {
            generate(alias, strongBox = false)
        }
        Log.i(TAG, "a Key B made, in ${security(alias)}")
    }

    private fun generate(
        alias: String,
        strongBox: Boolean,
    ) {
        val spec =
            KeyGenParameterSpec
                .Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                .setInvalidatedByBiometricEnrollment(false)
                .setUnlockedDeviceRequired(true)
                .setIsStrongBoxBacked(strongBox)
                .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).run {
            init(spec)
            generateKey()
        }
    }

    override fun security(alias: String): String {
        val key = keystore().getKey(alias, null) as SecretKey
        val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
                else -> "level ${info.securityLevel}"
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "secure hardware" else "software"
        }
    }

    override fun begin(
        alias: String,
        iv: ByteArray?,
    ): Seal {
        val cipher = init(alias, iv)
        return object : Seal {
            override val cipher = cipher

            override fun run(data: ByteArray): Pair<ByteArray, ByteArray> =
                try {
                    (iv ?: cipher.iv) to cipher.doFinal(data)
                } catch (e: AEADBadTagException) {
                    throw HeldKeyLost(alias, e)
                } catch (e: Exception) {
                    if (lost(e)) throw HeldKeyLost(alias, e) else throw e
                }
        }
    }

    override fun gone(alias: String): Boolean {
        if (!keystore().containsAlias(alias)) return true
        val probe =
            try {
                init(alias, null)
            } catch (_: HeldKeyLost) {
                return true
            }
        // Ended at once, so the operation holds no place a use the person
        // is about to allow would want.
        runCatching { probe.doFinal(ByteArray(0)) }
        return false
    }

    private fun init(
        alias: String,
        iv: ByteArray?,
    ): Cipher =
        try {
            val key = keystore().getKey(alias, null) as SecretKey? ?: throw HeldKeyLost(alias)
            Cipher.getInstance(TRANSFORMATION).apply {
                if (iv == null) init(Cipher.ENCRYPT_MODE, key) else init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
            }
        } catch (e: HeldKeyLost) {
            throw e
        } catch (e: Exception) {
            if (lost(e)) throw HeldKeyLost(alias, e) else throw e
        }

    /** Whether [e] is the Keystore's word that a key is gone for good, and not trouble for now. */
    private fun lost(e: Throwable): Boolean =
        generateSequence(e) { it.cause }.any { cause ->
            cause is KeyPermanentlyInvalidatedException || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && goneCode(cause))
        }

    /** Invalidation comes as [KeyPermanentlyInvalidatedException]; a key not there, as this code. */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun goneCode(cause: Throwable) =
        cause is android.security.KeyStoreException &&
            cause.numericErrorCode == android.security.KeyStoreException.ERROR_KEY_DOES_NOT_EXIST

    override fun aliases(prefix: String) = keystore().aliases().toList().filter { it.startsWith(prefix) }

    override fun delete(alias: String) = keystore().deleteEntry(alias)

    private fun keystore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private companion object {
        const val TAG = "HolderKeys"
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128
    }
}
