package org.foggyden.hexline.secrets

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Keys B as the Keystore keeps them, in memory and sealed with GCM as the
 * real ones are, so a wrong iv or an altered file does not open: each use
 * opens nothing until it has been allowed, a key made without a screen
 * lock is refused, and removing the lock takes every key away for good.
 * The Keystore's trouble for now ([trouble]) is thrown as it is, never as
 * a key lost.
 */
class FakeHolderKeys : HolderKeys {
    private val made = LinkedHashMap<String, SecretKey>()
    private val lost = HashSet<String>()
    private var lock = true

    /** What the Keystore throws for now, by alias, from every call naming one. */
    var trouble: ((String) -> Exception?)? = null

    /** What a delete throws, once each, before the key goes. */
    var deleteFails: ((String) -> Exception?)? = null

    /** Called from each [Seal.run] once its bytes are made, with them. */
    var onRun: ((ByteArray) -> Unit)? = null

    /** Every use begun, allowed or not, in order. */
    val begun = mutableListOf<FakeSeal>()

    val aliases get() = made.keys.toList()

    /** Where every key is said to live. */
    var level = "tee"

    override fun security(alias: String) = level

    override fun secureLock() = lock

    /** The person removes the screen lock: every key so far is gone. */
    fun removeLock() {
        lock = false
        made.clear()
        lost.clear()
    }

    fun setLock() {
        lock = true
    }

    /** One key gone on its own: still listed, and lost on its first use. */
    fun invalidate(alias: String) {
        lost += alias
    }

    override fun create(alias: String) {
        if (!lock) throw NoScreenLock()
        trouble?.invoke(alias)?.let { throw it }
        made[alias] = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    }

    override fun begin(
        alias: String,
        iv: ByteArray?,
    ): Seal {
        trouble?.invoke(alias)?.let { throw it }
        val key = made[alias] ?: throw HeldKeyLost(alias)
        if (alias in lost) throw HeldKeyLost(alias)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        if (iv == null) cipher.init(Cipher.ENCRYPT_MODE, key) else cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return FakeSeal(alias, cipher, iv).also { begun += it }
    }

    override fun gone(alias: String): Boolean {
        trouble?.invoke(alias)?.let { throw it }
        return alias !in made || alias in lost
    }

    override fun aliases(prefix: String) = made.keys.filter { it.startsWith(prefix) }

    override fun delete(alias: String) {
        deleteFails?.invoke(alias)?.let {
            deleteFails = null
            throw it
        }
        made -= alias
        lost -= alias
    }

    inner class FakeSeal(
        val alias: String,
        private val sealing: Cipher,
        private val iv: ByteArray?,
    ) : Seal {
        var allowed = false
        override val cipher: Cipher? = null

        override fun run(data: ByteArray): Pair<ByteArray, ByteArray> {
            check(allowed) { "a Key B used without the person's say" }
            allowed = false
            val out =
                try {
                    sealing.doFinal(data)
                } catch (e: AEADBadTagException) {
                    throw HeldKeyLost(alias, e)
                }
            onRun?.invoke(out)
            return (iv ?: sealing.iv) to out
        }
    }

    /** The person's answer to every prompt. */
    fun authorizer(answer: () -> Boolean = { true }) =
        Authorizer { seal ->
            answer().also { (seal as FakeSeal).allowed = it }
        }
}
