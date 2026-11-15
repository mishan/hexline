package org.foggyden.hexline.secrets

/**
 * Small named secrets, as [SecretStore] keeps them: a store that holds
 * them some other way (a test's, in memory) stands in for the Keystore.
 */
interface Secrets {
    /** [SecretUnavailable] if it cannot be kept now. */
    fun put(
        name: String,
        secret: ByteArray,
    )

    /**
     * The secret, or null if none was put. [SecretUnreadable] if one was and
     * never will open; [SecretUnavailable] if it cannot be opened now.
     */
    fun get(name: String): ByteArray?

    fun delete(name: String)
}
