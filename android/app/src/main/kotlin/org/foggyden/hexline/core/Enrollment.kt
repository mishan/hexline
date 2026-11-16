package org.foggyden.hexline.core

/** The core's enrollment of this phone, as the app holds it: one it closes when done, which wipes its key. */
interface Enrollment :
    EnrolleeInterface,
    AutoCloseable

/**
 * A new device to enroll, or with [renewing] (a seed and its certificate)
 * that device asking again. With [expecting], an identity's fingerprint,
 * an answer is kept only from that identity.
 */
fun coreEnrollment(
    renewing: Pair<ByteArray, ByteArray>?,
    expecting: String?,
): Enrollment {
    val made = renewing?.let { Enrollee.renewing(it.first, it.second) } ?: Enrollee()
    try {
        expecting?.let { made.expectIdentity(it) }
    } catch (e: Exception) {
        // Not handed over, so nobody else would wipe its key.
        made.close()
        throw e
    }
    return CoreEnrollment(made)
}

private class CoreEnrollment(
    private val enrollee: Enrollee,
) : Enrollment,
    EnrolleeInterface by enrollee {
    override fun close() = enrollee.close()
}
