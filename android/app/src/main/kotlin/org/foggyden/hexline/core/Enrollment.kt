package org.foggyden.hexline.core

/** The core's enrollment of this phone, as the app holds it: one it closes when done, which wipes its key. */
interface Enrollment :
    EnrolleeInterface,
    AutoCloseable

/**
 * A new device to enroll, or with [renewing] (a seed and its certificate)
 * that device asking again. With [expecting], another device's certificate,
 * an answer is kept only from that one's identity.
 */
fun coreEnrollment(
    renewing: Pair<ByteArray, ByteArray>?,
    expecting: ByteArray?,
): Enrollment =
    CoreEnrollment(
        (renewing?.let { Enrollee.renewing(it.first, it.second) } ?: Enrollee()).also { e ->
            expecting?.let { e.expectIdentityOf(it) }
        },
    )

private class CoreEnrollment(
    private val enrollee: Enrollee,
) : Enrollment,
    EnrolleeInterface by enrollee {
    override fun close() = enrollee.close()
}
