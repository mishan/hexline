package org.foggyden.hexline.identity

import org.foggyden.hexline.core.CertTime
import org.foggyden.hexline.core.certTime

/** Whether an identity's device certificate can sign in now, and what the person is to be asked. */
sealed interface Standing {
    data object Good : Standing

    /** Expires within [days] days, counting a day begun as one. */
    data class Renew(
        val days: Long,
    ) : Standing

    data object Expired : Standing

    /** Begins after the phone's clock, past what a server allows: the clock is likely wrong. */
    data object NotYetValid : Standing
}

/** Whether the identity can sign in now: soon to expire still can. */
val Standing.usable: Boolean get() = this == Standing.Good || this is Standing.Renew

/**
 * [identity]'s standing at [now], in seconds: outside its time by the
 * core's own rule, which the core holds a login to, and otherwise how
 * soon it wants renewing. In envelope mode renewing asks for the
 * passphrase again, so it is asked for close to the end (design 2.1).
 */
fun standing(
    identity: StoredIdentity,
    now: Long,
): Standing {
    when (certTime(identity.info.issued, identity.info.expires, now.toULong())) {
        CertTime.EXPIRED -> return Standing.Expired
        CertTime.NOT_YET_VALID -> return Standing.NotYetValid
        CertTime.VALID -> {}
    }
    // Within the skew past its end, it is still a day it may be used.
    val left = (identity.info.expires.toLong() - now).coerceAtLeast(1)
    return if (left <= RENEW_WITHIN) Standing.Renew((left + DAY - 1) / DAY) else Standing.Good
}

private const val DAY = 86_400L
private const val RENEW_WITHIN = 14 * DAY
