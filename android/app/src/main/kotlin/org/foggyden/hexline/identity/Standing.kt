package org.foggyden.hexline.identity

import org.foggyden.hexline.core.CertTime
import org.foggyden.hexline.core.certTime
import org.foggyden.hexline.core.certTimeChanges

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
 * passphrase again, so it is asked for close to the end; a phone holding
 * the key asks only for the screen lock, so from a third of the
 * certificate's life left (design 2.1).
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
    return if (left <= renewWithin(identity)) Standing.Renew((left + DAY - 1) / DAY) else Standing.Good
}

private fun renewWithin(identity: StoredIdentity) =
    if (identity.held) (identity.info.expires.toLong() - identity.info.issued.toLong()) / 3 else RENEW_WITHIN

/**
 * The first moment after [now] at which [identity]'s standing is
 * otherwise, if there is one: when a screen showing it is to look again.
 * Where the core's line falls, where renewal begins to be asked for, and
 * each day its count of days drops.
 */
fun nextChange(
    identity: StoredIdentity,
    now: Long,
): Long? {
    val (issued, expires) = identity.info.issued to identity.info.expires
    val days = (0..renewWithin(identity) / DAY).map { expires.toLong() - it * DAY } + (expires.toLong() - renewWithin(identity))
    val at = standing(identity, now)
    return (days + listOfNotNull(certTimeChanges(issued, expires, now.toULong())?.toLong()))
        .filter { it > now }
        .sorted()
        .firstOrNull { standing(identity, it) != at }
}

private const val DAY = 86_400L
private const val RENEW_WITHIN = 14 * DAY
