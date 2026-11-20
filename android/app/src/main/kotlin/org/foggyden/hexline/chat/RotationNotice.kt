package org.foggyden.hexline.chat

import org.foggyden.hexline.core.KeptRotation
import org.foggyden.hexline.core.RegistrarState
import org.foggyden.hexline.core.RotationRegistrar

/** What the person is told of a rotation sent: the worst any of its registrars answered. */
sealed interface RotationNotice {
    /** The registrar that answered so. */
    val registrar: String

    /** Whether it may be someone else's doing, to be shown whichever way the person signs in. */
    val alarm: Boolean get() = false

    /** Sent, published, or not yet answered: nothing to say beyond that it is under way. */
    data class UnderWay(
        override val registrar: String,
    ) : RotationNotice

    data class Pending(
        override val registrar: String,
        val until: Long,
    ) : RotationNotice

    data class Frozen(
        override val registrar: String,
    ) : RotationNotice

    /**
     * Refused for good: `revoked`, which anyone holding the old key alone can do, or
     * `not_registered`.
     */
    data class Refused(
        override val registrar: String,
        val code: String,
    ) : RotationNotice {
        override val alarm get() = code == "revoked"
    }

    /** Another rotation is held there: the window in which the operator can still freeze it. */
    data class PendingElsewhere(
        override val registrar: String,
        val until: Long?,
    ) : RotationNotice {
        override val alarm get() = true
    }

    /** `successor_mismatch`: the identity or its successor is held to a commitment this phone did not make. */
    data class Mismatch(
        override val registrar: String,
    ) : RotationNotice {
        override val alarm get() = true
    }

    /** Published to this phone's successor under another commitment: whoever made it controls the next move. */
    data class Superseded(
        override val registrar: String,
    ) : RotationNotice {
        override val alarm get() = true
    }

    /** Rotated there to a key this phone does not hold: the identity is whoever holds that key. */
    data class RotatedAway(
        override val registrar: String,
    ) : RotationNotice {
        override val alarm get() = true
    }
}

/** [rotation]'s notice: its registrars' worst, the home registrar's where two are as bad; none without a registrar. */
fun notice(rotation: KeptRotation): RotationNotice? {
    val ordered = rotation.registrars.sortedByDescending { it.home }
    return ordered.map(::noticeAt).maxByOrNull(::severity)
}

private fun noticeAt(r: RotationRegistrar): RotationNotice =
    when (r.state) {
        RegistrarState.PENDING -> RotationNotice.Pending(r.base, r.until)
        RegistrarState.PENDING_ELSEWHERE -> RotationNotice.PendingElsewhere(r.base, r.until.takeIf { it > 0 })
        RegistrarState.FROZEN -> RotationNotice.Frozen(r.base)
        RegistrarState.SUPERSEDED -> RotationNotice.Superseded(r.base)
        RegistrarState.ROTATED_AWAY -> RotationNotice.RotatedAway(r.base)
        RegistrarState.REFUSED ->
            if (r.refused == "successor_mismatch") RotationNotice.Mismatch(r.base) else RotationNotice.Refused(r.base, r.refused.orEmpty())
        else -> RotationNotice.UnderWay(r.base)
    }

private fun severity(n: RotationNotice): Int =
    when (n) {
        is RotationNotice.UnderWay -> 0
        is RotationNotice.Pending -> 1
        is RotationNotice.Frozen -> 2
        // A revocation is an alarm, so above the refusals that are not.
        is RotationNotice.Refused -> if (n.alarm) 4 else 3
        is RotationNotice.PendingElsewhere -> 5
        is RotationNotice.Mismatch -> 6
        is RotationNotice.Superseded -> 7
        is RotationNotice.RotatedAway -> 8
    }
