package org.foggyden.hexline.identity

import org.foggyden.hexline.core.CertInfo
import org.foggyden.hexline.core.CoreException

/** Why a holder's certificate for this phone was not had; the screen says it in words. */
enum class EnrollProblem {
    BadCode,

    /** No open session has the code, or it was used. */
    UnknownCode,
    BadMailbox,

    /** A mailbox over plain http to another machine: enrolling needs wss://, or one on this machine. */
    Cleartext,
    NoMailbox,
    BadDeviceName,

    /** The holder said no. */
    Denied,
    Expired,

    /** The holder may have answered: the answer was lost on its way, and the mailbox no longer has it. */
    AnswerLost,

    /** The answer certifies another device, or is from another identity than expected. */
    NotForThisPhone,

    /** The certificate would not sign in: no login, or larger than a server takes. */
    Unusable,

    /** The certificate would let the phone vouch, which it never holds. */
    Vouches,

    /** The phone's clock, likely: a certificate outside its time, or a renewal the holder found misdated. */
    Clock,

    /** The holder answered, and this phone could not take the answer. */
    RefusedHere,
    RateLimited,
    Unreachable,

    /** The device's key could not be made or read now: start again. */
    NotKept,

    /** The holder's answer could not be kept, and its device is gone: a new code is needed. */
    AnswerNotKept,
    Other,
}

fun enrollProblem(e: CoreException): EnrollProblem =
    when (e) {
        is CoreException.Connect -> EnrollProblem.Unreachable
        is CoreException.RateLimited -> EnrollProblem.RateLimited
        is CoreException.Protocol -> EnrollProblem.RefusedHere
        is CoreException.Refused ->
            when (e.code) {
                "bad_code" -> EnrollProblem.BadCode
                "unknown_code" -> EnrollProblem.UnknownCode
                "bad_mailbox" -> EnrollProblem.BadMailbox
                "cleartext_mailbox" -> EnrollProblem.Cleartext
                "no_mailbox" -> EnrollProblem.NoMailbox
                "bad_device_name" -> EnrollProblem.BadDeviceName
                "denied" if e.detail == "bad_renewal" -> EnrollProblem.Clock
                "denied" -> EnrollProblem.Denied
                "expired" -> EnrollProblem.Expired
                "answer_lost" -> EnrollProblem.AnswerLost
                "wrong_device", "wrong_identity" -> EnrollProblem.NotForThisPhone
                "cert_unusable" -> EnrollProblem.Unusable
                "cert_vouches" -> EnrollProblem.Vouches
                "cert_expired", "cert_not_yet_valid" -> EnrollProblem.Clock
                "short_renewal", "behind_reset" -> EnrollProblem.RefusedHere
                "rate_limited" -> EnrollProblem.RateLimited
                else -> EnrollProblem.Other
            }
        else -> EnrollProblem.Other
    }

/**
 * What the enroll screen shows: a projection of the view model's state.
 * [gen] is the run a tap answers to; [renewing] the identity renewed, if any.
 */
sealed interface Enrolling {
    data object Idle : Enrolling

    /** Making the device key, or reading the one a renewal is for. */
    data class Starting(
        val gen: Int,
        val renewing: String?,
    ) : Enrolling

    /** [device] is the fingerprint the holder will show, for the person to compare. */
    data class Ready(
        val gen: Int,
        val renewing: String?,
        val device: String,
    ) : Enrolling

    data class Waiting(
        val gen: Int,
        val renewing: String?,
        val device: String,
    ) : Enrolling

    /**
     * The holder certified this phone a device of [name] ([fingerprint]),
     * as [info] says: kept only once confirmed, in place of [replaces], the
     * device of that identity the phone holds now, if any. [namesake]: the
     * phone holds another identity by the same name.
     */
    data class Answered(
        val gen: Int,
        val renewing: String?,
        val device: String,
        val name: String,
        val fingerprint: String,
        val info: CertInfo,
        val replaces: CertInfo? = null,
        val namesake: Boolean = false,
    ) : Enrolling

    /** Kept on the phone once the save the person asked for lands: nothing to discard now. */
    data class Saving(
        val gen: Int,
        val name: String,
        val short: String,
    ) : Enrolling

    /** With no [device], there is none to ask with: the person starts again. */
    data class Failed(
        val gen: Int,
        val renewing: String?,
        val device: String,
        val problem: EnrollProblem,
        /** The holder's reason, when it said no. */
        val reason: String? = null,
    ) : Enrolling

    /** Kept on the phone as [fingerprint]. */
    data class Done(
        val fingerprint: String,
    ) : Enrolling
}

/** Whether the enroll screen is open: a run under way, or one that ended other than kept. */
val Enrolling.open: Boolean get() = this != Enrolling.Idle && this !is Enrolling.Done

/** The identity the run renews, if any. */
val Enrolling.renewing: String?
    get() =
        when (this) {
            is Enrolling.Starting -> renewing
            is Enrolling.Ready -> renewing
            is Enrolling.Waiting -> renewing
            is Enrolling.Answered -> renewing
            is Enrolling.Failed -> renewing
            else -> null
        }
