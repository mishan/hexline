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

    /** The answer certifies another device, or is from another identity than expected. */
    NotForThisPhone,

    /** The certificate would not sign in: no login, or larger than a server takes. */
    Unusable,
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
        is CoreException.Refused ->
            when (e.code) {
                "bad_code" -> EnrollProblem.BadCode
                "unknown_code" -> EnrollProblem.UnknownCode
                "bad_mailbox" -> EnrollProblem.BadMailbox
                "cleartext_mailbox" -> EnrollProblem.Cleartext
                "no_mailbox" -> EnrollProblem.NoMailbox
                "bad_device_name" -> EnrollProblem.BadDeviceName
                "denied" -> EnrollProblem.Denied
                "expired" -> EnrollProblem.Expired
                "wrong_device", "wrong_identity" -> EnrollProblem.NotForThisPhone
                "cert_unusable" -> EnrollProblem.Unusable
                "rate_limited" -> EnrollProblem.RateLimited
                else -> EnrollProblem.Other
            }
        else -> EnrollProblem.Other
    }

/** Where enrolling this phone stands, from its device key made to the certificate kept. */
sealed interface Enrolling {
    data object Idle : Enrolling

    /** Making the device key, or reading the one a renewal is for. */
    data object Starting : Enrolling

    /** [device] is the fingerprint the holder will show, for the person to compare. */
    data class Ready(
        val device: String,
    ) : Enrolling

    data class Waiting(
        val device: String,
    ) : Enrolling

    /**
     * The holder certified this phone a device of [name] ([short]): kept
     * only once confirmed, in place of [replaces], the device of that
     * identity the phone holds now, if any.
     */
    data class Answered(
        val device: String,
        val name: String,
        val short: String,
        val replaces: CertInfo? = null,
    ) : Enrolling

    /** Kept on the phone once the save the person asked for lands: nothing to discard now. */
    data class Saving(
        val name: String,
        val short: String,
    ) : Enrolling

    /** With no [device], there is none to ask with: the person starts again. */
    data class Failed(
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
