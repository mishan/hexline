package org.foggyden.hexline.identity

import org.foggyden.hexline.core.CoreException

/** Why an identity could not be restored; the screen says it in words. */
enum class RestoreProblem {
    /** The registrar answers a wrong secret and a missing backup alike. */
    NotFound,
    NotARegistrar,
    NoBackups,
    BadSecret,
    BadDeviceName,
    RateLimited,
    Unreachable,

    /** The Keystore cannot take the device now: try again. */
    NotKept,
    Other,
}

fun restoreProblem(e: CoreException): RestoreProblem =
    when (e) {
        is CoreException.Connect -> RestoreProblem.Unreachable
        is CoreException.RateLimited -> RestoreProblem.RateLimited
        is CoreException.Refused ->
            when (e.code) {
                "not_found" -> RestoreProblem.NotFound
                "bad_registrar", "not_a_registrar" -> RestoreProblem.NotARegistrar
                "no_envelopes" -> RestoreProblem.NoBackups
                "bad_passphrase", "bad_recovery_code" -> RestoreProblem.BadSecret
                "bad_device_name" -> RestoreProblem.BadDeviceName
                "rate_limited" -> RestoreProblem.RateLimited
                else -> RestoreProblem.Other
            }
        else -> RestoreProblem.Other
    }

/** Where a restore stands. */
sealed interface Restoring {
    data object Idle : Restoring

    data object Working : Restoring

    data class Failed(
        val problem: RestoreProblem,
    ) : Restoring

    /** Kept on the phone as [fingerprint]. */
    data class Done(
        val fingerprint: String,
    ) : Restoring
}
