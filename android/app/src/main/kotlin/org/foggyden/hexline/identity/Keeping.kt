package org.foggyden.hexline.identity

/** Where renewing this phone's own certificate stands. */
sealed interface Renewing {
    data object Idle : Renewing

    data object Working : Renewing

    data class Failed(
        val problem: SetupProblem,
    ) : Renewing

    data class Done(
        val fingerprint: String,
    ) : Renewing
}

/** What a backup put or took away. */
enum class Backed { PassphraseSaved, PassphraseRemoved, RecoveryCodeSaved }

/** Where a held identity's backup at its registrar stands. */
sealed interface BackingUp {
    data object Idle : BackingUp

    data object Working : BackingUp

    /** A new recovery code, shown once to write down. */
    data class Recovery(
        val code: String,
    ) : BackingUp {
        override fun toString() = "Recovery(code=redacted)"
    }

    data class ConfirmRecovery(
        val wrong: Boolean,
    ) : BackingUp

    data class Failed(
        val problem: SetupProblem,
    ) : BackingUp

    /** The new recovery code typed back and not known to be saved: it may already be the one in effect. */
    data class RecoveryNotSaved(
        val problem: SetupProblem,
    ) : BackingUp

    data class Done(
        val backed: Backed,
    ) : BackingUp
}
