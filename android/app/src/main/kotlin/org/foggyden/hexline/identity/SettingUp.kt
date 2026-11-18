package org.foggyden.hexline.identity

import org.foggyden.hexline.core.CoreException

/** Why this phone cannot hold an identity at all; the screen points to the other two ways onto it. */
enum class HolderRefusal {
    /** Android older than 11 (design §9). */
    TooOld,
    NoScreenLock,

    /** The Keystore keeps keys in software alone, which a release build holds no seed behind. */
    SoftwareOnly,
}

/** Why a step of a holder's setup did not go through; the screen says it in words. */
enum class SetupProblem {
    NotARegistrar,

    /** The registrar keeps no recovery envelopes. */
    NoBackups,
    HandleTaken,
    HandleInvalid,

    /** The device's name would make a certificate no server reads. */
    BadDeviceName,

    /** A passphrase that is blank. */
    BadPassphrase,

    /** The registrar has not registered the identity, so keeps nothing of it. */
    NotRegistered,
    InviteNeeded,
    InviteWrong,

    /** The handle is the identity's now, and its backup did not go through: asked again as it. */
    NotBackedUp,
    RateLimited,
    Unreachable,

    /** The held key is gone (the screen lock removed): the identity is a device here alone. */
    KeyLost,

    /** The phone could not keep the identity just now: try again. */
    NotKept,
    Other,
}

fun setupProblem(e: CoreException): SetupProblem =
    when (e) {
        is CoreException.Connect -> SetupProblem.Unreachable
        is CoreException.RateLimited -> SetupProblem.RateLimited
        is CoreException.Refused ->
            when (e.code) {
                "bad_registrar", "not_a_registrar" -> SetupProblem.NotARegistrar
                "no_envelopes" -> SetupProblem.NoBackups
                "handle_taken", "handle_held", "handle_reserved" -> SetupProblem.HandleTaken
                "handle_invalid" -> SetupProblem.HandleInvalid
                "bad_device_name" -> SetupProblem.BadDeviceName
                "bad_passphrase" -> SetupProblem.BadPassphrase
                "not_registered" -> SetupProblem.NotRegistered
                "proof_required" -> SetupProblem.InviteNeeded
                "proof_invalid" -> SetupProblem.InviteWrong
                "registered_not_backed_up", "registered_as" -> SetupProblem.NotBackedUp
                "rate_limited" -> SetupProblem.RateLimited
                else -> SetupProblem.Other
            }
        else -> SetupProblem.Other
    }

/**
 * Where a holder's setup stands. The codes are shown as text, which the
 * runtime may keep (design §2.2); everything else of them is wiped.
 */
sealed interface SettingUp {
    data object Idle : SettingUp

    /** The phone's keys and the registrar asked whether an identity can be held there. */
    data object Checking : SettingUp

    data class Refused(
        val why: HolderRefusal,
    ) : SettingUp

    /** The successor's code, shown once to write down. */
    data class Successor(
        val code: String,
    ) : SettingUp {
        override fun toString() = "Successor(code=redacted)"
    }

    /** The successor's code to type back; [wrong] if the last try was not it. */
    data class ConfirmSuccessor(
        val wrong: Boolean,
    ) : SettingUp

    /**
     * The recovery code, shown once to write down. [replaces]: a setup
     * finished again, whose new code replaces any written down before.
     */
    data class Recovery(
        val code: String,
        val replaces: Boolean,
    ) : SettingUp {
        override fun toString() = "Recovery(code=redacted, replaces=$replaces)"
    }

    data class ConfirmRecovery(
        val wrong: Boolean,
        val replaces: Boolean,
    ) : SettingUp

    /** Both codes typed back: holding the key asks the person, by the prompt. */
    data object ReadyToHold : SettingUp

    /** The prompt, the device kept, then the registrar asked. */
    data object Working : SettingUp

    /**
     * A step that did not go through. [handle] is the one asked for;
     * [fixed] when it can no longer change, as the identity holds it or
     * its setup is finished again.
     */
    data class Failed(
        val problem: SetupProblem,
        val handle: String,
        val fixed: Boolean,
    ) : SettingUp

    data class Done(
        val fingerprint: String,
    ) : SettingUp
}
