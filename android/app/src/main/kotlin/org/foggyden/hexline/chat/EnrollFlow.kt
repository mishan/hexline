package org.foggyden.hexline.chat

import org.foggyden.hexline.core.CertInfo
import org.foggyden.hexline.core.Enrolled
import org.foggyden.hexline.core.Enrollment
import org.foggyden.hexline.identity.EnrollProblem
import org.foggyden.hexline.identity.Enrolling

/**
 * Enrolling this phone, as one state that owns what it holds: the device
 * being enrolled is the state's while it is [Ready], [Waiting],
 * [Answered] or [Failed] with one, and closed by the step that leaves
 * those, so no key outlives the screen. Each run of the screen has a
 * generation ([gen]); a result or a tap from an older one changes nothing.
 * [renewing] is the identity a run renews, by fingerprint, or null.
 */
sealed interface EnrollState {
    val gen: Int

    /** The device this state holds, if any: closed when the state that holds it is left. */
    val owns: Enrollment? get() = null

    data class Idle(
        override val gen: Int = 0,
    ) : EnrollState

    data class Starting(
        override val gen: Int,
        val renewing: String?,
    ) : EnrollState

    data class Ready(
        override val gen: Int,
        val renewing: String?,
        val enrollee: Enrollment,
        val device: String,
    ) : EnrollState {
        override val owns get() = enrollee
    }

    data class Waiting(
        override val gen: Int,
        val renewing: String?,
        val enrollee: Enrollment,
        val device: String,
        val mailbox: String,
    ) : EnrollState {
        override val owns get() = enrollee
    }

    data class Answered(
        override val gen: Int,
        val renewing: String?,
        val enrollee: Enrollment,
        val device: String,
        val mailbox: String,
        val answer: Enrolled,
        val replaces: CertInfo?,
        val namesake: Boolean,
    ) : EnrollState {
        override val owns get() = enrollee
    }

    data class Saving(
        override val gen: Int,
        val name: String,
        val short: String,
    ) : EnrollState

    /** With an [enrollee], the person may ask again with it; with none, they start again. */
    data class Failed(
        override val gen: Int,
        val renewing: String?,
        val enrollee: Enrollment?,
        val device: String,
        val problem: EnrollProblem,
        val reason: String? = null,
    ) : EnrollState {
        override val owns get() = enrollee
    }

    data class Done(
        override val gen: Int,
        val fingerprint: String,
    ) : EnrollState
}

sealed interface EnrollEvent {
    /** The screen opened, for a new identity or to renew [renewing]. */
    data class Start(
        val renewing: String?,
    ) : EnrollEvent

    /** The device for run [gen] made, or not. */
    data class Made(
        val gen: Int,
        val enrollee: Enrollment?,
        val device: String,
    ) : EnrollEvent

    data class Request(
        val gen: Int,
        val mailbox: String,
        val code: String,
        val name: String,
    ) : EnrollEvent

    /** The holder's answer for run [gen], with what it replaces on the phone. */
    data class Answer(
        val gen: Int,
        val answer: Enrolled,
        val replaces: CertInfo?,
        val namesake: Boolean,
    ) : EnrollEvent

    data class Refused(
        val gen: Int,
        val problem: EnrollProblem,
        val reason: String?,
    ) : EnrollEvent

    /** Keep the answer whose identity is [shown], as the screen showed it. */
    data class Confirm(
        val gen: Int,
        val shown: String,
    ) : EnrollEvent

    /** The answer for run [gen] kept, or [problem] why not. */
    data class Saved(
        val gen: Int,
        val fingerprint: String?,
        val problem: EnrollProblem?,
    ) : EnrollEvent

    /** The person let it go. */
    data object Discard : EnrollEvent

    /** The flow was left (signed in, or the app's screen gone). */
    data object Closed : EnrollEvent

    /** The kept identity was picked on the connect screen. */
    data object Seen : EnrollEvent
}

sealed interface EnrollEffect {
    /** Ends a wait and wipes the device's key. */
    data class Close(
        val enrollee: Enrollment,
    ) : EnrollEffect

    data class Make(
        val gen: Int,
        val renewing: String?,
    ) : EnrollEffect

    data class Enroll(
        val gen: Int,
        val enrollee: Enrollment,
        val mailbox: String,
        val code: String,
        val name: String,
    ) : EnrollEffect

    /** Keeps [answer] with [enrollee]'s key, which the save closes once it has it. */
    data class Save(
        val gen: Int,
        val enrollee: Enrollment,
        val answer: Enrolled,
        val mailbox: String,
    ) : EnrollEffect
}

/**
 * The next state and what to do on the way, for [event] in [state].
 * Nothing here runs anything: an effect is the caller's to run.
 */
fun reduce(
    state: EnrollState,
    event: EnrollEvent,
): Pair<EnrollState, List<EnrollEffect>> {
    // What the state holds, closed unless the next state takes it.
    fun to(
        next: EnrollState,
        vararg effects: EnrollEffect,
    ): Pair<EnrollState, List<EnrollEffect>> {
        val drop = state.owns?.takeIf { it !== next.owns && effects.none { e -> e is EnrollEffect.Save && e.enrollee === it } }
        return next to (listOfNotNull(drop?.let { EnrollEffect.Close(it) }) + effects)
    }
    val unchanged = state to emptyList<EnrollEffect>()
    return when (event) {
        is EnrollEvent.Start -> {
            val gen = state.gen + 1
            to(EnrollState.Starting(gen, event.renewing), EnrollEffect.Make(gen, event.renewing))
        }
        is EnrollEvent.Made ->
            when {
                state !is EnrollState.Starting || state.gen != event.gen ->
                    // Made for a run since let go of: nobody's.
                    unchanged.copy(second = listOfNotNull(event.enrollee?.let { EnrollEffect.Close(it) }))
                event.enrollee == null ->
                    to(EnrollState.Failed(state.gen, state.renewing, null, "", EnrollProblem.NotKept))
                else -> to(EnrollState.Ready(state.gen, state.renewing, event.enrollee, event.device))
            }
        is EnrollEvent.Request -> {
            val (renewing, enrollee, device) =
                when {
                    state is EnrollState.Ready && state.gen == event.gen -> Triple(state.renewing, state.enrollee, state.device)
                    state is EnrollState.Failed && state.gen == event.gen && state.enrollee != null ->
                        Triple(state.renewing, state.enrollee, state.device)
                    else -> return unchanged
                }
            to(
                EnrollState.Waiting(event.gen, renewing, enrollee, device, event.mailbox),
                EnrollEffect.Enroll(event.gen, enrollee, event.mailbox, event.code, event.name),
            )
        }
        is EnrollEvent.Answer ->
            if (state is EnrollState.Waiting && state.gen == event.gen) {
                to(
                    EnrollState.Answered(
                        state.gen,
                        state.renewing,
                        state.enrollee,
                        state.device,
                        state.mailbox,
                        event.answer,
                        event.replaces,
                        event.namesake,
                    ),
                )
            } else {
                unchanged
            }
        is EnrollEvent.Refused ->
            if (state is EnrollState.Waiting && state.gen == event.gen) {
                to(EnrollState.Failed(state.gen, state.renewing, state.enrollee, state.device, event.problem, event.reason))
            } else {
                unchanged
            }
        is EnrollEvent.Confirm ->
            if (state is EnrollState.Answered && state.gen == event.gen && state.answer.fingerprint == event.shown) {
                to(
                    EnrollState.Saving(state.gen, state.answer.name, state.answer.short),
                    EnrollEffect.Save(state.gen, state.enrollee, state.answer, state.mailbox),
                )
            } else {
                unchanged
            }
        is EnrollEvent.Saved ->
            when {
                state !is EnrollState.Saving || state.gen != event.gen -> unchanged
                event.fingerprint != null -> to(EnrollState.Done(state.gen, event.fingerprint))
                else -> to(EnrollState.Failed(state.gen, null, null, "", event.problem ?: EnrollProblem.Other))
            }
        EnrollEvent.Discard, EnrollEvent.Closed -> to(EnrollState.Idle(state.gen))
        EnrollEvent.Seen -> if (state is EnrollState.Done) to(EnrollState.Idle(state.gen)) else unchanged
    }
}

/** What the screen shows of [state]. */
fun EnrollState.shown(): Enrolling =
    when (this) {
        is EnrollState.Idle -> Enrolling.Idle
        is EnrollState.Starting -> Enrolling.Starting(gen, renewing)
        is EnrollState.Ready -> Enrolling.Ready(gen, renewing, device)
        is EnrollState.Waiting -> Enrolling.Waiting(gen, renewing, device)
        is EnrollState.Answered ->
            Enrolling.Answered(gen, renewing, device, answer.name, answer.fingerprint, answer.info, replaces, namesake)
        is EnrollState.Saving -> Enrolling.Saving(gen, name, short)
        is EnrollState.Failed -> Enrolling.Failed(gen, renewing, if (enrollee == null) "" else device, problem, reason)
        is EnrollState.Done -> Enrolling.Done(fingerprint)
    }
