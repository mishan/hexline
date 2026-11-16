package org.foggyden.hexline.chat

import org.foggyden.hexline.core.CertInfo
import org.foggyden.hexline.core.Enrolled
import org.foggyden.hexline.core.Enrollment
import org.foggyden.hexline.identity.EnrollProblem
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The enroll screen's steps, every state against every event. */
class EnrollFlowTest {
    private class Device(
        val name: String,
    ) : Enrollment {
        override fun deviceFingerprint() = name

        override suspend fun enroll(
            mailbox: String,
            code: String?,
            name: String,
        ): Enrolled = error("not run here")

        override fun cancel() {}

        override fun seed() = ByteArray(32)

        override fun expectIdentity(fingerprint: String) {}

        override fun mayHaveAsked() = false

        override fun close() {}

        override fun toString() = name
    }

    private val info = CertInfo("fp", ByteArray(32), ByteArray(32), 0u, 1u, true, true, false, false, null)
    private val answer = Enrolled(ByteArray(1), ByteArray(1), "fp", "fp", "Alice", info)
    private val held = Device("held")
    private val made = Device("made")

    private val states =
        listOf(
            EnrollState.Idle(1),
            EnrollState.Starting(1, null),
            EnrollState.Ready(1, null, held, "d"),
            EnrollState.Waiting(1, null, held, "d", "m"),
            EnrollState.Answered(1, null, held, "d", "m", answer, null, false),
            EnrollState.Saving(1, "Alice", "fp"),
            EnrollState.Failed(1, null, held, "d", EnrollProblem.Denied),
            EnrollState.Failed(1, null, null, "", EnrollProblem.NotKept),
            EnrollState.Done(1, "fp"),
        )

    private val events =
        listOf(
            EnrollEvent.Start(null),
            EnrollEvent.Made(1, made, "d2"),
            EnrollEvent.Made(0, made, "d2"),
            EnrollEvent.Made(1, null, ""),
            EnrollEvent.Request(1, "m", "c", "n"),
            EnrollEvent.Request(0, "m", "c", "n"),
            EnrollEvent.Answer(1, answer, null, false),
            EnrollEvent.Answer(0, answer, null, false),
            EnrollEvent.Refused(1, EnrollProblem.Denied, null),
            EnrollEvent.Confirm(1, "fp"),
            EnrollEvent.Confirm(1, "other"),
            EnrollEvent.Confirm(0, "fp"),
            EnrollEvent.Saved(1, "fp", null),
            EnrollEvent.Saved(1, null, EnrollProblem.AnswerNotKept),
            EnrollEvent.Saved(0, "fp", null),
            EnrollEvent.Discard,
            EnrollEvent.Closed,
            EnrollEvent.Seen,
        )

    private fun kind(s: EnrollState) = s::class.simpleName + if (s is EnrollState.Failed && s.enrollee == null) "-none" else ""

    @Test
    fun aDeviceIsClosedExactlyWhenNoStateOrSaveHoldsItAnyMore() {
        for (state in states) {
            for (event in events) {
                val (next, effects) = reduce(state, event)
                val closed = effects.filterIsInstance<EnrollEffect.Close>().map { it.enrollee }
                val saved = effects.filterIsInstance<EnrollEffect.Save>().map { it.enrollee }
                val label = "${kind(state)} + $event"
                // What the state held goes on in the next, to a save, or is closed: once, and nothing else is.
                val before = listOfNotNull(state.owns)
                val gone = before.filter { it !== next.owns && it !in saved }
                val stray = listOfNotNull((event as? EnrollEvent.Made)?.enrollee).filter { it !== next.owns }
                assertEquals(label, (gone + stray).toSet(), closed.toSet())
                assertEquals("$label: closed once", closed.size, closed.toSet().size)
                assertTrue("$label: a device closed and kept", closed.none { it === next.owns || it in saved })
            }
        }
    }

    @Test
    fun aRunGoesOnlyByItsOwnStepsAndAnOlderRunsAreNothing() {
        val idle = EnrollState.Idle(1)
        val starting = EnrollState.Starting(1, null)
        val ready = EnrollState.Ready(1, null, held, "d")
        val waiting = EnrollState.Waiting(1, null, held, "d", "m")
        val answered = EnrollState.Answered(1, null, held, "d", "m", answer, null, false)
        val saving = EnrollState.Saving(1, "Alice", "fp")
        val failed = EnrollState.Failed(1, null, held, "d", EnrollProblem.Denied)
        val cases =
            listOf(
                Triple(idle, EnrollEvent.Start("fp") as EnrollEvent, "Starting 2 fp"),
                Triple(waiting, EnrollEvent.Start(null), "Starting 2 null"),
                Triple(starting, EnrollEvent.Made(1, made, "d2"), "Ready made"),
                Triple(starting, EnrollEvent.Made(0, made, "d2"), "Starting 1 null"),
                Triple(starting, EnrollEvent.Made(1, null, ""), "Failed-none NotKept"),
                Triple(ready, EnrollEvent.Request(1, "m", "c", "n"), "Waiting held"),
                Triple(ready, EnrollEvent.Request(0, "m", "c", "n"), "Ready held"),
                Triple(waiting, EnrollEvent.Request(1, "m", "c", "n"), "Waiting held"),
                Triple(failed, EnrollEvent.Request(1, "m", "c", "n"), "Waiting held"),
                Triple(waiting, EnrollEvent.Answer(1, answer, null, false), "Answered held"),
                Triple(waiting, EnrollEvent.Answer(0, answer, null, false), "Waiting held"),
                Triple(waiting, EnrollEvent.Refused(1, EnrollProblem.Denied, "no"), "Failed held"),
                Triple(answered, EnrollEvent.Confirm(1, "fp"), "Saving"),
                Triple(answered, EnrollEvent.Confirm(1, "other"), "Answered held"),
                Triple(answered, EnrollEvent.Confirm(0, "fp"), "Answered held"),
                Triple(saving, EnrollEvent.Saved(1, "fp", null), "Done"),
                Triple(saving, EnrollEvent.Saved(1, null, EnrollProblem.AnswerNotKept), "Failed-none AnswerNotKept"),
                Triple(saving, EnrollEvent.Saved(0, "fp", null), "Saving"),
                Triple(saving, EnrollEvent.Discard, "Idle"),
                Triple(answered, EnrollEvent.Closed, "Idle"),
                Triple(EnrollState.Done(1, "fp"), EnrollEvent.Seen, "Idle"),
                Triple(ready, EnrollEvent.Seen, "Ready held"),
            )
        for ((state, event, want) in cases) {
            val (next, effects) = reduce(state, event)
            val shown =
                when (next) {
                    is EnrollState.Starting -> "Starting ${next.gen} ${next.renewing}"
                    is EnrollState.Ready -> "Ready ${next.enrollee}"
                    is EnrollState.Waiting -> "Waiting ${next.enrollee}"
                    is EnrollState.Answered -> "Answered ${next.enrollee}"
                    is EnrollState.Failed -> if (next.enrollee == null) "Failed-none ${next.problem}" else "Failed ${next.enrollee}"
                    else -> kind(next)
                }
            assertEquals("${kind(state)} + $event", want, shown)
            // A step that asks for work asks for it for its own run.
            effects.filterIsInstance<EnrollEffect.Enroll>().forEach { assertEquals(state.gen, it.gen) }
            effects.filterIsInstance<EnrollEffect.Save>().forEach { assertEquals(state.gen, it.gen) }
        }
    }
}
