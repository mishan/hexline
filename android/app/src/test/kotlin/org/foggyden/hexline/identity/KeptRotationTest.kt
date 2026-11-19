package org.foggyden.hexline.identity

import android.app.Application
import org.foggyden.hexline.core.Posted
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class KeptRotationTest {
    private fun rotation(
        vararg registrars: RotationRegistrar,
        state: RotationState = RotationState.Sent,
    ) = KeptRotation("k0", "k1", byteArrayOf(1), state, byteArrayOf(2), registrars.toList())

    private fun at(
        base: String,
        state: RegistrarState,
        until: Long = 0,
        postedAt: Long = 0,
        wait: Long = if (postedAt > 0) REPOST_FLOOR else 0,
    ) = RotationRegistrar(base, listOf("alice"), base == HOME, state, until, postedAt = postedAt, wait = wait)

    @Test
    fun aRegistrarsAnswerIsKeptForItAloneAndReadBackFromTheFile() {
        // Held before, so what a later answer does not say is cleared.
        val held = at(HOME, RegistrarState.Pending, until = 50, postedAt = 1)
        for ((answer, want) in listOf(
            Posted.Published to at(HOME, RegistrarState.Published, postedAt = NOW),
            Posted.Frozen to at(HOME, RegistrarState.Frozen, postedAt = NOW),
            Posted.Pending(100u) to at(HOME, RegistrarState.Pending, 100, NOW),
            Posted.PendingElsewhere(200u) to at(HOME, RegistrarState.PendingElsewhere, 200, NOW),
            Posted.PendingElsewhere(null) to at(HOME, RegistrarState.PendingElsewhere, postedAt = NOW),
            Posted.Superseded("c2") to at(HOME, RegistrarState.Superseded, postedAt = NOW).copy(supersededBy = "c2"),
            Posted.Refused("successor_mismatch") to at(HOME, RegistrarState.Refused, postedAt = NOW).copy(refused = "successor_mismatch"),
            Posted.RotatedAway("k2") to at(HOME, RegistrarState.RotatedAway, postedAt = NOW).copy(rotatedTo = "k2"),
            null to held.copy(postedAt = NOW, failures = 1),
        )) {
            val posted = rotation(held, at(OTHER, RegistrarState.Signed)).posted(HOME, answer, NOW)
            assertEquals("$answer", listOf(want, at(OTHER, RegistrarState.Signed)), posted.registrars)
            assertEquals("$answer, read back", posted.registrars, KeptRotation.decode(posted.encode())?.registrars)
        }
        assertThrows(IllegalArgumentException::class.java) {
            rotation(held).posted(OTHER, Posted.Published, NOW)
        }
    }

    @Test
    fun aRecordIsPostedHomeFirstAndNotAgainOnceHeldUntilItsTimeOrRefusedForGood() {
        val cases =
            listOf(
                "not yet sent" to (rotation(at(HOME, RegistrarState.Signed), state = RotationState.Signed) to emptyList()),
                "home first" to (rotation(at(HOME, RegistrarState.Sent), at(OTHER, RegistrarState.Signed)) to listOf(HOME)),
                "held" to (rotation(at(HOME, RegistrarState.Pending, NOW + 1)) to emptyList()),
                "held till now" to (rotation(at(HOME, RegistrarState.Pending, NOW)) to listOf(HOME)),
                "behind another" to (rotation(at(HOME, RegistrarState.PendingElsewhere, NOW + 1)) to emptyList()),
                "behind another till now" to (rotation(at(HOME, RegistrarState.PendingElsewhere, NOW)) to listOf(HOME)),
                "frozen" to (rotation(at(HOME, RegistrarState.Frozen)) to listOf(HOME)),
                "posted just now" to (rotation(at(HOME, RegistrarState.Sent, postedAt = NOW - REPOST_FLOOR + 1)) to emptyList()),
                "frozen just now" to (rotation(at(HOME, RegistrarState.Frozen, postedAt = NOW - REPOST_FLOOR + 1)) to emptyList()),
                "held past its time by a clock ahead" to (rotation(at(HOME, RegistrarState.Pending, NOW - 5, NOW - 1)) to emptyList()),
                "posted in the future by a clock set back since" to
                    (rotation(at(HOME, RegistrarState.Sent, postedAt = NOW + DAY)) to listOf(HOME)),
                "posted a while ago" to (rotation(at(HOME, RegistrarState.Sent, postedAt = NOW - REPOST_FLOOR)) to listOf(HOME)),
                "refused at home" to (rotation(at(HOME, RegistrarState.Refused), at(OTHER, RegistrarState.Signed)) to emptyList()),
                "rotated away at home" to (rotation(at(HOME, RegistrarState.RotatedAway), at(OTHER, RegistrarState.Signed)) to emptyList()),
                "superseded at home" to (rotation(at(HOME, RegistrarState.Superseded), at(OTHER, RegistrarState.Signed)) to emptyList()),
                "published at home" to (rotation(at(HOME, RegistrarState.Published), at(OTHER, RegistrarState.Signed)) to listOf(OTHER)),
                "reattested at home" to (rotation(at(HOME, RegistrarState.Reattested), at(OTHER, RegistrarState.Sent)) to listOf(OTHER)),
                "refused elsewhere" to (rotation(at(HOME, RegistrarState.Published), at(OTHER, RegistrarState.Refused)) to emptyList()),
                "held elsewhere" to (rotation(at(HOME, RegistrarState.CardPut), at(OTHER, RegistrarState.Pending, NOW + 1)) to emptyList()),
            )
        for ((what, case) in cases) {
            val (rotation, want) = case
            assertEquals(what, want, rotation.due(NOW).map { it.base })
        }
    }

    @Test
    fun postsThatGetNoAnswerAreLeftLongerEachTimeUntilOneDoes() {
        var r = rotation(at(HOME, RegistrarState.Sent))
        val waits =
            (0L until 8L).map {
                r = r.posted(HOME, null, NOW + it)
                r.registrars.single().wait
            }
        assertEquals(listOf(60L, 120, 240, 480, 960, 1920, 3600, 3600), waits)
        r = KeptRotation.decode(r.encode())!!
        assertEquals("kept in the file", 3600L to 8, r.registrars.single().let { it.wait to it.failures })
        val last = NOW + 7
        assertEquals("not before its wait", emptyList<String>(), r.due(last + 3599).map { it.base })
        assertEquals("after it", listOf(HOME), r.due(last + 3600).map { it.base })

        val limited = KeptRotation.decode(rotation(at(HOME, RegistrarState.Sent)).posted(HOME, null, NOW, retryAfter = 7200).encode())!!
        assertEquals("a registrar's retry_after, kept", emptyList<String>(), limited.due(NOW + 7199).map { it.base })
        assertEquals(listOf(HOME), limited.due(NOW + 7200).map { it.base })

        val answered = r.posted(HOME, Posted.PendingElsewhere(null), last + 3600).registrars.single()
        assertEquals("an answer starts again", REPOST_FLOOR to 0, answered.wait to answered.failures)
    }

    @Test
    fun theSameAnswerAgainIsLeftLongerEachTimeUntilAnotherComes() {
        for (answer in listOf(Posted.Frozen, Posted.PendingElsewhere(null), Posted.Pending(NOW.toULong()))) {
            var r = rotation(at(HOME, RegistrarState.Sent))
            val waits =
                (0L until 5L).map {
                    r = r.posted(HOME, answer, NOW + it * REPOST_CEILING)
                    r.registrars.single().wait
                }
            assertEquals("$answer", listOf(60L, 60, 120, 240, 480), waits)
            val other = r.posted(HOME, Posted.Pending(NOW.toULong() + 99u), NOW + 5 * REPOST_CEILING).registrars.single()
            assertEquals("$answer, then another", REPOST_FLOOR to 0, other.wait to other.failures)
        }
    }

    @Test
    fun aRetryAfterPastADayIsWaitedForADay() {
        val r = rotation(at(HOME, RegistrarState.Sent)).posted(HOME, null, NOW, retryAfter = Long.MAX_VALUE)
        assertEquals(RETRY_AFTER_CEILING, r.registrars.single().wait)
        assertEquals(listOf(HOME), r.due(NOW + RETRY_AFTER_CEILING).map { it.base })
    }

    private companion object {
        const val HOME = "https://home.example"
        const val OTHER = "https://other.example"
        const val NOW = 1_800_000_000L
        const val DAY = 86_400L
    }
}
