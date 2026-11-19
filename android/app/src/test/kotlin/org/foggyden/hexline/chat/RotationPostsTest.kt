package org.foggyden.hexline.chat

import android.app.Application
import androidx.lifecycle.Lifecycle
import kotlinx.coroutines.CompletableDeferred
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.Posted
import org.foggyden.hexline.identity.KeptRotation
import org.foggyden.hexline.identity.REPOST_FLOOR
import org.foggyden.hexline.identity.RegistrarState
import org.foggyden.hexline.identity.RotationRegistrar
import org.foggyden.hexline.identity.RotationState
import org.foggyden.hexline.identity.read
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** A rotation sent, posted to its registrars with nobody asked, over [ViewModelHarness]. */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class RotationPostsTest : ViewModelHarness() {
    @Test
    fun aRotationIsPostedAtStartAndOnComingToTheFrontOnlyWhenDueHomeFirst() {
        sent()
        model()
        settle()
        assertEquals("at start, home alone", listOf(HOME), posted())
        val until = now + 10 * REPOST_FLOOR
        answer(Posted.Pending(until.toULong()))
        now += REPOST_FLOOR
        front()
        assertEquals("held until its time", listOf(HOME), posted())
        now = until
        front()
        assertEquals("posted again at its time", listOf(HOME, HOME), posted())
        answer(Posted.Published)
        assertEquals("then the others, in the same run", listOf(HOME, HOME, OTHER), posted())
        answer(Posted.Published)
        now += DAY
        front()
        assertEquals("and none once published everywhere", 3, posted().size)
    }

    @Test
    fun inFrontARotationIsPostedAgainWhenNextDueAndNotOnceInTheBack() {
        val waits = mutableListOf<Pair<Long, CompletableDeferred<Unit>>>()
        wait = { seconds -> CompletableDeferred<Unit>().also { waits += seconds to it }.await() }
        sent()
        model()
        process.lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_START)
        settle()
        val until = now + 10 * REPOST_FLOOR
        answer(Posted.Pending(until.toULong()))
        assertEquals("waits for its time", 10 * REPOST_FLOOR, waits.last().first)
        // The clock corrected back a little while it waited: waited out from there.
        now = until - 5
        core { waits.last().second.complete(Unit) }
        settle()
        assertEquals("waits out the rest", 5L, waits.last().first)
        now = until
        core { waits.last().second.complete(Unit) }
        settle()
        assertEquals("posted again then", listOf(HOME, HOME), posted())
        // Still frozen each time: waited on as the file's back-off says, longer as it goes on.
        val waited = mutableListOf<Long>()
        repeat(3) {
            answer(Posted.Frozen)
            val held =
                outside {
                    identities
                        .rotation(PREDECESSOR)
                        .read!!
                        .registrars
                        .single { it.home }
                }
            assertEquals("as the file has it", held.wait, waits.last().first)
            waited += waits.last().first
            now += waits.last().first
            core { waits.last().second.complete(Unit) }
            settle()
        }
        assertEquals("posted again each time", 5, posted().size)
        assertEquals(listOf(REPOST_FLOOR, REPOST_FLOOR, 2 * REPOST_FLOOR), waited)
        answer(Posted.Frozen)
        process.lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
        now += waits.last().first
        core { waits.last().second.complete(Unit) }
        settle()
        assertEquals("not once in the back", 5, posted().size)
    }

    @Test
    fun aRotationIsNotPostedAgainWhileAPostOfItIsOut() {
        sent()
        model()
        settle()
        now += 2 * REPOST_FLOOR
        front()
        assertEquals(listOf(HOME), posted())
        answer(null)
        front()
        assertEquals("nor just after", listOf(HOME), posted())
    }

    @Test
    fun eachAnswerIsKeptInTheFileAndShown() {
        val cases =
            listOf(
                Posted.Published to RegistrarState.Published,
                Posted.Pending((NOW + DAY).toULong()) to RegistrarState.Pending,
                Posted.PendingElsewhere(null) to RegistrarState.PendingElsewhere,
                Posted.Superseded("c2") to RegistrarState.Superseded,
                Posted.RotatedAway("k2") to RegistrarState.RotatedAway,
                Posted.Frozen to RegistrarState.Frozen,
                Posted.Refused("successor_mismatch") to RegistrarState.Refused,
            )
        for ((answer, want) in cases) {
            fresh()
            setups = FakeSetups()
            now = NOW
            sent()
            val vm = model()
            settle()
            answer(answer)
            val kept = outside { identities.rotation(PREDECESSOR).read }
            assertEquals("$answer kept", want, kept?.registrars?.single { it.home }?.state)
            assertEquals("$answer shown as kept", kept?.registrars, vm.rotations.value[PREDECESSOR]?.registrars)
        }
    }

    @Test
    fun anUnansweredPostWaitsTheFloorAndARateLimitedOneItsRetryAfter() {
        val cases =
            listOf(
                CoreException.Connect("unreachable") to REPOST_FLOOR,
                CoreException.RateLimited(null) to REPOST_FLOOR,
                CoreException.RateLimited(10u * REPOST_FLOOR.toULong()) to 10 * REPOST_FLOOR,
            )
        for ((e, wait) in cases) {
            fresh()
            setups = FakeSetups()
            now = NOW
            sent()
            model()
            settle()
            core {
                setups.posts
                    .last()
                    .second
                    .completeExceptionally(e)
            }
            settle()
            now = NOW + wait - 1
            front()
            assertEquals("$e: not posted again before", 1, posted().size)
            now = NOW + wait
            front()
            assertEquals("$e: posted again once waited", 2, posted().size)
        }
    }

    /** This test's identity kept as [PREDECESSOR]'s successor, its rotation sent to a home registrar and another. */
    private fun sent() =
        outside {
            identities.keep(KeptRotation(PREDECESSOR, FINGERPRINT, CARD, RotationState.Holding))
            identities.save(SEED.copyOf(), CERT, CARD, "alice@example", null, rotatingFrom = PREDECESSOR, rotation = RECORD)
            identities.keep(
                KeptRotation(
                    PREDECESSOR,
                    FINGERPRINT,
                    CARD,
                    RotationState.Sent,
                    RECORD,
                    listOf(
                        RotationRegistrar(HOME, listOf("alice"), true, RegistrarState.Sent),
                        RotationRegistrar(OTHER, listOf("alice"), false),
                    ),
                ),
            )
        }

    private fun posted() = setups.posts.map { it.first }

    /** The last post's answer, [answer], or none where null. */
    private fun answer(answer: Posted?) {
        val out = setups.posts.last().second
        core { if (answer == null) out.completeExceptionally(CoreException.Connect("unreachable")) else out.complete(answer) }
        settle()
    }

    /** The app come to the front, and gone to the back again. */
    private fun front() {
        process.lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_START)
        process.lifecycle.handleLifecycleEvent(Lifecycle.Event.ON_STOP)
        settle()
    }

    private companion object {
        const val PREDECESSOR = "k0"
        const val HOME = "https://hl.example"
        const val OTHER = "https://other.example"
        const val NOW = ISSUED + DAY
        val RECORD = byteArrayOf(0xa6.toByte(), 1, 2, 3)
    }
}
