package org.foggyden.hexline.chat

import kotlinx.coroutines.withContext
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.Posted
import org.foggyden.hexline.identity.Identities
import org.foggyden.hexline.identity.KeptRotation
import org.foggyden.hexline.identity.RotationState
import org.foggyden.hexline.identity.read
import org.foggyden.hexline.servers.StoreQueue
import org.foggyden.hexline.servers.stored

/**
 * Posts each rotation sent, with nobody asked, to the registrars it is
 * due at, as its same record every time, and keeps each answer in its
 * file, or that none came, which holds the registrar off for longer each
 * time, or for as long as a rate limit asked.
 * Every read and write of [identities] is on [queue]; [published] is told,
 * on it, of each change.
 */
class RotationPosts(
    private val identities: Identities,
    private val queue: StoreQueue,
    private val post: suspend (registrar: String, record: ByteArray) -> Posted,
    private val now: () -> Long,
    private val published: () -> Unit,
) {
    private var running = false

    /**
     * On the main thread: one run at a time, so no record is posted twice at
     * once. When a post is next due, in seconds, or null where none will be,
     * or another run is under way (which says so itself).
     */
    suspend fun run(): Long? {
        if (running) return null
        running = true
        try {
            // Again once a run has posted, as home's publishing makes the others due.
            val asked = mutableSetOf<Pair<String, String>>()
            while (true) {
                val at = now()
                val due =
                    withContext(queue.dispatcher) { sentRotations(identities) }.flatMap { r ->
                        r.due(at).filter { (r.from to it.base) !in asked }.map { r to it.base }
                    }
                if (due.isEmpty()) return withContext(queue.dispatcher) { nextDue(sentRotations(identities), at) }
                for ((rotation, base) in due) {
                    asked += rotation.from to base
                    var retryAfter: Long? = null
                    val answer =
                        try {
                            post(base, rotation.record!!)
                        } catch (e: CoreException) {
                            if (e is CoreException.RateLimited) retryAfter = e.retryAfter?.toLong()
                            null
                        }
                    val postedAt = now()
                    withContext(queue.dispatcher) {
                        stored {
                            // Only while it is still the rotation posted: not once finished, or its successor gone.
                            val kept =
                                sentRotations(
                                    identities,
                                ).find { it.from == rotation.from && it.record.contentEquals(rotation.record) }
                            if (kept != null) {
                                identities.keep(kept.posted(base, answer, postedAt, retryAfter))
                                published()
                            }
                        }
                    }
                }
            }
        } finally {
            running = false
        }
    }

    /** The first time from [at] that any of [rotations] is due somewhere. */
    private fun nextDue(
        rotations: List<KeptRotation>,
        at: Long,
    ): Long? {
        // One posted earlier in the run, due again while a later post was out: at once.
        if (rotations.any { it.due(at).isNotEmpty() }) return at
        // Due changes only at these: a registrar's wait ending, a held time coming.
        val times =
            rotations
                .flatMap { r -> r.registrars.flatMap { listOf(it.postedAt + it.wait, it.until) } }
                .filter { it > at }
                .sorted()
        return times.firstOrNull { t -> rotations.any { it.due(t).isNotEmpty() } }
    }
}

/** Each rotation sent whose successor this phone keeps, as its file has it: on the store queue. */
fun sentRotations(identities: Identities): List<KeptRotation> =
    identities.list().mapNotNull { k ->
        k.rotatingFrom?.let { identities.rotation(it).read }?.takeIf { it.state == RotationState.Sent && it.to == k.fingerprint }
    }
