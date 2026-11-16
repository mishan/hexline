package org.foggyden.hexline.chat

import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.Enrollment
import org.foggyden.hexline.core.newerCard
import org.foggyden.hexline.core.renewalDue
import org.foggyden.hexline.identity.Identities
import org.foggyden.hexline.identity.StoredIdentity
import org.foggyden.hexline.identity.standing
import org.foggyden.hexline.identity.usable
import org.foggyden.hexline.secrets.SecretUnavailable
import org.foggyden.hexline.servers.StoreQueue
import java.io.IOException

/**
 * Renews, with nobody typing, each enrolled identity with a third of its
 * certificate's life left, at the mailbox it was enrolled through, where a
 * holder stands by for it (enrollment section 8); once a day at most, an
 * unreachable mailbox aside. Where none stands by, the identity is marked
 * so the person is asked for a code. Every read and write of [identities]
 * is on [queue]; [published] is told, on it, of each change.
 */
class QuietRenewal(
    private val identities: Identities,
    private val queue: StoreQueue,
    private val enroll: (renewing: Pair<ByteArray, ByteArray>?, expecting: String?) -> Enrollment,
    private val now: () -> Long,
    private val published: () -> Unit,
) {
    private var running = false

    /** On the main thread: one run at a time. */
    suspend fun run() {
        if (running) return
        running = true
        try {
            val at = now()
            val due =
                withContext(queue.dispatcher) {
                    identities.list().filter {
                        it.mailbox != null &&
                            renewalDue(it.info.issued, it.info.expires, at.toULong()) &&
                            standing(it, at).usable &&
                            at - it.renewTried >= DAY
                    }
                }
            for (kept in due) renew(kept)
        } finally {
            running = false
        }
    }

    private suspend fun renew(kept: StoredIdentity) {
        var seed: ByteArray? = null
        // One record for the device, its certificate and its mailbox: the one
        // chosen, unless another has taken its place since.
        val (renewing, mine) =
            try {
                val (current, held) =
                    withContext(queue.dispatcher) {
                        identities.device(kept.fingerprint)?.also { seed = it.second }
                    } ?: return
                if (!current.cert.contentEquals(kept.cert) || current.mailbox == null) return
                current to enroll(held to current.cert, null)
            } catch (_: SecretUnavailable) {
                return
            } catch (_: CoreException) {
                return
            } finally {
                seed?.fill(0)
            }
        // Noted before the holder is asked: a process killed or frozen while
        // it waits has asked, and is not to ask again today.
        note(renewing, now(), false)
        try {
            val answer = mine.enroll(renewing.mailbox!!, null, renewing.info.name ?: DEVICE_NAME)
            val renewed = mine.seed()
            queue.scope
                .async {
                    try {
                        // Kept only for the certificate it renewed: not if deleted or replaced meanwhile.
                        val now = identities.list().find { it.fingerprint == kept.fingerprint }
                        if (now != null && now.cert.contentEquals(renewing.cert) && answer.fingerprint == kept.fingerprint) {
                            identities.save(renewed, answer.cert, newerCard(now.card, answer.card), now.handle, now.registrar, now.mailbox)
                            published()
                        }
                    } finally {
                        renewed.fill(0)
                    }
                }.await()
        } catch (e: CoreException) {
            when {
                // Offline before a holder could be asked: not a try after all.
                e is CoreException.Connect && !mine.mayHaveAsked() -> note(renewing, renewing.renewTried, renewing.noHolder)
                e is CoreException.Refused && e.code == "no_holder" -> note(renewing, now(), true)
                else -> note(renewing, now(), false)
            }
        } catch (_: SecretUnavailable) {
            return
        } catch (_: IOException) {
            return
        } finally {
            // Let go of while it waited (the screen gone): the wait ends too.
            mine.cancel()
            mine.close()
        }
    }

    /** [renewing]'s try as [at] and [noHolder], for its certificate alone. */
    private fun note(
        renewing: StoredIdentity,
        at: Long,
        noHolder: Boolean,
    ) = queue.scope.launch {
        identities.renewTried(renewing.fingerprint, renewing.cert, at, noHolder)
        published()
    }

    private companion object {
        const val DAY = 86_400L

        /** What a device asks to be called when it renews with no name of its own. */
        const val DEVICE_NAME = "Hexline"
    }
}
