package org.foggyden.hexline.identity

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequest
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.withContext
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.NotYet
import org.foggyden.hexline.core.ResetRetried
import org.foggyden.hexline.core.shortHash
import org.foggyden.hexline.servers.StoreQueue
import org.foggyden.hexline.servers.stored
import java.util.concurrent.TimeUnit

/** When each identity's reset is next retried: the one place it is asked for. */
interface ResetRetries {
    /** [fingerprint]'s retry in [inSecs], in place of any asked for before: a new reset's outcome. */
    fun schedule(
        fingerprint: String,
        inSecs: Long,
    )

    /** [fingerprint]'s retry in [inSecs] where none is asked for yet, as a start finds a reset kept. */
    fun ensure(
        fingerprint: String,
        inSecs: Long,
    )

    /** No retry for [fingerprint] any more. */
    fun cancel(fingerprint: String)
}

/** Retries asked of WorkManager, so they are made with the app closed and the process gone. */
class WorkResetRetries(
    context: Context,
) : ResetRetries {
    private val work = WorkManager.getInstance(context)

    override fun schedule(
        fingerprint: String,
        inSecs: Long,
    ) {
        work.enqueueUniqueWork(name(fingerprint), ExistingWorkPolicy.REPLACE, request(fingerprint, inSecs))
    }

    override fun ensure(
        fingerprint: String,
        inSecs: Long,
    ) {
        work.enqueueUniqueWork(name(fingerprint), ExistingWorkPolicy.KEEP, request(fingerprint, inSecs))
    }

    override fun cancel(fingerprint: String) {
        work.cancelUniqueWork(name(fingerprint))
    }

    companion object {
        internal const val FINGERPRINT = "fingerprint"

        private fun name(fingerprint: String) = "reset-retry-" + shortHash(fingerprint.toByteArray())

        /**
         * A retry of [fingerprint]'s reset in [inSecs], made only while the
         * phone has a network: a try made without one is not a try, and the
         * core gives a registrar up only after enough tries.
         */
        fun request(
            fingerprint: String,
            inSecs: Long,
        ): OneTimeWorkRequest =
            OneTimeWorkRequestBuilder<ResetRetryWorker>()
                .setInitialDelay(inSecs.coerceAtLeast(0), TimeUnit.SECONDS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .setInputData(workDataOf(FINGERPRINT to fingerprint))
                .build()
    }
}

/** A retry as WorkManager runs it: what is kept for its identity now, posted, and the next asked for last. */
class ResetRetryWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val fingerprint = inputData.getString(WorkResetRetries.FINGERPRINT) ?: return Result.success()
        val identities = Identities(applicationContext)
        val retrier =
            ResetRetrier(identities, CoreHolderSetups, StoreQueue.process, Absorbing(identities, CoreHolderSetups)) {
                System.currentTimeMillis() / 1000
            }
        val next = retrier.run(fingerprint)
        // Last, so a retry canceled before it asks for no other; in place of whatever is asked for
        // now, as a reset asks, so there is only ever one run to come.
        next?.let { WorkResetRetries(applicationContext).schedule(fingerprint, it) }
        return Result.success()
    }
}

/**
 * A reset's retry for an identity: the retry kept for it read from its
 * file as each run starts, never one handed to the run, posted, and what
 * it came to written back with what its reads verified.
 */
class ResetRetrier(
    private val identities: Identities,
    private val setups: HolderSetups,
    private val queue: StoreQueue,
    private val absorbing: Absorbing,
    private val now: () -> Long,
) {
    /**
     * [fingerprint]'s retry made, if one is kept and due: seconds until the
     * next, as what is kept once it is written says, so a newer reset's
     * retry is asked for when it is due; or null for none.
     */
    suspend fun run(fingerprint: String): Long? {
        val stored = withContext(queue.dispatcher) { identities.list().find { it.fingerprint == fingerprint } } ?: return null
        val reset = stored.reset ?: return null
        val retry = reset.retry ?: return null
        // Woken before it is due, as a start asking for one where none was can.
        if (reset.retryAt > now()) return reset.retryAt - now()
        var got: ResetRetried? = null
        var unreadable = false
        var failed: Long? = null
        try {
            got = setups.retryReset(retry, stored.card)
        } catch (e: CoreException.Refused) {
            when (e.code) {
                // A reset of the identity under way: its outcome replaces this one.
                "busy" -> failed = BUSY_WAIT
                // Bytes the core does not take: only a new reset reaches what they were for.
                else -> unreadable = true
            }
        } catch (_: CoreException) {
            failed = RETRY_EVERY
        } finally {
            withContext(NonCancellable + queue.dispatcher) {
                stored {
                    got?.let { r -> identities.retried(fingerprint, r.epoch.toLong()) { kept -> after(kept, r) } }
                    if (unreadable) {
                        identities.retried(fingerprint, reset.epoch) { it.copy(retry = null, pending = emptyList(), unread = true) }
                    }
                }
                absorbing.absorb(fingerprint, null)
            }
            changes.tryEmit(fingerprint)
        }
        val kept = withContext(queue.dispatcher) { identities.list().find { it.fingerprint == fingerprint }?.reset }
        if (kept?.retry == null) return null
        // The same retry, not posted: asked again after a while. Anything else is when the kept one is due.
        if (failed != null && kept.epoch == reset.epoch) return failed
        return maxOf(0, kept.retryAt - now())
    }

    /** [kept] as [r] leaves it: a registrar done no longer counted unreached, and one dropped from the retry counted so. */
    private fun after(
        kept: ResetKept,
        r: ResetRetried,
    ): ResetKept {
        val left = r.notDone.filter { it.registrar !in r.later && it.why != NotYet.OVERTAKEN }
        val (gaveUp, refused) = left.partition { it.why == NotYet.GAVE_UP }
        val reached = (r.done + r.notRegistrars + r.notDone.filter { it.why == NotYet.OVERTAKEN }.map { it.registrar }).toSet()
        return kept.copy(
            retry = r.retry,
            retryAt = r.retryIn?.let { now() + it.toLong() } ?: 0,
            pending = r.later,
            unreset = (kept.unreset + refused.map { it.registrar }).distinct() - reached,
            givenUp = (kept.givenUp + gaveUp.map { it.registrar }).distinct() - reached,
        )
    }

    companion object {
        private const val BUSY_WAIT = 60L
        private const val RETRY_EVERY = 15 * 60L
        private val changes = MutableSharedFlow<String>(extraBufferCapacity = 64)

        /** Each identity whose reset a retry wrote to, to be read again. */
        val changed: SharedFlow<String> = changes
    }
}
