package org.foggyden.hexline.identity

import android.util.Log
import org.foggyden.hexline.core.WholeRead
import java.io.IOException

/**
 * The one writer of what reads of an identity's records found: every key
 * the core has verified revoked, and the floor, only ever added to, beside
 * a whole read where one was whole. Shared by everything in the process
 * that reads the records, the view model and a reset's retries alike, and
 * called on the store queue alone.
 */
class Absorbing(
    private val identities: Identities,
    private val setups: HolderSetups,
    /** Told after each absorb, on the store queue, so what is read from the evidence is read again. */
    private val absorbed: () -> Unit = {},
) {
    /**
     * What the core holds of [fingerprint]'s records written to its files,
     * [whole] kept as its last whole read. What the disk will not take the
     * core still holds for as long as this process lives, and the next call
     * writes it; a whole read kept from before, which predates it, then
     * stands in no more.
     */
    fun absorb(
        fingerprint: String,
        whole: WholeRead?,
    ) {
        val stored = identities.list().find { it.fingerprint == fingerprint } ?: return
        val card = stored.card
        val evidence = setups.evidence(card)
        // The identity's epoch is the floor's home: the whole read's own among it, never the marker
        // alone, and the core's own, which a reset raises before any registrar is known to hold it.
        val floor = maxOf(evidence.floor, whole?.floor ?: 0uL).toLong().coerceAtLeast(setups.floor(card))
        try {
            identities.learned(fingerprint, floor)
        } catch (e: IOException) {
            Log.w("hexline", "device epoch $floor not kept", e)
        }
        // A reset whose outcome is unknown may have moved the floor past what a read now sees.
        val kept = whole?.takeIf { stored.reset?.uncertain != true }
        try {
            identities.recordsRead(fingerprint, kept, evidence.revoked)
        } catch (e: IOException) {
            Log.w("hexline", "a read of the records not kept", e)
            try {
                identities.forgetRead(fingerprint)
            } catch (e: IOException) {
                Log.w("hexline", "a whole read not let go of", e)
            }
        }
        absorbed()
    }
}
