package org.foggyden.hexline.chat

import org.foggyden.hexline.identity.ResetRetries

/** Retries asked for as WorkManager would be asked: each recorded, none made. */
class FakeRetries : ResetRetries {
    /** Each ask, in order: what it was, for which identity, and in how long. */
    val asked = mutableListOf<Triple<String, String, Long>>()

    override fun schedule(
        fingerprint: String,
        inSecs: Long,
    ) {
        asked += Triple("schedule", fingerprint, inSecs)
    }

    override fun ensure(
        fingerprint: String,
        inSecs: Long,
    ) {
        asked += Triple("ensure", fingerprint, inSecs)
    }

    override fun cancel(fingerprint: String) {
        asked += Triple("cancel", fingerprint, 0)
    }
}
