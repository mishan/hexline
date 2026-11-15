package org.foggyden.hexline.servers

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

/**
 * Where every read and write of the saved servers and identities is made,
 * one at a time and in the order it was asked for, for the life of the
 * process rather than of a screen: a forget, a delete or a save asked for
 * as the person leaves is made after they have gone. A task that checks
 * its attempt and then writes does both in one task, so one asked for
 * after it cannot come between.
 */
object StoreQueue {
    val dispatcher = Dispatchers.IO.limitedParallelism(1)

    /** For work that must be made whatever becomes of who asked for it. */
    val scope = CoroutineScope(SupervisorJob() + dispatcher)
}
