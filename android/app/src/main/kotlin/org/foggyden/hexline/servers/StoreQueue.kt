package org.foggyden.hexline.servers

import android.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.foggyden.hexline.secrets.SecretUnavailable
import java.io.IOException

/**
 * Where every read and write of the saved servers and identities is made,
 * one at a time and in the order it was asked for, for the life of the
 * process rather than of a screen: a forget, a delete or a save asked for
 * as the person leaves is made after they have gone. A task that checks
 * its attempt and then writes does both in one task, so one asked for
 * after it cannot come between.
 */
class StoreQueue(
    val dispatcher: CoroutineDispatcher,
) {
    /** For work that must be made whatever becomes of who asked for it. */
    val scope = CoroutineScope(SupervisorJob() + dispatcher)

    companion object {
        /** The process's: every screen's work in one order. */
        val process = StoreQueue(Dispatchers.IO.limitedParallelism(1))
    }
}

/** [work], a store's, with what a store cannot do now set aside rather than thrown at the app. */
fun stored(work: () -> Unit) {
    try {
        work()
    } catch (e: IOException) {
        Log.w("hexline", "a store write was lost", e)
    } catch (e: SecretUnavailable) {
        Log.w("hexline", "a store write was lost", e)
    }
}
