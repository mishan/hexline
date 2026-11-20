package org.foggyden.hexline.identity

import org.foggyden.hexline.core.KeptRotation

/** What a rotation's file holds: none, one that does not read, or the rotation. */
sealed interface FoundRotation {
    data object None : FoundRotation

    data object Unreadable : FoundRotation

    data class Read(
        val rotation: KeptRotation,
    ) : FoundRotation
}

/** The rotation found, if one was and it read. */
val FoundRotation.read: KeptRotation? get() = (this as? FoundRotation.Read)?.rotation
