package org.foggyden.hexline.chat

import org.foggyden.hexline.core.KeptRotation
import org.foggyden.hexline.core.RegistrarState
import org.foggyden.hexline.core.RotationRegistrar
import org.foggyden.hexline.core.RotationState
import org.junit.Assert.assertEquals
import org.junit.Test

class RotationNoticeTest {
    private fun at(
        base: String,
        state: RegistrarState,
        refused: String? = null,
    ) = RotationRegistrar(base, listOf("alice"), base == HOME, state, 0, refused)

    @Test
    fun aRotationIsShownAsItsRegistrarsWorstAnswerHomeFirst() {
        val cases =
            listOf(
                listOf(at(HOME, RegistrarState.SENT), at(OTHER, RegistrarState.SIGNED)) to RotationNotice.UnderWay(HOME),
                listOf(at(HOME, RegistrarState.PUBLISHED), at(OTHER, RegistrarState.FROZEN)) to RotationNotice.Frozen(OTHER),
                listOf(at(HOME, RegistrarState.PUBLISHED), at(OTHER, RegistrarState.SUPERSEDED)) to RotationNotice.Superseded(OTHER),
                listOf(at(OTHER, RegistrarState.REFUSED, "not_registered"), at(HOME, RegistrarState.REFUSED, "not_registered")) to
                    RotationNotice.Refused(HOME, "not_registered"),
                listOf(at(HOME, RegistrarState.REFUSED, "not_registered"), at(OTHER, RegistrarState.REFUSED, "revoked")) to
                    RotationNotice.Refused(OTHER, "revoked"),
                listOf(at(HOME, RegistrarState.REFUSED, "revoked"), at(OTHER, RegistrarState.PENDING_ELSEWHERE)) to
                    RotationNotice.PendingElsewhere(OTHER, null),
                listOf(at(HOME, RegistrarState.SUPERSEDED), at(OTHER, RegistrarState.REFUSED, "successor_mismatch")) to
                    RotationNotice.Superseded(HOME),
                listOf(at(HOME, RegistrarState.PENDING_ELSEWHERE), at(OTHER, RegistrarState.REFUSED, "successor_mismatch")) to
                    RotationNotice.Mismatch(OTHER),
                listOf(
                    at(HOME, RegistrarState.PUBLISHED),
                    at(OTHER, RegistrarState.SUPERSEDED),
                    at("https://third.example", RegistrarState.ROTATED_AWAY),
                ) to
                    RotationNotice.RotatedAway("https://third.example"),
            )
        for ((registrars, want) in cases + listOf(emptyList<RotationRegistrar>() to null)) {
            val rotation = KeptRotation("k0", "k1", byteArrayOf(1), RotationState.SENT, byteArrayOf(2), registrars)
            assertEquals("$registrars", want, notice(rotation))
        }
    }

    private companion object {
        const val HOME = "https://hl.example"
        const val OTHER = "https://other.example"
    }
}
