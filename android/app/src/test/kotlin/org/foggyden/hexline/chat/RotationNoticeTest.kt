package org.foggyden.hexline.chat

import org.foggyden.hexline.identity.KeptRotation
import org.foggyden.hexline.identity.RegistrarState
import org.foggyden.hexline.identity.RotationRegistrar
import org.foggyden.hexline.identity.RotationState
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
                listOf(at(HOME, RegistrarState.Sent), at(OTHER, RegistrarState.Signed)) to RotationNotice.UnderWay(HOME),
                listOf(at(HOME, RegistrarState.Published), at(OTHER, RegistrarState.Frozen)) to RotationNotice.Frozen(OTHER),
                listOf(at(HOME, RegistrarState.Published), at(OTHER, RegistrarState.Superseded)) to RotationNotice.Superseded(OTHER),
                listOf(at(OTHER, RegistrarState.Refused, "revoked"), at(HOME, RegistrarState.Refused, "not_registered")) to
                    RotationNotice.Refused(HOME, "not_registered"),
                listOf(at(HOME, RegistrarState.Refused, "revoked"), at(OTHER, RegistrarState.PendingElsewhere)) to
                    RotationNotice.PendingElsewhere(OTHER, null),
                listOf(at(HOME, RegistrarState.Superseded), at(OTHER, RegistrarState.Refused, "successor_mismatch")) to
                    RotationNotice.Superseded(HOME),
                listOf(at(HOME, RegistrarState.PendingElsewhere), at(OTHER, RegistrarState.Refused, "successor_mismatch")) to
                    RotationNotice.Mismatch(OTHER),
                listOf(
                    at(HOME, RegistrarState.Published),
                    at(OTHER, RegistrarState.Superseded),
                    at("https://third.example", RegistrarState.RotatedAway),
                ) to
                    RotationNotice.RotatedAway("https://third.example"),
            )
        for ((registrars, want) in cases + listOf(emptyList<RotationRegistrar>() to null)) {
            val rotation = KeptRotation("k0", "k1", byteArrayOf(1), RotationState.Sent, byteArrayOf(2), registrars)
            assertEquals("$registrars", want, notice(rotation))
        }
    }

    private companion object {
        const val HOME = "https://hl.example"
        const val OTHER = "https://other.example"
    }
}
