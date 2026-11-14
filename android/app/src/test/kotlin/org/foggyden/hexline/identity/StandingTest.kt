package org.foggyden.hexline.identity

import org.foggyden.hexline.core.CertInfo
import org.junit.Assert.assertEquals
import org.junit.Test

class StandingTest {
    private fun kept(
        issued: Long,
        expires: Long,
    ) = StoredIdentity(
        null,
        byteArrayOf(),
        byteArrayOf(),
        CertInfo("fp", byteArrayOf(), byteArrayOf(), issued.toULong(), expires.toULong(), true, true, false, true, null),
    )

    @Test
    fun anIdentityIsAskedToBeRenewedFromTwoWeeksBeforeItExpiresAndRefusedOutsideItsTime() {
        val issued = 10 * DAY
        val expires = 100 * DAY
        val cases =
            listOf(
                issued - 301 to Standing.NotYetValid,
                issued - 300 to Standing.Good,
                expires - 15 * DAY to Standing.Good,
                expires - 14 * DAY - 1 to Standing.Good,
                expires - 14 * DAY to Standing.Renew(14),
                expires - DAY - 1 to Standing.Renew(2),
                expires - 1 to Standing.Renew(1),
                // The core's line, within the skew a server allows.
                expires + 300 to Standing.Renew(1),
                expires + 301 to Standing.Expired,
                expires + DAY to Standing.Expired,
            )
        for ((now, want) in cases) assertEquals("at $now", want, standing(kept(issued, expires), now))
    }

    private companion object {
        const val DAY = 86_400L
    }
}
