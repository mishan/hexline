package org.foggyden.hexline.chat

import android.app.Application
import org.foggyden.hexline.core.HeldRenewal
import org.foggyden.hexline.core.certForDevice
import org.foggyden.hexline.core.holderMint
import org.foggyden.hexline.core.newIdentity
import org.foggyden.hexline.identity.StoredIdentity
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn
import org.foggyden.hexline.servers.refusalKey
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class HeldRenewalTest {
    private val made = newIdentity("Carol")
    private val minted = holderMint(made.seed, made.card, "Pixel", 0uL)
    private val kept =
        StoredIdentity("carol", minted.cert, made.card, certForDevice(minted.cert, made.card, minted.deviceSeed), "reg.example").held()
    private val server = Server("wss://a.example/ng", "", SignIn.Identity(kept.fingerprint))
    private val other = Server("wss://b.example/ng", "", SignIn.Identity(kept.fingerprint))

    @Test
    fun aHeldIdentityIsRenewedAsItsDeviceOnlyWhereNoServerHasRefusedThatDevice() {
        val key = refusalKey(server, kept.info.device)
        for ((refusals, want) in listOf(
            emptyMap<String, String>() to HeldRenewal.RENEW,
            mapOf(refusalKey(server, byteArrayOf(1, 2, 3)) to "revoked") to HeldRenewal.RENEW,
            mapOf(key to "revoked") to HeldRenewal.NEW_DEVICE,
            mapOf(key to "rotated") to HeldRenewal.NOTHING,
            mapOf(key to "revoked", refusalKey(other, kept.info.device) to "rotated") to HeldRenewal.NOTHING,
        )) {
            assertEquals("$refusals", want, heldRenewal(kept, refusals))
        }
    }
}
