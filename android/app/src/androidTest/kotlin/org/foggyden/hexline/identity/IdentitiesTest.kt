package org.foggyden.hexline.identity

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.secrets.SecretStore
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class IdentitiesTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val alias = "hexline-test-${UUID.randomUUID()}"
    private val secrets = File(context.cacheDir, "$alias-secrets")
    private val dir = File(context.cacheDir, "$alias-identities")

    private fun identities() = Identities(context, SecretStore(context, alias, secrets), dir)

    private fun files() = dir.listFiles().orEmpty().toList()

    @After
    fun cleanUp() {
        secrets.deleteRecursively()
        dir.deleteRecursively()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
    }

    @Test
    fun anIdentityKeptIsListedWithoutItsSeedAndForgottenWhole() {
        assertTrue(identities().list().isEmpty())
        val kept = identities().save(SEED.copyOf(), CERT, CARD, "alice@example")
        assertEquals(FINGERPRINT, kept.fingerprint)
        val listed = identities().list().single()
        assertEquals(listOf(FINGERPRINT, "alice@example"), listOf(listed.fingerprint, listed.handle))
        assertArrayEquals(CERT, listed.cert)
        assertArrayEquals(CARD, listed.card)
        assertTrue(listed.info.canLogin && listed.info.canManage)
        assertArrayEquals(SEED, identities().device(FINGERPRINT)?.second)
        val sealed = (files() + secrets.listFiles().orEmpty()).joinToString { String(it.readBytes(), Charsets.ISO_8859_1) }
        assertTrue("no seed in the clear", !sealed.contains(String(SEED, Charsets.ISO_8859_1)))

        identities().delete(FINGERPRINT)
        assertTrue(identities().list().isEmpty())
        assertNull(identities().device(FINGERPRINT)?.second)
        assertTrue("its seed goes too", secrets.listFiles().isNullOrEmpty())
    }

    @Test
    fun aNewDeviceTakesTheIdentitysPlaceAndTheOldSeedGoes() {
        identities().save(SEED.copyOf(), CERT, CARD, null)
        identities().save(SEED2.copyOf(), CERT2, CARD, null)
        assertArrayEquals(CERT2, identities().list().single().cert)
        assertArrayEquals(SEED2, identities().device(FINGERPRINT)?.second)
        assertEquals("one seed left", 1, secrets.listFiles().orEmpty().size)
    }

    @Test
    fun aCertificateIsKeptOnlyBesideTheKeyItCertifies() {
        assertThrows(CoreException::class.java) { identities().save(OTHER, CERT, CARD, null) }
        assertThrows(CoreException::class.java) { identities().save(SEED.copyOf(), byteArrayOf(1, 2, 3), CARD, null) }
        assertTrue(identities().list().isEmpty())
        assertTrue("nothing written", secrets.listFiles().isNullOrEmpty() && files().isEmpty())
    }

    @Test
    fun aFileAlteredOrCutShortListsAsNothingAndTheRestStillList() {
        identities().save(SEED.copyOf(), CERT, CARD, null)
        val file = files().single()
        val good = file.readText()
        for (bad in listOf("{", good.replace("\"cert\"", "\"crt\""), good.replace("\"card\":\"", "\"card\":\"AAAA"))) {
            file.writeText(bad)
            assertTrue(bad, identities().list().isEmpty())
        }
        // Another identity's file under this one's name.
        File(dir, "identity-000000000000000000000000").writeText(good)
        file.writeText(good)
        assertEquals(listOf(FINGERPRINT), identities().list().map { it.fingerprint })
    }

    @Test
    fun anIdentityLeftOnlyInItsBackupIsListed() {
        identities().save(SEED.copyOf(), CERT, CARD, null)
        val file = files().single()
        file.renameTo(File(dir, file.name + ".bak"))
        assertEquals(listOf(FINGERPRINT), identities().list().map { it.fingerprint })
    }

    @Test
    fun anIdentityWhoseSeedWillNeverOpenIsForgotten() {
        identities().save(SEED.copyOf(), CERT, CARD, null)
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
        assertNull(identities().device(FINGERPRINT)?.second)
        assertTrue(identities().list().isEmpty())
        assertTrue("its file goes too", files().isEmpty())
    }

    private companion object {
        fun hex(s: String) = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

        // An identity and two devices of it, made once with hl-identity and
        // fixed here: the app cannot sign a certificate of its own.
        val SEED = hex("0202020202020202020202020202020202020202020202020202020202020202")
        val SEED2 = hex("0404040404040404040404040404040404040404040404040404040404040404")
        val OTHER = hex("0303030303030303030303030303030303030303030303030303030303030303")
        val CERT =
            hex(
                "a76176016373696758405824fbeefc383034d005006130620730d74936582d87c31f0c23d13e8f50ce590a1dc6843b5bd7284e197e48c54bd4b219fe4d7c4532a2e4b0f97c10530ceb006664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b49d20067657870697265731a7e15d500686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
            )
        val CERT2 =
            hex(
                "a761760163736967584087523261031e0ac080b3510ee22f29bb199e86763b619ee4caf5c62824cd1698b29272578b247f8ce0aebf7e1fbb3a904114a01cbfe18bbef94da49aab825c0b666465766963655820ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c666973737565641a6b49d20067657870697265731a7e15d500686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e63582072b6ee7d98af4a63aae28f4b74aa6fbc2c763cfff33e4f8b59a252c19618656d",
            )
        val CARD =
            hex(
                "a561760163736967584067d88dac70a297fd5f414f8df75ac190a6a6d8f78659c342d4259dda59fae16f57c55711d6c0b05b502616b95d286d97b98b518ff50bf4c013db9a915e30fd0e646e616d65674669787475726567757064617465641a6b49d200686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            )
        const val FINGERPRINT = "6htgz65xb7yfs53dmhdanfmk7fgn995n1571rjnz8a36a1fks5z0"
    }
}
