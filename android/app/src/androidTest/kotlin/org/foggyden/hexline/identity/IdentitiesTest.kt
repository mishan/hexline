package org.foggyden.hexline.identity

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.holderMint
import org.foggyden.hexline.core.newIdentity
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
        val kept = identities().save(SEED.copyOf(), CERT, CARD, "alice@example", null)
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
        identities().save(SEED.copyOf(), CERT, CARD, null, null)
        identities().save(SEED2.copyOf(), CERT2, CARD, null, null)
        assertArrayEquals(CERT2, identities().list().single().cert)
        assertArrayEquals(SEED2, identities().device(FINGERPRINT)?.second)
        assertEquals("one seed left", 1, secrets.listFiles().orEmpty().size)
    }

    @Test
    fun theRegistrarAnIdentityCameFromIsKeptToRenewItAt() {
        identities().save(SEED.copyOf(), CERT, CARD, "alice@example", "reg.example")
        assertEquals("reg.example", identities().list().single().registrar)
        identities().save(SEED2.copyOf(), CERT2, CARD, "alice@example", "reg.example")
        assertEquals("a new device keeps it", "reg.example", identities().list().single().registrar)
    }

    @Test
    fun anEnrolledDevicesMailboxAndItsQuietRenewalAreKeptForThatCertificateAlone() {
        identities().save(SEED.copyOf(), CERT, CARD, "alice@example", null, "hl.example")
        identities().renewTried(FINGERPRINT, CERT2, 100, true)
        assertEquals("another certificate's renewal changes nothing", 0L, identities().list().single().renewTried)
        identities().renewTried(FINGERPRINT, CERT, 100, true)
        val tried = identities().list().single()
        assertEquals(listOf("hl.example", 100L, true), listOf(tried.mailbox, tried.renewTried, tried.noHolder))
        // A certificate kept anew is a renewal done: nothing tried for it yet.
        identities().save(SEED.copyOf(), CERT, CARD, "alice@example", null, "hl.example")
        val renewed = identities().list().single()
        assertEquals(listOf("hl.example", 0L, false), listOf(renewed.mailbox, renewed.renewTried, renewed.noHolder))
    }

    @Test
    fun aCertificateIsKeptOnlyBesideTheKeyItCertifies() {
        assertThrows(CoreException::class.java) { identities().save(OTHER, CERT, CARD, null, null) }
        assertThrows(CoreException::class.java) { identities().save(SEED.copyOf(), byteArrayOf(1, 2, 3), CARD, null, null) }
        assertTrue(identities().list().isEmpty())
        assertTrue("nothing written", secrets.listFiles().isNullOrEmpty() && files().isEmpty())
    }

    @Test
    fun aFileAlteredOrCutShortListsAsNothingAndTheRestStillList() {
        identities().save(SEED.copyOf(), CERT, CARD, null, null)
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
        identities().save(SEED.copyOf(), CERT, CARD, null, null)
        val file = files().single()
        file.renameTo(File(dir, file.name + ".bak"))
        assertEquals(listOf(FINGERPRINT), identities().list().map { it.fingerprint })
    }

    @Test
    fun anIdentityWhoseSeedWillNeverOpenIsForgotten() {
        identities().save(SEED.copyOf(), CERT, CARD, null, null)
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
        assertNull(identities().device(FINGERPRINT)?.second)
        assertTrue(identities().list().isEmpty())
        assertTrue("its file goes too", files().isEmpty())
    }

    @Test
    fun everyWriteKeepsWhatASuccessorCarries() {
        identities().keep(KeptRotation(PREDECESSOR, FINGERPRINT, CARD, RotationState.Holding))
        identities().save(
            SEED.copyOf(),
            CERT,
            CARD,
            "alice@example",
            "reg.example",
            unfinished = true,
            rotatingFrom = PREDECESSOR,
            rotation = RECORD,
        )
        val writes =
            listOf<Pair<String, () -> Unit>>(
                "renewTried" to { identities().renewTried(FINGERPRINT, CERT, 100, true) },
                "intends" to { identities().intends(FINGERPRINT, "alice@example") },
                "renewed" to { identities().renewed(FINGERPRINT, CERT, replacing = CERT) },
                "unrecoverable" to { identities().unrecoverable(FINGERPRINT) },
                "committed" to { identities().committed(FINGERPRINT, CARD, "alice@example") },
                "saved anew, as a renewal" to { identities().save(SEED.copyOf(), CERT, CARD, "alice@example", "reg.example") },
            )
        for ((what, write) in writes) {
            write()
            for (kept in listOf(identities().list().single(), identities().list().single().held())) {
                assertEquals(what, PREDECESSOR, kept.rotatingFrom)
                assertArrayEquals(what, RECORD, kept.rotation)
            }
        }
        identities().rotated(FINGERPRINT, CARD)
        val done = identities().list().single()
        assertNull("the rotation finished", done.rotatingFrom)
        assertArrayEquals("its record kept to show", RECORD, done.rotation)
    }

    @Test
    fun aRotationIsKeptWholeAndItsSuccessorOnlyOnceItNamesIt() {
        assertThrows(IllegalStateException::class.java) {
            identities().save(SEED.copyOf(), CERT, CARD, null, null, rotatingFrom = PREDECESSOR, rotation = RECORD)
        }
        assertTrue("nothing kept", identities().list().isEmpty() && secrets.listFiles().isNullOrEmpty())
        val sent = sending()
        val read = identities().rotation(PREDECESSOR).read!!
        assertEquals(sent.copy(card0 = read.card0, record = read.record), read)
        assertArrayEquals(CARD, read.card0)
        assertArrayEquals(RECORD, read.record)
        assertEquals("kept by its predecessor alone", FoundRotation.None, identities().rotation(FINGERPRINT))
        assertEquals(PREDECESSOR, identities().list().single().rotatingFrom)
    }

    @Test
    fun aRotationIsSentOnlyWhileItsSuccessorIsKeptAndOnceSentIsOnlyFinished() {
        identities().keep(KeptRotation(PREDECESSOR, FINGERPRINT, CARD, RotationState.Signed, RECORD))
        val sent = KeptRotation(PREDECESSOR, FINGERPRINT, CARD, RotationState.Sent, RECORD)
        assertThrows("discarded by another start", IllegalStateException::class.java) { identities().keep(sent) }
        sending()
        for (undo in listOf(
            sent.copy(state = RotationState.Signed),
            sent.copy(to = "k-other"),
            sent.copy(record = byteArrayOf(1)),
        )) {
            assertThrows(IllegalStateException::class.java) { identities().keep(undo) }
        }
        assertThrows("nor let go of while its successor waits", IllegalStateException::class.java) {
            identities().forgetRotation(PREDECESSOR)
        }
        identities().delete(PREDECESSOR)
        assertEquals("nor by its predecessor's delete", RotationState.Sent, identities().rotation(PREDECESSOR).read?.state)
        identities().keep(sent.copy(backedUp = true))
        assertTrue(identities().rotation(PREDECESSOR).read!!.backedUp)

        // Finished: the successor is the identity, and its rotation goes with it.
        identities().rotated(FINGERPRINT, CARD)
        assertEquals(FoundRotation.None, identities().rotation(PREDECESSOR))
        assertNull(identities().list().single().rotatingFrom)
    }

    @Test
    fun aRotationWhoseSyncFailedIsStillSent() {
        identities().keep(KeptRotation(PREDECESSOR, FINGERPRINT, CARD, RotationState.Holding))
        identities().save(SEED.copyOf(), CERT, CARD, null, null, rotatingFrom = PREDECESSOR, rotation = RECORD)
        val unsynced = Identities(context, SecretStore(context, alias, secrets), dir, syncDir = { throw java.io.IOException("no sync") })
        assertThrows(java.io.IOException::class.java) {
            unsynced.keep(KeptRotation(PREDECESSOR, FINGERPRINT, CARD, RotationState.Sent, RECORD))
        }
        assertEquals(RotationState.Sent, identities().rotation(PREDECESSOR).read?.state)
        assertThrows(IllegalStateException::class.java) { identities().forgetRotation(PREDECESSOR) }
        assertEquals(emptyList<Pair<String, String>>(), identities().unsentRotations())
    }

    @Test
    fun aSentRotationAFinishLeftIsSweptAndOneWhoseSuccessorIsGoneKeepsItsHold() {
        sending()
        val bytes = files().single { it.name.startsWith("rotation-") }.readBytes()
        identities().rotated(FINGERPRINT, CARD)
        // As a finish cut short between the identity and the file leaves it.
        writeAtomically(File(dir, "rotation-left"), bytes)
        identities().sweepOrphans()
        assertTrue("swept", files().none { it.name.startsWith("rotation-") })

        identities().delete(FINGERPRINT)
        writeAtomically(File(dir, "rotation-left"), bytes)
        assertEquals("its successor gone, the hold it names stays", emptyList<Pair<String, String>>(), identities().unsentRotations())
    }

    @Test
    fun aRotationsFileThatDoesNotReadIsToldApartAndNotWrittenOver() {
        sending()
        files().single { it.name.startsWith("rotation-") }.writeText("{")
        assertEquals(FoundRotation.Unreadable, identities().rotation(PREDECESSOR))
        assertThrows(IllegalStateException::class.java) {
            identities().keep(KeptRotation(PREDECESSOR, FINGERPRINT, CARD, RotationState.Holding))
        }
    }

    @Test
    fun aStartDiscardsASuccessorWhoseRotationWasNeverSentAndNothingElse() {
        val k0 = newIdentity("Bob")
        val device = holderMint(k0.seed, k0.card, "Pixel")
        identities().save(device.deviceSeed, device.cert, k0.card, null, null)
        identities().keep(KeptRotation(k0.fingerprint, FINGERPRINT, CARD, RotationState.Holding))
        assertEquals("held, and not yet kept", listOf(k0.fingerprint to FINGERPRINT), identities().unsentRotations())
        identities().save(SEED.copyOf(), CERT, CARD, null, null, rotatingFrom = k0.fingerprint, rotation = RECORD)
        assertEquals(listOf(k0.fingerprint to FINGERPRINT), identities().unsentRotations())
        identities().discardRotation(k0.fingerprint, FINGERPRINT)
        assertEquals("the predecessor untouched", listOf(k0.fingerprint), identities().list().map { it.fingerprint })
        assertEquals(FoundRotation.None, identities().rotation(k0.fingerprint))

        // A rotation's file naming an identity kept as no successor of it.
        identities().keep(KeptRotation(PREDECESSOR, k0.fingerprint, CARD, RotationState.Holding))
        assertEquals(emptyList<Pair<String, String>>(), identities().unsentRotations())
        identities().discardRotation(PREDECESSOR, k0.fingerprint)
        assertEquals(listOf(k0.fingerprint), identities().list().map { it.fingerprint })
    }

    @Test
    fun aSuccessorIsDiscardedByItsRotationsFileOnlyWhenThatIsGoneOrAnothers() {
        val found = mutableMapOf<String, Any?>()
        for (case in listOf("gone", "another's", "unreadable")) {
            identities().keep(KeptRotation(PREDECESSOR, FINGERPRINT, CARD, RotationState.Holding))
            identities().save(SEED.copyOf(), CERT, CARD, null, null, rotatingFrom = PREDECESSOR, rotation = RECORD)
            val file = files().single { it.name.startsWith("rotation-") }
            when (case) {
                "gone" -> identities().forgetRotation(PREDECESSOR)
                "another's" -> writeAtomically(file, KeptRotation(PREDECESSOR, "k-other", CARD, RotationState.Sent, RECORD).encode())
                else -> file.writeText("{")
            }
            val unsent = identities().unsentRotations()
            for ((from, successor) in unsent) identities().discardRotation(from, successor)
            found[case] = unsent
            found["$case: the successor kept"] = identities().list().isNotEmpty()
            found["$case: its file"] = files().any { it.name.startsWith("rotation-") } to identities().rotation(PREDECESSOR).read?.to
            identities().delete(FINGERPRINT)
            files().filter { it.name.startsWith("rotation-") }.forEach { it.delete() }
        }
        val discarded = listOf(PREDECESSOR to FINGERPRINT)
        assertEquals(
            mapOf(
                "gone" to discarded,
                "gone: the successor kept" to false,
                "gone: its file" to (false to null),
                "another's" to discarded,
                "another's: the successor kept" to false,
                "another's: its file" to (true to "k-other"),
                "unreadable" to emptyList<Pair<String, String>>(),
                "unreadable: the successor kept" to true,
                "unreadable: its file" to (true to null),
            ),
            found,
        )
    }

    @Test
    fun aRotationTheDiskDidNotKeepIsAnError() {
        val cut =
            Identities(context, SecretStore(context, alias, secrets), dir) { file, bytes ->
                writeAtomically(
                    file,
                    bytes.copyOf(
                        bytes.size - 1,
                    ),
                )
            }
        assertThrows(java.io.IOException::class.java) {
            cut.keep(KeptRotation(PREDECESSOR, FINGERPRINT, CARD, RotationState.Holding))
        }
    }

    /** This test's identity kept as [PREDECESSOR]'s successor, its rotation sent. */
    private fun sending(): KeptRotation {
        identities().keep(KeptRotation(PREDECESSOR, FINGERPRINT, CARD, RotationState.Holding))
        identities().save(SEED.copyOf(), CERT, CARD, null, null, rotatingFrom = PREDECESSOR, rotation = RECORD)
        val sent =
            KeptRotation(
                PREDECESSOR,
                FINGERPRINT,
                CARD,
                RotationState.Sent,
                RECORD,
                listOf(RotationRegistrar("https://reg.example", listOf("alice"), home = true, RegistrarState.Pending, 1_234)),
                backedUp = true,
            )
        identities().keep(sent)
        return sent
    }

    private companion object {
        const val PREDECESSOR = "k0"
        val RECORD = byteArrayOf(0xa6.toByte(), 1, 2, 3)

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
