package org.foggyden.hexline.identity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.io.SyncFailedException

class WriteAtomicallyTest {
    @get:Rule
    val folder = TemporaryFolder()

    @Test
    fun aWriteIsKeptOnlyOnceEachStepSaysItIs() {
        val synced = mutableListOf<File>()
        val file = File(folder.root, "identity-x").apply { writeText("old") }
        // A backup an interrupted write left would be read in its place.
        File(folder.root, "identity-x.bak").writeText("older")
        writeAtomically(file, "new".toByteArray(), syncDir = { synced += it })
        assertEquals("new", file.readText())
        assertFalse(File(folder.root, "identity-x.bak").exists())
        assertEquals(listOf(folder.root), synced)

        val failures =
            listOf(
                "the file's sync" to Pair({ _: java.io.FileOutputStream -> throw SyncFailedException("sync failed") }, { _: File -> }),
                "the directory's sync" to
                    Pair({ out: java.io.FileOutputStream -> out.fd.sync() }, { _: File -> throw IOException("not synced") }),
            )
        for ((step, seams) in failures) {
            file.writeText("old")
            val thrown =
                try {
                    writeAtomically(file, "new".toByteArray(), seams.first, seams.second)
                    false
                } catch (_: IOException) {
                    true
                }
            assertTrue("$step failing is told", thrown)
            assertFalse("$step: nothing left beside it", File(folder.root, "identity-x.new").exists())
        }
        file.writeText("old")
        try {
            writeAtomically(file, "new".toByteArray(), { throw SyncFailedException("sync failed") }) {}
        } catch (_: IOException) {
        }
        assertEquals("a failure before the rename leaves the file as it was", "old", file.readText())
    }
}
