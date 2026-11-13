package org.foggyden.hexline

import org.foggyden.hexline.core.coreVersion
import org.junit.Assert.assertTrue
import org.junit.Test

class CoreTest {
    @Test
    fun theCoreAnswersThroughItsBindings() {
        val version = coreVersion()
        assertTrue(version, Regex("""\d+\.\d+\.\d+""").matches(version + "x"))
    }
}
