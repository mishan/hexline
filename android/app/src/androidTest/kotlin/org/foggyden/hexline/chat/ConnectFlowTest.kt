package org.foggyden.hexline.chat

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.foggyden.hexline.R
import org.foggyden.hexline.identity.Restoring
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ConnectFlowTest {
    @get:Rule
    val rule = createComposeRule()

    private fun text(id: Int) = InstrumentationRegistry.getInstrumentation().targetContext.getString(id)

    @Test
    fun whatWasTypedIsStillThereAfterARestoreIsCanceled() {
        rule.setContent {
            MaterialTheme {
                ConnectFlow(
                    emptyList(),
                    emptyList(),
                    emptyMap(),
                    Restoring.Idle,
                    null,
                    false,
                    { _, _, _, _ -> },
                    {},
                    { _, _, _, _, _ -> },
                    {},
                    {},
                    { _, _ -> },
                )
            }
        }
        rule.onNode(hasSetTextAction() and hasText(text(R.string.server_address))).performTextInput("wss://a.example/ng")
        rule.onNode(hasText(text(R.string.sign_in_identity))).performClick()
        rule.onNode(hasText(text(R.string.restore_identity))).performClick()
        rule.onNode(hasText(text(R.string.restore_title))).assertExists()
        rule.onNode(hasText(text(R.string.cancel))).performClick()
        rule.onNode(hasSetTextAction() and hasText("wss://a.example/ng")).assertExists()
    }
}
