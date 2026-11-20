package org.foggyden.hexline.chat

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.hasContentDescription
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isSelectable
import androidx.compose.ui.test.isSelected
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.foggyden.hexline.R
import org.foggyden.hexline.core.CertInfo
import org.foggyden.hexline.core.KeptRotation
import org.foggyden.hexline.core.RegistrarState
import org.foggyden.hexline.core.RotationRegistrar
import org.foggyden.hexline.core.RotationState
import org.foggyden.hexline.identity.Enrolling
import org.foggyden.hexline.identity.Restoring
import org.foggyden.hexline.identity.StoredIdentity
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ConnectFlowTest {
    @get:Rule
    val rule = createComposeRule()

    private fun text(
        id: Int,
        vararg args: Any,
    ) = InstrumentationRegistry.getInstrumentation().targetContext.getString(id, *args)

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
                    { _, _, _, _, _, _ -> },
                    {},
                    {},
                    { _, _ -> },
                    Enrolling.Idle,
                    {},
                    { _, _, _, _ -> },
                    { _, _ -> },
                    {},
                    {},
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

    @Test
    fun aRotationsWorstAnswerIsShownOnTheEntryOfTheIdentityItMovesAwayFrom() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val until = 1_900_000_000L
        val cases =
            listOf(
                rotation(at(HOME, RegistrarState.SENT)) to text(R.string.rotation_under_way, "hl.example"),
                rotation(at(HOME, RegistrarState.PENDING, until = until)) to
                    text(R.string.rotation_pending, "hl.example", publishTime(ctx, until)),
                rotation(at(HOME, RegistrarState.PENDING_ELSEWHERE, until = until)) to
                    text(R.string.rotation_pending_elsewhere, "hl.example", publishTime(ctx, until)),
                rotation(at(HOME, RegistrarState.PENDING_ELSEWHERE)) to text(R.string.rotation_pending_elsewhere_untimed, "hl.example"),
                rotation(at(HOME, RegistrarState.FROZEN)) to text(R.string.rotation_frozen, "hl.example"),
                rotation(at(HOME, RegistrarState.SUPERSEDED)) to text(R.string.rotation_superseded, "hl.example"),
                rotation(at(HOME, RegistrarState.ROTATED_AWAY)) to text(R.string.rotation_rotated_away, "hl.example"),
                rotation(
                    at(HOME, RegistrarState.REFUSED, "successor_mismatch"),
                ) to text(R.string.rotation_successor_mismatch, "hl.example"),
                rotation(at(HOME, RegistrarState.REFUSED, "revoked")) to text(R.string.rotation_revoked, "hl.example"),
                rotation(at(HOME, RegistrarState.REFUSED, "not_registered")) to text(R.string.rotation_not_registered, "hl.example"),
                // Published at home: what another registrar answered, the worse.
                rotation(at(HOME, RegistrarState.PUBLISHED), at(OTHER, RegistrarState.SUPERSEDED)) to
                    text(R.string.rotation_superseded, "other.example"),
                rotation(at(HOME, RegistrarState.PUBLISHED), at(OTHER, RegistrarState.REFUSED, "successor_mismatch")) to
                    text(R.string.rotation_successor_mismatch, "other.example"),
            )
        var rotations by mutableStateOf(emptyMap<String, KeptRotation>())
        rule.setContent { Flow(rotations) }
        rule.onNode(hasText(text(R.string.sign_in_identity))).performClick()
        for ((rotation, want) in cases) {
            rotations = mapOf(K0.fingerprint to rotation)
            rule.onNode(hasText(want)).assertExists(rotation.registrars.toString())
        }
    }

    @Test
    fun whatMayBeSomeoneElsesMoveIsABannerWhicheverWayThePersonSignsInWhoseDetailsShowTheEntrysText() {
        val name = "alice@hl.example"
        val cases =
            listOf(
                at(HOME, RegistrarState.FROZEN) to null,
                at(HOME, RegistrarState.REFUSED, "not_registered") to null,
                at(HOME, RegistrarState.REFUSED, "revoked") to
                    (text(R.string.rotation_revoked_banner, name, "hl.example") to text(R.string.rotation_revoked, "hl.example")),
                at(HOME, RegistrarState.PENDING_ELSEWHERE) to
                    (
                        text(R.string.rotation_pending_elsewhere_banner, name) to
                            text(R.string.rotation_pending_elsewhere_untimed, "hl.example")
                    ),
                at(HOME, RegistrarState.REFUSED, "successor_mismatch") to
                    (
                        text(
                            R.string.rotation_mismatch_banner,
                            name,
                            "hl.example",
                        ) to text(R.string.rotation_successor_mismatch, "hl.example")
                    ),
                at(HOME, RegistrarState.SUPERSEDED) to
                    (text(R.string.rotation_superseded_banner, name) to text(R.string.rotation_superseded, "hl.example")),
                at(HOME, RegistrarState.ROTATED_AWAY) to
                    (text(R.string.rotation_rotated_away_banner, name) to text(R.string.rotation_rotated_away, "hl.example")),
            )
        val banners = cases.mapNotNull { it.second?.first }
        var rotations by mutableStateOf(emptyMap<String, KeptRotation>())
        rule.setContent { Flow(rotations) }
        for ((registrar, want) in cases) {
            rotations = mapOf(K0.fingerprint to rotation(registrar))
            rule.onNode(hasText(text(R.string.sign_in_password)) and isSelectable()).performClick()
            rule.onNode(hasText(text(R.string.sign_in_password)) and isSelected()).assertExists()
            if (want == null) {
                for (b in banners) rule.onNode(hasText(b)).assertDoesNotExist()
                continue
            }
            val (banner, full) = want
            rule.onNode(hasText(banner)).assertExists("${registrar.state}")
            rule.onNode(hasText(full)).assertDoesNotExist()
            rule.onNode(hasContentDescription(text(R.string.rotation_details_label, name))).performClick()
            rule.onNode(hasText(full)).assertExists("${registrar.state}, opened")
            rule.onNode(hasText(text(R.string.sign_in_password)) and isSelected()).assertExists("${registrar.state}, still by password")
            rule.onNode(hasText(text(R.string.close))).performClick()
            rule.onNode(hasText(full)).assertDoesNotExist()
        }
    }

    @Composable
    private fun Flow(rotations: Map<String, KeptRotation>) =
        MaterialTheme {
            ConnectFlow(
                emptyList(),
                listOf(K0),
                emptyMap(),
                Restoring.Idle,
                null,
                false,
                { _, _, _, _ -> },
                {},
                { _, _, _, _, _, _ -> },
                {},
                {},
                { _, _ -> },
                Enrolling.Idle,
                {},
                { _, _, _, _ -> },
                { _, _ -> },
                {},
                {},
                rotations = rotations,
            )
        }

    private fun at(
        base: String,
        state: RegistrarState,
        refused: String? = null,
        until: Long = 0,
    ) = RotationRegistrar(base, listOf("alice"), base == HOME, state, until, refused)

    private fun rotation(vararg registrars: RotationRegistrar) =
        KeptRotation(K0.fingerprint, "k1", byteArrayOf(1), RotationState.SENT, byteArrayOf(2), registrars.toList())

    private companion object {
        const val HOME = "https://hl.example"
        const val OTHER = "https://other.example"

        val K0 =
            StoredIdentity(
                "alice@hl.example",
                byteArrayOf(1),
                byteArrayOf(2),
                CertInfo("k0", byteArrayOf(3), byteArrayOf(4), 0u, 4_000_000_000u, true, true, false, true, "Alice"),
                held = true,
            )
    }
}
