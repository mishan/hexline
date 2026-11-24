package org.foggyden.hexline.chat

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.foggyden.hexline.R
import org.foggyden.hexline.core.NotYet
import org.foggyden.hexline.core.NotYetReset
import org.foggyden.hexline.identity.Certifying
import org.foggyden.hexline.identity.DeviceList
import org.foggyden.hexline.identity.MintedDevice
import org.foggyden.hexline.identity.ResetKept
import org.foggyden.hexline.identity.ResetShown
import org.foggyden.hexline.identity.Resetting
import org.foggyden.hexline.identity.Revoking
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.lang.reflect.Proxy

/** The Devices screen's reset, from the button to what it came to, over a list and an outcome the test gives. */
@RunWith(AndroidJUnit4::class)
class DevicesResetScreenTest {
    @get:Rule
    val rule = createComposeRule()

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun text(
        id: Int,
        vararg args: Any,
    ) = context.getString(id, *args)

    /** Each action the screen asked for, by name, with what it was asked with. */
    private val asked = mutableListOf<Pair<String, List<Any?>>>()

    private val actions =
        Proxy.newProxyInstance(SetupActions::class.java.classLoader, arrayOf(SetupActions::class.java)) { proxy, method, args ->
            when (method.name) {
                // Compose compares what it is handed.
                "equals" -> proxy === args?.get(0)
                "hashCode" -> System.identityHashCode(proxy)
                "toString" -> "actions"
                else -> {
                    asked += method.name to args.orEmpty().toList()
                    null
                }
            }
        } as SetupActions

    private val own = MintedDevice(ByteArray(32) { 1 }, "OWN-FP", "Pixel", 2_000_000_000, true, own = true, epoch = 1)
    private val tablet = MintedDevice(ByteArray(32) { 7 }, "TAB-FP", "Tablet", 2_000_000_000, false, epoch = 0)

    private fun list(
        reset: ResetKept? = null,
        own: MintedDevice = this.own,
    ) = DeviceList("fp", listOf(own, tablet), floor = 1, reset = reset, registrar = "https://hl.example")

    private fun show(
        devices: DeviceList,
        resetting: Resetting = Resetting.Idle,
    ) {
        rule.setContent {
            MaterialTheme {
                DevicesScreen("fp", "alice@hl.example", "mail.example", devices, Certifying.Idle, Revoking.Idle, actions, resetting) {}
            }
        }
    }

    private fun shows(line: String) = rule.onNodeWithText(line).performScrollTo().assertIsDisplayed()

    private fun inDialog(line: String) = rule.onNode(hasText(line) and hasAnyAncestor(isDialog()))

    @Test
    fun resetDevicesIsAskedForOnlyOnceTheConfirmIsAnswered() {
        show(list())
        rule.onNodeWithText(text(R.string.reset_devices)).performScrollTo().performClick()
        inDialog(text(R.string.reset_confirm_body, "hl.example")).assertIsDisplayed()
        assertEquals(emptyList<String>(), asked.map { it.first }.filter { it == "resetDevices" })
        inDialog(text(R.string.reset_devices)).performClick()
        rule.waitForIdle()
        assertEquals(listOf("fp"), asked.single { it.first == "resetDevices" }.second)
    }

    @Test
    fun whatAResetCameToIsToldRegistrarByRegistrarWithTheDevicesSignedOutAndAddDevice() {
        val notDone =
            listOf(
                NotYetReset("https://down.example", NotYet.UNREACHABLE, null, null),
                NotYetReset("https://closed.example", NotYet.CONNECTION_REFUSED, null, null),
                NotYetReset("https://strict.example", NotYet.REFUSED, "frozen", null),
                NotYetReset("https://busy.example", NotYet.REFUSED, "rate_limited", 60uL),
                NotYetReset("https://old.example", NotYet.UNSUPPORTED, null, null),
                NotYetReset("https://ahead.example", NotYet.DATED_AHEAD, null, null),
            )
        val later = listOf("https://down.example", "https://busy.example")
        val shown = ResetShown(listOf("https://hl.example"), notDone, listOf("https://web.example"), later)
        show(list(), Resetting.Done("fp", shown))
        shows(text(R.string.reset_done))
        shows(text(R.string.reset_at, "hl.example"))
        shows(text(R.string.reset_unreachable, "down.example"))
        shows(text(R.string.reset_connection_refused, "closed.example"))
        shows(text(R.string.reset_refused, "strict.example", "frozen"))
        shows(text(R.string.reset_refused_retrying, "busy.example", "rate_limited"))
        shows(text(R.string.reset_unsupported, "old.example"))
        shows(text(R.string.reset_wont_retry, "ahead.example"))
        shows(text(R.string.reset_not_a_registrar, "web.example"))
        shows(text(R.string.device_signed_out))
        // Add a device, beside the one the screen always has.
        rule.onAllNodesWithText(text(R.string.certify_start)).assertCountEquals(2)
    }

    @Test
    fun aResetKeptWithRegistrarsItHasNotReachedOffersAnotherAndQualifiesTheSignedOut() {
        val kept =
            ResetKept(
                epoch = 1,
                pending = listOf("https://down.example"),
                unreset = listOf("https://ahead.example"),
                givenUp = listOf("https://gone.example"),
            )
        show(list(kept))
        shows(text(R.string.reset_retrying, "down.example"))
        shows(text(R.string.reset_wont_retry, "ahead.example"))
        shows(text(R.string.reset_gave_up, "gone.example"))
        shows(text(R.string.reset_still_signed_in, "down.example, ahead.example, gone.example"))
        rule.onNodeWithText(text(R.string.reset_again)).performScrollTo().performClick()
        inDialog(text(R.string.reset_confirm_again)).assertIsDisplayed()
    }

    @Test
    fun aResetNoRegistrarTookIsNotToldAsDevicesReset() {
        val refused = listOf(NotYetReset("https://hl.example", NotYet.REFUSED, "frozen", null))
        val shown = ResetShown(emptyList(), refused, emptyList(), emptyList())
        show(list(ResetKept(epoch = 1, unreset = listOf("https://hl.example"))), Resetting.Done("fp", shown))
        shows(text(R.string.reset_reached_none))
        rule.onAllNodesWithText(text(R.string.reset_done)).assertCountEquals(0)
        shows(text(R.string.reset_again))
    }

    @Test
    fun aResetEveryRegistrarWasResetPastIsNotToldAsReachingNone() {
        val past = listOf(NotYetReset("https://hl.example", NotYet.OVERTAKEN, null, null))
        show(list(ResetKept(epoch = 1)), Resetting.Done("fp", ResetShown(emptyList(), past, emptyList(), emptyList())))
        shows(text(R.string.reset_reset_past))
        rule.onAllNodesWithText(text(R.string.reset_reached_none)).assertCountEquals(0)
    }

    @Test
    fun aRegistrarARetryReachedWhileTheScreenIsOpenIsShownReset() {
        val down = listOf(NotYetReset("https://down.example", NotYet.UNREACHABLE, null, null))
        val shown = ResetShown(listOf("https://hl.example"), down, emptyList(), listOf("https://down.example"))
        // What the reset came to as it was made, and what a retry has kept since.
        show(list(ResetKept(epoch = 1)), Resetting.Done("fp", shown))
        shows(text(R.string.reset_at, "down.example"))
        rule.onAllNodesWithText(text(R.string.reset_unreachable, "down.example")).assertCountEquals(0)
        rule.onAllNodesWithText(text(R.string.reset_still_signed_in, "down.example")).assertCountEquals(0)
    }

    @Test
    fun aResetThatMayNotHaveFinishedIsSaidAndOfferedAgain() {
        show(list(ResetKept(underWay = 1)))
        shows(text(R.string.reset_unfinished))
        shows(text(R.string.reset_again))
    }

    @Test
    fun thisPhoneSignedOutByAResetIsOfferedARenewal() {
        show(list(own = MintedDevice(own.device, own.fingerprint, own.name, own.expires, true, own = true, epoch = 0)))
        shows(text(R.string.reset_own_signed_out))
        rule.onNodeWithText(text(R.string.renew)).performScrollTo().performClick()
        rule.waitForIdle()
        assertEquals(listOf("fp"), asked.single { it.first == "renew" }.second)
    }
}
