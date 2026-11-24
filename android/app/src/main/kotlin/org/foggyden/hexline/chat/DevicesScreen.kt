package org.foggyden.hexline.chat

import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import org.foggyden.hexline.R
import org.foggyden.hexline.core.Caps
import org.foggyden.hexline.core.CertifyEnd
import org.foggyden.hexline.core.NotYet
import org.foggyden.hexline.core.NotYetReset
import org.foggyden.hexline.core.Qr
import org.foggyden.hexline.core.RevokeReason
import org.foggyden.hexline.identity.Certifying
import org.foggyden.hexline.identity.DeviceList
import org.foggyden.hexline.identity.MintedDevice
import org.foggyden.hexline.identity.ResetKept
import org.foggyden.hexline.identity.ResetShown
import org.foggyden.hexline.identity.Resetting
import org.foggyden.hexline.identity.Revoked
import org.foggyden.hexline.identity.Revoking

/**
 * The devices a held identity's key certified on this phone (design
 * §2.1): another certified by a code it types or a QR code it scans, one
 * revoked at the registrar, and all of them signed out by a reset.
 */
@Composable
fun DevicesScreen(
    fingerprint: String,
    name: String,
    initialMailbox: String,
    devices: DeviceList?,
    certifying: Certifying,
    revoking: Revoking,
    actions: SetupActions,
    resetting: Resetting = Resetting.Idle,
    onClose: () -> Unit,
) {
    // A code shown here is this identity's alone, and admits nobody once the screen is gone.
    DisposableEffect(fingerprint) {
        actions.openDevices(fingerprint)
        onDispose { actions.cancelCertifying() }
    }
    // Another identity's, under way or done, is not this screen's to show.
    // While any identity's answer or revocation is under way, no other is started.
    val elsewhere = certifying is Certifying.Answering || revoking is Revoking.Working || resetting is Resetting.Working
    val certifying = certifying.takeIf { it.identity == fingerprint } ?: Certifying.Idle
    val revoking = revoking.takeIf { it.identity == fingerprint } ?: Revoking.Idle
    val resetting = resetting.takeIf { it.identity == fingerprint } ?: Resetting.Idle
    var confirmingReset by remember { mutableStateOf(false) }
    val devices = devices?.takeIf { it.identity == fingerprint }
    var mailbox by rememberSaveable { mutableStateOf(initialMailbox) }
    var manage by remember(certifying::class) { mutableStateOf(false) }
    var revokingDevice by remember { mutableStateOf<MintedDevice?>(null) }
    val busy = certifying is Certifying.Answering || revoking is Revoking.Working || resetting is Resetting.Working
    val close = {
        actions.cancelCertifying()
        actions.certifySeen()
        actions.revokingSeen()
        actions.resettingSeen()
        onClose()
    }
    // A code shown: the whole screen kept from screenshots, recordings, casting and the recents thumbnail.
    val window = LocalActivity.current?.window
    DisposableEffect(window) {
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
    // Held while an answer or a revocation is under way: Back would end the model with it.
    BackHandler { if (!busy) close() }
    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.devices_title, name), style = MaterialTheme.typography.headlineMedium)
        when (certifying) {
            is Certifying.Opening, is Certifying.Answering -> Text(stringResource(R.string.holder_working))
            is Certifying.Showing -> {
                Text(stringResource(R.string.certify_type_code))
                Code(certifying.code)
                Text(stringResource(R.string.certify_at_host, certifying.host))
                Text(stringResource(R.string.certify_identity, name, certifying.shown))
                certifying.qr?.let {
                    Text(stringResource(R.string.certify_or_scan))
                    QrCode(it)
                }
                val minutes = ((certifying.lasts + 59) / 60).toInt()
                Text(pluralStringResource(R.plurals.certify_expires, minutes, minutes), style = MaterialTheme.typography.bodySmall)
                TextButton(actions::cancelCertifying) { Text(stringResource(R.string.cancel)) }
            }
            is Certifying.Asked -> {
                val request = certifying.request
                Text(stringResource(R.string.certify_asked), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.certify_device_name, request.name ?: stringResource(R.string.device_unnamed)))
                if (request.scanned) {
                    Text(stringResource(R.string.certify_scanned))
                } else {
                    Text(stringResource(R.string.certify_compare))
                    Code(request.fingerprint)
                }
                if (request.renewal) Text(stringResource(R.string.certify_renewal))
                val gets = request.gets.copy(manage = manage && request.mayManage)
                Text(
                    stringResource(
                        R.string.certify_asks,
                        request.asks?.let { capabilities(it) } ?: stringResource(R.string.certify_asks_whatever),
                        request.asksDays?.let { days(it) } ?: stringResource(R.string.certify_asks_whatever),
                    ),
                )
                Text(stringResource(R.string.certify_gets, capabilities(gets), lifetime(request.getsSecs)))
                if (request.mayManage) Checked(manage, { manage = it }, stringResource(R.string.certify_manage))
                Text(stringResource(R.string.certify_never_vouch), style = MaterialTheme.typography.bodySmall)
                when (certifying.revoked) {
                    Revoked.Yes -> Problem(stringResource(R.string.certify_revoked))
                    // What would let it be told: the list read again, or the one set aside discarded.
                    Revoked.Unknown ->
                        Problem(
                            stringResource(
                                if (devices?.setAside == true) R.string.certify_revoked_unknown else R.string.certify_revoked_unopened,
                            ),
                        )
                    Revoked.No -> Unit
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (certifying.revoked != Revoked.Yes) {
                        Button(
                            { actions.approveDevice(fingerprint, manage) },
                            enabled = certifying.revoked == Revoked.No && !elsewhere,
                        ) { Text(stringResource(R.string.certify_approve)) }
                    }
                    TextButton({ actions.denyDevice(fingerprint) }) { Text(stringResource(R.string.certify_deny)) }
                }
            }
            else -> {
                when (certifying) {
                    is Certifying.Approved ->
                        Text(stringResource(R.string.certify_approved, certifying.device.name ?: certifying.device.fingerprint))
                    is Certifying.Denied -> Text(stringResource(R.string.certify_denied))
                    is Certifying.Ended -> Problem(describe(certifying.why))
                    is Certifying.Failed -> Problem(describe(certifying.problem))
                    else -> Unit
                }
                Text(stringResource(R.string.certify_intro))
                OutlinedTextField(
                    mailbox,
                    { mailbox = it },
                    label = { Text(stringResource(R.string.certify_mailbox)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Button({ actions.startCertifying(fingerprint, mailbox.trim()) }, enabled = mailbox.isNotBlank()) {
                    Text(stringResource(R.string.certify_start))
                }
            }
        }
        when (revoking) {
            is Revoking.Done -> Text(stringResource(R.string.revoke_done, revoking.device.name ?: revoking.device.fingerprint))
            is Revoking.Failed -> Problem(describe(revoking.problem))
            is Revoking.Working -> Text(stringResource(R.string.holder_working))
            Revoking.Idle -> Unit
        }
        Text(stringResource(R.string.devices_certified), style = MaterialTheme.typography.titleMedium)
        if (devices == null) Text(stringResource(R.string.devices_loading))
        if (devices?.unreadable == true) {
            Problem(stringResource(R.string.devices_unopened))
            TextButton({ actions.openDevices(fingerprint) }) { Text(stringResource(R.string.try_again)) }
        }
        if (devices?.setAside == true) {
            Problem(stringResource(R.string.devices_unreadable))
            if (devices.setAsideLoses) Problem(stringResource(R.string.devices_discard_loses))
            TextButton({ actions.discardUnreadable(fingerprint) }) { Text(stringResource(R.string.devices_discard_unreadable)) }
        }
        if (devices?.unchecked == true) {
            Problem(stringResource(R.string.devices_unchecked))
            TextButton({ actions.openDevices(fingerprint) }) { Text(stringResource(R.string.try_again)) }
        }
        for (device in devices?.devices.orEmpty()) {
            val revoked = devices?.revoked(device) == true
            val signedOut = devices?.signedOut(device) == true
            // Revoked here, and no read has shown the registrar holds it.
            val unconfirmed = device.revoked && devices?.confirmed?.contains(device.fingerprint) != true
            Column {
                Text(device.name ?: stringResource(R.string.device_unnamed), style = MaterialTheme.typography.bodyLarge)
                Text(stringResource(R.string.enroll_fingerprint, device.fingerprint), style = MaterialTheme.typography.bodySmall)
                for (about in listOfNotNull(
                    stringResource(R.string.device_this_phone).takeIf { device.own },
                    stringResource(R.string.device_revoked).takeIf { revoked },
                    stringResource(R.string.device_unconfirmed).takeIf { unconfirmed },
                    stringResource(R.string.device_signed_out).takeIf { signedOut && !revoked },
                    stringResource(R.string.device_can_manage).takeIf { device.canManage && !revoked },
                    stringResource(R.string.enroll_until, expiry(device.expires.toULong())).takeIf { !revoked },
                )) {
                    Text(about, style = MaterialTheme.typography.bodySmall)
                }
                if (!device.own && (!revoked || unconfirmed)) {
                    TextButton({ revokingDevice = device }, enabled = !busy && !elsewhere) {
                        Text(stringResource(if (unconfirmed) R.string.revoke_again else R.string.revoke))
                    }
                }
            }
        }
        if (devices != null && devices.devices.firstOrNull()?.let { it.own && devices.signedOut(it) } == true) {
            Problem(stringResource(R.string.reset_own_signed_out))
            TextButton({ actions.renew(fingerprint) }, enabled = !busy) { Text(stringResource(R.string.renew)) }
        }
        when (resetting) {
            is Resetting.Working -> Text(stringResource(R.string.holder_working))
            is Resetting.Failed -> Problem(describe(resetting.problem))
            is Resetting.Done -> {
                // Signed out only where a registrar took it: none did, and it is not said to have.
                Text(stringResource(if (resetting.reset.done.isEmpty()) R.string.reset_reached_none else R.string.reset_done))
                ResetLines(resetting.reset)
                Button({ actions.startCertifying(fingerprint, mailbox.trim()) }, enabled = mailbox.isNotBlank() && !busy) {
                    Text(stringResource(R.string.certify_start))
                }
            }
            Resetting.Idle -> devices?.reset?.let { KeptLines(it) }
        }
        val reset = devices?.reset
        if (reset != null && (reset.uncertain || reset.unreset.isNotEmpty() || reset.givenUp.isNotEmpty())) {
            TextButton({ confirmingReset = true }, enabled = !busy && !elsewhere) { Text(stringResource(R.string.reset_again)) }
        }
        Text(stringResource(R.string.reset_devices_about), style = MaterialTheme.typography.bodySmall)
        Button({ confirmingReset = true }, enabled = !busy && !elsewhere && devices != null) {
            Text(stringResource(R.string.reset_devices))
        }
        TextButton(close, enabled = !busy) { Text(stringResource(R.string.dismiss)) }
    }
    if (confirmingReset) {
        val registrar = devices?.registrar?.let(::hostOf) ?: name
        AlertDialog(
            onDismissRequest = { confirmingReset = false },
            title = { Text(stringResource(R.string.reset_confirm_title, name)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.reset_confirm_body, registrar))
                    if (devices?.reset != null) Text(stringResource(R.string.reset_confirm_again))
                }
            },
            confirmButton = {
                TextButton({
                    confirmingReset = false
                    actions.resetDevices(fingerprint)
                }) { Text(stringResource(R.string.reset_devices)) }
            },
            dismissButton = { TextButton({ confirmingReset = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
    revokingDevice?.let { device ->
        var reason by remember { mutableStateOf(RevokeReason.LOST) }
        AlertDialog(
            onDismissRequest = { revokingDevice = null },
            title = { Text(stringResource(R.string.revoke_title, device.name ?: device.fingerprint)) },
            text = {
                Column {
                    Text(stringResource(R.string.revoke_body))
                    for (r in RevokeReason.entries) {
                        Row(
                            Modifier.selectable(reason == r, role = Role.RadioButton) { reason = r },
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(reason == r, null)
                            Text(stringResource(describe(r)))
                        }
                    }
                }
            },
            confirmButton = {
                TextButton({
                    revokingDevice = null
                    actions.revokeDevice(fingerprint, device, reason)
                }) { Text(stringResource(R.string.revoke)) }
            },
            dismissButton = { TextButton({ revokingDevice = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

/** What a reset just made came to, registrar by registrar. */
@Composable
private fun ResetLines(reset: ResetShown) {
    for (r in reset.done) Text(stringResource(R.string.reset_at, hostOf(r)))
    for (n in reset.notDone) Text(notYet(n, n.registrar in reset.later))
    for (r in reset.notRegistrars) Text(stringResource(R.string.reset_not_a_registrar, hostOf(r)))
    StillSignedIn(reset.notDone.filter { it.why != NotYet.OVERTAKEN }.map { it.registrar })
}

/** What is kept of the last reset, as a start finds it: what is still retried, and what never will be. */
@Composable
private fun KeptLines(reset: ResetKept) {
    if (reset.uncertain) Problem(stringResource(R.string.reset_unfinished))
    for (r in reset.pending) Text(stringResource(R.string.reset_retrying, hostOf(r)))
    for (r in reset.unreset) Text(stringResource(R.string.reset_wont_retry, hostOf(r)))
    for (r in reset.givenUp) Text(stringResource(R.string.reset_gave_up, hostOf(r)))
    StillSignedIn(reset.pending + reset.unreset + reset.givenUp)
}

/** Where devices shown as signed out still are not, if anywhere. */
@Composable
private fun StillSignedIn(registrars: List<String>) {
    if (registrars.isEmpty()) return
    Text(stringResource(R.string.reset_still_signed_in, registrars.joinToString(", ", transform = ::hostOf)))
}

@Composable
private fun notYet(
    n: NotYetReset,
    later: Boolean,
): String {
    val at = hostOf(n.registrar)
    return when {
        n.why == NotYet.OVERTAKEN -> stringResource(R.string.reset_overtaken, at)
        n.why == NotYet.GAVE_UP -> stringResource(R.string.reset_gave_up, at)
        n.why == NotYet.UNSUPPORTED -> stringResource(R.string.reset_unsupported, at)
        n.why == NotYet.CONNECTION_REFUSED -> stringResource(R.string.reset_connection_refused, at)
        n.why == NotYet.REFUSED && n.code != null && later -> stringResource(R.string.reset_refused_retrying, at, n.code!!)
        n.why == NotYet.REFUSED && n.code != null -> stringResource(R.string.reset_refused, at, n.code!!)
        n.why == NotYet.UNREACHABLE && later -> stringResource(R.string.reset_unreachable, at)
        later -> stringResource(R.string.reset_not_yet, at)
        else -> stringResource(R.string.reset_wont_retry, at)
    }
}

/** A registrar as a person reads it: its host, where it is named by a URL. */
private fun hostOf(registrar: String) = runCatching { java.net.URI(registrar).host }.getOrNull() ?: registrar

/** [secs] of a certificate's life, in days, or in minutes where it is under one. */
@Composable
private fun lifetime(secs: ULong): String =
    if (secs >= DAY) {
        days(secs / DAY)
    } else {
        val minutes = (secs / 60u).toInt()
        pluralStringResource(R.plurals.minutes, minutes, minutes)
    }

private const val DAY = 86_400uL

/** [count] days, however many: a request may ask for more than an Int holds. */
@Composable
private fun days(count: ULong): String =
    pluralStringResource(R.plurals.days, count.coerceAtMost(Int.MAX_VALUE.toULong()).toInt(), count.toString())

/** [caps] as a list a person reads: never empty, as nothing that signs in nowhere is asked about. */
@Composable
private fun capabilities(caps: Caps): String =
    listOfNotNull(
        stringResource(R.string.cap_login).takeIf { caps.login },
        stringResource(R.string.cap_message).takeIf { caps.message },
        stringResource(R.string.cap_manage).takeIf { caps.manage },
        stringResource(R.string.cap_vouch).takeIf { caps.vouch },
    ).joinToString(", ")

/** [qr] drawn dark on light whatever the theme, with the quiet zone a camera needs around it. */
@Composable
private fun QrCode(qr: Qr) {
    val description = stringResource(R.string.certify_qr)
    val side = qr.size.toInt()
    Canvas(
        Modifier
            .size(240.dp)
            .background(Color.White)
            .semantics { contentDescription = description },
    ) {
        val cell = size.width / (side + 2 * QUIET)
        for (y in 0 until side) {
            for (x in 0 until side) {
                if (qr.modules[y * side + x]) {
                    drawRect(Color.Black, Offset((x + QUIET) * cell, (y + QUIET) * cell), Size(cell, cell))
                }
            }
        }
    }
}

private const val QUIET = 4

@Composable
private fun describe(why: CertifyEnd): String =
    stringResource(
        when (why) {
            CertifyEnd.EXPIRED -> R.string.certify_expired
            CertifyEnd.NO_MAILBOX -> R.string.certify_no_mailbox
            CertifyEnd.UNPAIRED -> R.string.certify_unpaired
            CertifyEnd.STALE -> R.string.certify_stale
            CertifyEnd.UNREADABLE -> R.string.certify_unreadable
            CertifyEnd.NO_LOGIN -> R.string.certify_no_login
            CertifyEnd.SIGNED_OUT -> R.string.certify_signed_out
            CertifyEnd.UNCHECKED -> R.string.certify_unchecked
        },
    )

private fun describe(reason: RevokeReason) =
    when (reason) {
        RevokeReason.LOST -> R.string.revoke_lost
        RevokeReason.STOLEN -> R.string.revoke_stolen
        RevokeReason.RETIRED -> R.string.revoke_retired
    }
