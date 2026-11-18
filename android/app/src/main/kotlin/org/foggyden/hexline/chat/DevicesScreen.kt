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
import org.foggyden.hexline.core.Qr
import org.foggyden.hexline.identity.CertifyEnd
import org.foggyden.hexline.identity.Certifying
import org.foggyden.hexline.identity.MintedDevice
import org.foggyden.hexline.identity.RevokeReason
import org.foggyden.hexline.identity.Revoking

/**
 * The devices a held identity's key certified on this phone (design
 * §2.1): another certified by a code it types or a QR code it scans, and
 * one revoked at the registrar.
 */
@Composable
fun DevicesScreen(
    fingerprint: String,
    name: String,
    initialMailbox: String,
    devices: List<MintedDevice>,
    certifying: Certifying,
    revoking: Revoking,
    actions: SetupActions,
    onClose: () -> Unit,
) {
    // A code shown here is this identity's alone, and admits nobody once the screen is gone.
    DisposableEffect(fingerprint) {
        actions.openDevices(fingerprint)
        onDispose { actions.cancelCertifying() }
    }
    val certifying =
        when (certifying) {
            is Certifying.Showing -> certifying.takeIf { it.identity == fingerprint }
            is Certifying.Asked -> certifying.takeIf { it.identity == fingerprint }
            else -> certifying
        } ?: Certifying.Idle
    var mailbox by rememberSaveable { mutableStateOf(initialMailbox) }
    var manage by remember(certifying::class) { mutableStateOf(false) }
    var revokingDevice by remember { mutableStateOf<MintedDevice?>(null) }
    val busy = certifying == Certifying.Answering || revoking == Revoking.Working
    val close = {
        actions.cancelCertifying()
        actions.certifySeen()
        actions.revokingSeen()
        onClose()
    }
    // A code shown: the whole screen kept from screenshots, recordings, casting and the recents thumbnail.
    val window = LocalActivity.current?.window
    DisposableEffect(window) {
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
    BackHandler(enabled = !busy) { close() }
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
            Certifying.Opening, Certifying.Answering -> Text(stringResource(R.string.holder_working))
            is Certifying.Showing -> {
                Text(stringResource(R.string.certify_type_code))
                Code(certifying.code)
                Text(stringResource(R.string.certify_at_host, certifying.host))
                Text(stringResource(R.string.certify_identity, name, certifying.shown))
                certifying.qr?.let {
                    Text(stringResource(R.string.certify_or_scan))
                    QrCode(it)
                }
                val minutes = ((certifying.expiresIn + 59) / 60).toInt()
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
                        request.asksDays?.let { pluralStringResource(R.plurals.days, it.toInt(), it.toInt()) }
                            ?: stringResource(R.string.certify_asks_whatever),
                    ),
                )
                Text(
                    stringResource(
                        R.string.certify_gets,
                        capabilities(gets),
                        pluralStringResource(R.plurals.days, request.getsDays.toInt(), request.getsDays.toInt()),
                    ),
                )
                if (request.mayManage) Checked(manage, { manage = it }, stringResource(R.string.certify_manage))
                Text(stringResource(R.string.certify_never_vouch), style = MaterialTheme.typography.bodySmall)
                if (certifying.revoked) Problem(stringResource(R.string.certify_revoked))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (!certifying.revoked) {
                        Button({ actions.approveDevice(fingerprint, manage) }) { Text(stringResource(R.string.certify_approve)) }
                    }
                    TextButton({ actions.denyDevice(fingerprint) }) { Text(stringResource(R.string.certify_deny)) }
                }
            }
            else -> {
                when (certifying) {
                    is Certifying.Approved ->
                        Text(stringResource(R.string.certify_approved, certifying.device.name ?: certifying.device.fingerprint))
                    Certifying.Denied -> Text(stringResource(R.string.certify_denied))
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
            Revoking.Working -> Text(stringResource(R.string.holder_working))
            Revoking.Idle -> Unit
        }
        Text(stringResource(R.string.devices_certified), style = MaterialTheme.typography.titleMedium)
        for (device in devices) {
            Column {
                Text(device.name ?: stringResource(R.string.device_unnamed), style = MaterialTheme.typography.bodyLarge)
                Text(stringResource(R.string.enroll_fingerprint, device.fingerprint), style = MaterialTheme.typography.bodySmall)
                for (about in listOfNotNull(
                    stringResource(R.string.device_this_phone).takeIf { device.own },
                    stringResource(R.string.device_revoked).takeIf { device.revoked },
                    stringResource(R.string.device_can_manage).takeIf { device.canManage && !device.revoked },
                    stringResource(R.string.enroll_until, expiry(device.expires.toULong())).takeIf { !device.revoked },
                )) {
                    Text(about, style = MaterialTheme.typography.bodySmall)
                }
                if (!device.own && !device.revoked) {
                    TextButton({ revokingDevice = device }, enabled = !busy) { Text(stringResource(R.string.revoke)) }
                }
            }
        }
        TextButton(close, enabled = !busy) { Text(stringResource(R.string.dismiss)) }
    }
    revokingDevice?.let { device ->
        var reason by remember { mutableStateOf(RevokeReason.Lost) }
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
            CertifyEnd.Expired -> R.string.certify_expired
            CertifyEnd.NoMailbox -> R.string.certify_no_mailbox
            CertifyEnd.Unpaired -> R.string.certify_unpaired
            CertifyEnd.Stale -> R.string.certify_stale
            CertifyEnd.Unreadable -> R.string.certify_unreadable
            CertifyEnd.NoLogin -> R.string.certify_no_login
        },
    )

private fun describe(reason: RevokeReason) =
    when (reason) {
        RevokeReason.Lost -> R.string.revoke_lost
        RevokeReason.Stolen -> R.string.revoke_stolen
        RevokeReason.Retired -> R.string.revoke_retired
    }
