package org.foggyden.hexline.chat

import android.content.Context
import android.text.format.DateFormat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import kotlinx.coroutines.delay
import org.foggyden.hexline.R
import org.foggyden.hexline.core.CertInfo
import org.foggyden.hexline.core.ClassicLogin
import org.foggyden.hexline.core.HeldRenewal
import org.foggyden.hexline.core.KeptRotation
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.coreVersion
import org.foggyden.hexline.identity.BackingUp
import org.foggyden.hexline.identity.Certifying
import org.foggyden.hexline.identity.DeviceList
import org.foggyden.hexline.identity.EnrollProblem
import org.foggyden.hexline.identity.Enrolling
import org.foggyden.hexline.identity.HolderRefusal
import org.foggyden.hexline.identity.Renewing
import org.foggyden.hexline.identity.RestoreProblem
import org.foggyden.hexline.identity.Restoring
import org.foggyden.hexline.identity.Revoking
import org.foggyden.hexline.identity.SettingUp
import org.foggyden.hexline.identity.Standing
import org.foggyden.hexline.identity.StoredIdentity
import org.foggyden.hexline.identity.nextChange
import org.foggyden.hexline.identity.open
import org.foggyden.hexline.identity.renewing
import org.foggyden.hexline.identity.standing
import org.foggyden.hexline.identity.usable
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn
import org.foggyden.hexline.servers.refusalKey

/**
 * Signing in: the connect screen, and the restore screen it opens. The
 * form is held here, outside either, so what was typed is still there
 * when the person comes back from a restore.
 */
@Composable
fun ConnectFlow(
    saved: List<Server>,
    identities: List<StoredIdentity>,
    refusals: Map<String, String>,
    restore: Restoring,
    error: Why?,
    connecting: Boolean,
    onConnect: (server: Server, password: String?, remember: Boolean, link: ClassicLogin?) -> Unit,
    onForget: (Server) -> Unit,
    onRestore: (registrar: String, handle: String, kind: SecretKind, secret: String, deviceName: String, hold: Boolean) -> Unit,
    onRestoreSeen: () -> Unit,
    onDelete: (fingerprint: String) -> Unit,
    onTryAgain: (server: Server, fingerprint: String) -> Unit,
    enrolling: Enrolling,
    onStartEnroll: (renewing: String?) -> Unit,
    onRequestEnroll: (gen: Int, mailbox: String, code: String, deviceName: String) -> Unit,
    onConfirmEnroll: (gen: Int, shown: String) -> Unit,
    onDiscardEnroll: () -> Unit,
    onEnrollSeen: () -> Unit,
    heldLost: List<String> = emptyList(),
    onHeldLostSeen: (fingerprint: String) -> Unit = {},
    settingUp: SettingUp = SettingUp.Idle,
    /** Holder setup, where the phone offers it. */
    setup: SetupActions? = null,
    renewing: Renewing = Renewing.Idle,
    backingUp: BackingUp = BackingUp.Idle,
    certifying: Certifying = Certifying.Idle,
    devices: DeviceList? = null,
    /** Whether [identities] has been read yet: a selection is not judged against the list before it has. */
    identitiesRead: Boolean = false,
    revoking: Revoking = Revoking.Idle,
    /** Each rotation sent, by the identity it moves away from. */
    rotations: Map<String, KeptRotation> = emptyMap(),
) {
    var backupFor by rememberSaveable { mutableStateOf<String?>(null) }
    var devicesFor by rememberSaveable { mutableStateOf<String?>(null) }
    val form = rememberSaveable(stateSaver = FormSaver) { mutableStateOf(ConnectForm()) }
    var setupOpen by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(settingUp) {
        if (settingUp is SettingUp.Done) {
            setupOpen = false
            form.value = form.value.restored(settingUp.fingerprint)
            setup?.seen()
        }
    }
    // The registrar and handle the restore screen opens with: blank for a
    // new identity, an identity's own to renew it. Null while it is closed.
    var restoreFor by rememberSaveable { mutableStateOf<Pair<String, String>?>(null) }
    LaunchedEffect(restore) { if (restore is Restoring.Done) restoreFor = null }
    val opened = restoreFor
    // Open while the view model has a run under way: it holds the device.
    val backing = backupFor?.let { fp -> identities.find { it.fingerprint == fp } }
    val certifier = devicesFor?.let { fp -> identities.find { it.fingerprint == fp && it.held } }
    // Held here no longer, or gone, its Devices screen is not to come back by itself.
    LaunchedEffect(identities, identitiesRead, devicesFor) {
        if (identitiesRead && devicesFor != null && certifier == null) devicesFor = null
    }
    if (setup != null && (setupOpen || settingUp !is SettingUp.Idle && settingUp !is SettingUp.Done)) {
        HolderSetupScreen(settingUp, setup) { setupOpen = false }
    } else if (setup != null && backing != null) {
        BackupScreen(backing.fingerprint, named(backing), backingUp, setup) { backupFor = null }
    } else if (setup != null && certifier != null) {
        DevicesScreen(
            certifier.fingerprint,
            named(certifier),
            form.value.url.ifBlank { certifier.registrar.orEmpty() },
            devices,
            certifying,
            revoking,
            setup,
        ) { devicesFor = null }
    } else if (enrolling.open) {
        val renewing = enrolling.renewing?.let { fp -> identities.find { it.fingerprint == fp } }
        EnrollScreen(
            enrolling = enrolling,
            initialMailbox = renewing?.mailbox ?: form.value.url,
            onStart = { onStartEnroll(enrolling.renewing) },
            onRequest = onRequestEnroll,
            onConfirm = onConfirmEnroll,
            onCancel = onDiscardEnroll,
        )
    } else if (opened != null) {
        RestoreScreen(restore, opened.first, opened.second, onRestore) {
            restoreFor = null
            onRestoreSeen()
        }
    } else {
        ConnectScreen(
            form = form,
            saved = saved,
            identities = identities,
            refusals = refusals,
            restored = (restore as? Restoring.Done)?.fingerprint ?: (enrolling as? Enrolling.Done)?.fingerprint,
            error = error,
            connecting = connecting,
            onConnect = onConnect,
            onForget = onForget,
            onRestore = { renewing ->
                val held = renewing?.takeIf { it.held && setup != null }
                when {
                    held != null ->
                        when (heldRenewal(held, refusals)) {
                            HeldRenewal.RENEW -> setup?.renew(held.fingerprint)
                            HeldRenewal.NEW_DEVICE -> setup?.newDevice(held.fingerprint)
                            // Rotated away: nothing to renew, and no button offers it.
                            HeldRenewal.NOTHING -> {}
                        }
                    renewing?.mailbox != null -> onStartEnroll(renewing.fingerprint)
                    else -> {
                        onRestoreSeen()
                        restoreFor = (renewing?.registrar.orEmpty()) to (renewing?.handle.orEmpty())
                    }
                }
            },
            onEnroll = { onStartEnroll(null) },
            onRestored = {
                onRestoreSeen()
                onEnrollSeen()
            },
            onDelete = onDelete,
            onTryAgain = onTryAgain,
            heldLost = heldLost,
            onHeldLostSeen = onHeldLostSeen,
            onSetup = setup?.let { { setupOpen = true } },
            onFinishSetup = setup?.let { s -> { fingerprint: String -> s.finish(fingerprint) } },
            onBackup = setup?.let { { fingerprint: String -> backupFor = fingerprint } },
            onDevices = setup?.let { { fingerprint: String -> devicesFor = fingerprint } },
            renewing = renewing,
            onRenewSeen = { setup?.renewSeen() },
            rotations = rotations,
        )
    }
}

@Composable
private fun ConnectScreen(
    form: MutableState<ConnectForm>,
    saved: List<Server>,
    identities: List<StoredIdentity>,
    refusals: Map<String, String>,
    restored: String?,
    error: Why?,
    connecting: Boolean,
    onConnect: (server: Server, password: String?, remember: Boolean, link: ClassicLogin?) -> Unit,
    onForget: (Server) -> Unit,
    onRestore: (renewing: StoredIdentity?) -> Unit,
    onEnroll: () -> Unit,
    onRestored: () -> Unit,
    onDelete: (fingerprint: String) -> Unit,
    onTryAgain: (server: Server, fingerprint: String) -> Unit,
    heldLost: List<String>,
    onHeldLostSeen: (fingerprint: String) -> Unit,
    onSetup: (() -> Unit)?,
    onFinishSetup: ((fingerprint: String) -> Unit)?,
    onBackup: ((fingerprint: String) -> Unit)?,
    onDevices: ((fingerprint: String) -> Unit)?,
    renewing: Renewing,
    onRenewSeen: () -> Unit,
    rotations: Map<String, KeptRotation>,
) {
    var form by form
    val now = certificateClock(identities)
    var deleting by remember { mutableStateOf<StoredIdentity?>(null) }
    var detailsFor by remember { mutableStateOf<StoredIdentity?>(null) }
    val refused = { server: Server, kept: StoredIdentity -> refusals[refusalKey(server, kept.info.device)] }
    // The servers arrive once read; the last fills only a form not yet begun.
    LaunchedEffect(saved.firstOrNull()) {
        val last = saved.firstOrNull()
        if (last != null && form.url.isEmpty() && form.login.isEmpty()) form = form.filled(last)
    }
    LaunchedEffect(restored) {
        if (restored != null) {
            form = form.restored(restored)
            onRestored()
        }
    }
    val identity = form.identity(identities)
    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
        for (lost in heldLost) {
            val identity = identities.find { it.fingerprint == lost }
            val name = identity?.let(::named) ?: lost.take(16)
            val notice = if (identity?.unrecoverable == true) R.string.held_key_lost_unfinished else R.string.held_key_lost
            Column {
                Text(stringResource(notice, name), color = MaterialTheme.colorScheme.error)
                TextButton({ onHeldLostSeen(lost) }) { Text(stringResource(R.string.dismiss)) }
            }
        }
        when (renewing) {
            is Renewing.Done, is Renewing.Failed ->
                Column {
                    if (renewing is Renewing.Failed) Problem(describe(renewing.problem)) else Text(stringResource(R.string.renewed))
                    TextButton(onRenewSeen) { Text(stringResource(R.string.dismiss)) }
                }
            Renewing.Working -> Text(stringResource(R.string.holder_working))
            Renewing.Idle -> Unit
        }
        for (kept in identities) {
            val banner =
                when (val s = standing(kept, now)) {
                    is Standing.Renew -> pluralStringResource(R.plurals.renew_banner, s.days.toInt(), named(kept), s.days.toInt())
                    Standing.Expired -> stringResource(R.string.expired_banner, named(kept))
                    else -> null
                } ?: stringResource(R.string.no_holder_banner, named(kept)).takeIf { kept.noHolder } ?: continue
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(banner, Modifier.weight(1f), color = MaterialTheme.colorScheme.error)
                if (!kept.held || heldRenewal(kept, refusals) != HeldRenewal.NOTHING) {
                    TextButton({ onRestore(kept) }) { Text(stringResource(R.string.renew)) }
                }
            }
        }
        // Whichever way the person signs in, as it may be someone else's doing.
        for (kept in identities) {
            val notice = rotations[kept.fingerprint]?.let(::notice)?.takeIf { it.alarm } ?: continue
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(rotationBanner(notice, named(kept)), Modifier.weight(1f), color = MaterialTheme.colorScheme.error)
                val label = stringResource(R.string.rotation_details_label, named(kept))
                TextButton({ detailsFor = kept }, Modifier.semantics { contentDescription = label }) {
                    Text(stringResource(R.string.details))
                }
            }
        }
        if (saved.isNotEmpty()) {
            Text(stringResource(R.string.saved_servers), style = MaterialTheme.typography.titleSmall)
            for (server in saved) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton({ form = form.filled(server) }, Modifier.weight(1f)) {
                        Text(stringResource(R.string.saved_server, server.url, whom(server, identities, now, refused)))
                    }
                    TextButton({ onForget(server) }) { Text(stringResource(R.string.forget)) }
                }
            }
        }
        OutlinedTextField(
            form.url,
            { form = form.withUrl(it) },
            label = { Text(stringResource(R.string.server_address)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(!form.byIdentity, { form = form.copy(byIdentity = false) }, { Text(stringResource(R.string.sign_in_password)) })
            FilterChip(form.byIdentity, { form = form.copy(byIdentity = true) }, { Text(stringResource(R.string.sign_in_identity)) })
        }
        if (!form.byIdentity) {
            OutlinedTextField(
                form.login,
                { form = form.copy(login = it) },
                label = { Text(stringResource(R.string.login)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            PasswordField(form.password, { form = form.copy(password = it) })
            Checked(form.rememberPassword, { form = form.copy(rememberPassword = it) }, stringResource(R.string.remember_password))
        } else {
            if (identities.isEmpty()) Text(stringResource(R.string.no_identities))
            if (form.missing(identities)) Text(stringResource(R.string.identity_missing), color = MaterialTheme.colorScheme.error)
            Column(Modifier.selectableGroup()) {
                for (kept in identities) {
                    val standing = standing(kept, now)
                    val refusedHere = refused(form.identityServer(kept), kept)
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .selectable(kept == identity, role = Role.RadioButton) { form = form.chose(kept.fingerprint) }
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(kept == identity, null)
                        Column(Modifier.padding(start = 8.dp)) {
                            Text(named(kept))
                            listOfNotNull(describe(standing), refusedHere?.let { describeRefusal(it, form.url) }).forEach {
                                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                            }
                            Text(capabilities(kept), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    rotations[kept.fingerprint]?.let { RotationNote(it) }
                    if (kept.unrecoverable) {
                        Text(
                            stringResource(R.string.holder_unrecoverable),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                    if (kept.unfinished && onFinishSetup != null) {
                        Text(
                            stringResource(R.string.holder_unfinished),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error,
                        )
                        TextButton({ onFinishSetup(kept.fingerprint) }) { Text(stringResource(R.string.holder_finish)) }
                    }
                    // Wrapped, as a held identity's buttons are wider than a small phone.
                    FlowRow {
                        // Offered whatever a server said: a new device is the way back.
                        if ((standing != Standing.Good || refusedHere != null) &&
                            (!kept.held || heldRenewal(kept, refusals) != HeldRenewal.NOTHING)
                        ) {
                            TextButton({ onRestore(kept) }) { Text(stringResource(R.string.renew)) }
                        }
                        // The server may have lifted it: asked again there.
                        if (refusedHere != null) {
                            TextButton({ onTryAgain(form.identityServer(kept), kept.fingerprint) }) {
                                Text(stringResource(R.string.try_again))
                            }
                        }
                        if (kept.held && onBackup != null) {
                            TextButton({ onBackup(kept.fingerprint) }) { Text(stringResource(R.string.backup)) }
                        }
                        if (kept.held && onDevices != null) {
                            TextButton({ onDevices(kept.fingerprint) }) { Text(stringResource(R.string.devices)) }
                        }
                        TextButton({ deleting = kept }) { Text(stringResource(R.string.delete)) }
                    }
                }
            }
            TextButton({ onRestore(null) }) { Text(stringResource(R.string.restore_identity)) }
            TextButton(onEnroll) { Text(stringResource(R.string.enroll_identity)) }
            onSetup?.let { TextButton(it) { Text(stringResource(R.string.holder_setup)) } }
            // Linking writes to the account, which a device may do only with manage.
            if (identity != null && !identity.info.canManage) {
                Text(stringResource(R.string.needs_manage), style = MaterialTheme.typography.bodySmall)
            } else if (identity != null && standing(identity, now).usable && refused(form.identityServer(identity), identity) == null) {
                Checked(form.linking, { form = form.copy(linking = it) }, stringResource(R.string.have_account))
                if (form.linking) {
                    OutlinedTextField(
                        form.linkLogin,
                        { form = form.copy(linkLogin = it) },
                        label = { Text(stringResource(R.string.login)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    PasswordField(form.linkPassword, { form = form.copy(linkPassword = it) })
                }
            }
        }
        if (error != null) {
            Text(
                describe(error),
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
        val request = form.request(identities, now, refused)
        Button(
            onClick = { request?.let { onConnect(it.server, it.password, it.remember, it.link) } },
            enabled = request != null && !connecting,
        ) { Text(stringResource(if (connecting) R.string.connecting else R.string.connect)) }
        Text(
            stringResource(R.string.core_version, coreVersion()),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline,
        )
    }
    detailsFor?.let { shown ->
        val notice = rotations[shown.fingerprint]?.let(::notice) ?: return@let
        AlertDialog(
            onDismissRequest = { detailsFor = null },
            title = { Text(named(shown)) },
            text = { Text(rotationText(notice)) },
            confirmButton = { TextButton({ detailsFor = null }) { Text(stringResource(R.string.close)) } },
        )
    }
    deleting?.let { doomed ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text(stringResource(R.string.delete_identity_title, named(doomed))) },
            text = { Text(stringResource(R.string.delete_identity_body)) },
            confirmButton = {
                TextButton({
                    deleting = null
                    onDelete(doomed.fingerprint)
                }) { Text(stringResource(R.string.delete)) }
            },
            dismissButton = { TextButton({ deleting = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

/**
 * The time, in seconds, as what the screen shows of [identities] needs
 * it: read again when the app comes back, and at the next moment any of
 * them stands otherwise, so a certificate that begins or ends while the
 * screen is open is shown, and offered, as it now is.
 */
@Composable
private fun certificateClock(identities: List<StoredIdentity>): Long {
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LifecycleResumeEffect(Unit) {
        now = System.currentTimeMillis() / 1000
        onPauseOrDispose {}
    }
    LaunchedEffect(identities, now) {
        val next = identities.mapNotNull { nextChange(it, now) }.minOrNull() ?: return@LaunchedEffect
        delay((next - now) * 1000)
        // Never short of it: a clock read a moment early would wait again for nothing.
        now = maxOf(System.currentTimeMillis() / 1000, next)
    }
    return now
}

/** What the person is told of an identity that is not simply good, or null. */
@Composable
private fun describe(standing: Standing): String? =
    when (standing) {
        Standing.Good -> null
        is Standing.Renew -> pluralStringResource(R.plurals.expires_in, standing.days.toInt(), standing.days.toInt())
        Standing.Expired -> stringResource(R.string.identity_expired)
        Standing.NotYetValid -> stringResource(R.string.identity_not_yet_valid)
    }

/** A server's host as a person knows it: with its port unless that is the scheme's own. */
private fun shownHost(uri: java.net.URI): String? {
    val host = uri.host ?: return null
    val own = if (uri.scheme == "wss") 443 else 80
    return if (uri.port == -1 || uri.port == own) host else "$host:${uri.port}"
}

/** What a server refused an identity's device as, and which server. */
@Composable
private fun describeRefusal(
    code: String,
    url: String,
): String {
    val host = runCatching { shownHost(java.net.URI(url.trim())) }.getOrNull() ?: url.trim()
    return if (code == "rotated") stringResource(R.string.refused_rotated, host) else stringResource(R.string.refused_revoked, host)
}

/**
 * A rotation away from an identity, as its registrars answered: there from
 * the time it is sent, so a live region announces what it changes to.
 */
@Composable
private fun RotationNote(rotation: KeptRotation) {
    val notice = notice(rotation) ?: return
    val quiet = notice is RotationNotice.UnderWay || notice is RotationNotice.Pending
    Text(
        rotationText(notice),
        Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        style = MaterialTheme.typography.bodySmall,
        color = if (quiet) MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
    )
}

/** What a rotation's [notice] tells the person, in full. */
@Composable
private fun rotationText(notice: RotationNotice): String {
    val at = registrarHost(notice.registrar)
    val context = LocalContext.current
    return when (notice) {
        is RotationNotice.UnderWay -> stringResource(R.string.rotation_under_way, at)
        is RotationNotice.Pending -> stringResource(R.string.rotation_pending, at, publishTime(context, notice.until))
        is RotationNotice.Frozen -> stringResource(R.string.rotation_frozen, at)
        is RotationNotice.PendingElsewhere ->
            notice.until?.let { stringResource(R.string.rotation_pending_elsewhere, at, publishTime(context, it)) }
                ?: stringResource(R.string.rotation_pending_elsewhere_untimed, at)
        is RotationNotice.Mismatch -> stringResource(R.string.rotation_successor_mismatch, at)
        is RotationNotice.Superseded -> stringResource(R.string.rotation_superseded, at)
        is RotationNotice.RotatedAway -> stringResource(R.string.rotation_rotated_away, at)
        is RotationNotice.Refused ->
            when (notice.code) {
                "revoked" -> stringResource(R.string.rotation_revoked, at)
                "not_registered" -> stringResource(R.string.rotation_not_registered, at)
                else -> stringResource(R.string.rotation_refused, at, notice.code)
            }
    }
}

/** The banner of a rotation's [notice] that may be someone else's doing, for the identity [name]. */
@Composable
private fun rotationBanner(
    notice: RotationNotice,
    name: String,
): String =
    when (notice) {
        is RotationNotice.PendingElsewhere -> stringResource(R.string.rotation_pending_elsewhere_banner, name)
        is RotationNotice.Mismatch -> stringResource(R.string.rotation_mismatch_banner, name, registrarHost(notice.registrar))
        is RotationNotice.Refused -> stringResource(R.string.rotation_revoked_banner, name, registrarHost(notice.registrar))
        is RotationNotice.RotatedAway -> stringResource(R.string.rotation_rotated_away_banner, name)
        else -> stringResource(R.string.rotation_superseded_banner, name)
    }

/** A registrar as a person knows it: its host. */
private fun registrarHost(base: String): String = runCatching { java.net.URI(base).host }.getOrNull() ?: base

/** When a registrar publishes a rotation, in seconds, by the person's own clock and its 12- or 24-hour setting. */
internal fun publishTime(
    context: Context,
    until: Long,
): String {
    val date = java.util.Date(until * 1000)
    return "${DateFormat.getMediumDateFormat(context).format(date)} ${DateFormat.getTimeFormat(context).format(date)}"
}

/** What this device's certificate lets it do, in words. */
@Composable
private fun capabilities(identity: StoredIdentity): String = capabilities(identity.info)

@Composable
private fun capabilities(info: CertInfo): String {
    val can =
        listOfNotNull(
            stringResource(R.string.cap_login).takeIf { info.canLogin },
            stringResource(R.string.cap_message).takeIf { info.canMessage },
            stringResource(R.string.cap_manage).takeIf { info.canManage },
            stringResource(R.string.cap_vouch).takeIf { info.canVouch },
        )
    return if (can.isEmpty()) stringResource(R.string.device_can_nothing) else stringResource(R.string.device_can, can.joinToString(", "))
}

/** The form as the task saves it: never what was typed as a password. */
private val FormSaver =
    listSaver<ConnectForm, Any?>(
        save = { listOf(it.url, it.byIdentity, it.login, it.rememberPassword, it.chosen, it.linking, it.linkLogin) },
        restore = {
            ConnectForm(
                url = it[0] as String,
                byIdentity = it[1] as Boolean,
                login = it[2] as String,
                rememberPassword = it[3] as Boolean,
                chosen = it[4] as String?,
                linking = it[5] as Boolean,
                linkLogin = it[6] as String,
            )
        },
    )

/** An identity as a person knows it: by its handle, or the start of its fingerprint. */
private fun named(identity: StoredIdentity) = identity.handle ?: identity.fingerprint.take(16)

@Composable
private fun whom(
    server: Server,
    identities: List<StoredIdentity>,
    now: Long,
    refused: (Server, StoredIdentity) -> String?,
): String =
    when (val how = server.signIn) {
        SignIn.Password -> server.login ?: stringResource(R.string.as_guest)
        is SignIn.Identity -> {
            val kept = identities.find { it.fingerprint == how.fingerprint }
            val name = kept?.let(::named) ?: how.fingerprint.take(16)
            val why =
                when {
                    kept == null -> null
                    refused(server, kept) != null -> stringResource(R.string.standing_refused)
                    standing(kept, now) == Standing.Expired -> stringResource(R.string.standing_expired)
                    standing(kept, now) == Standing.NotYetValid -> stringResource(R.string.standing_not_yet_valid)
                    else -> null
                }
            if (why == null) name else stringResource(R.string.whom_unusable, name, why)
        }
    }

@Composable
internal fun PasswordField(
    value: String,
    onChange: (String) -> Unit,
    label: Int = R.string.password,
) {
    OutlinedTextField(
        value,
        onChange,
        label = { Text(stringResource(label)) },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        // No suggestion learned from it, nor one that could append a space.
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
internal fun Checked(
    checked: Boolean,
    onChange: (Boolean) -> Unit,
    label: String,
) {
    Row(
        Modifier.selectable(checked, role = Role.Checkbox) { onChange(!checked) },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked, null)
        Text(label)
    }
}

/**
 * Makes this phone a device of an identity a registrar keeps a backup of,
 * opened with its passphrase or recovery code.
 */
@Composable
fun RestoreScreen(
    restoring: Restoring,
    initialRegistrar: String,
    initialHandle: String,
    onRestore: (registrar: String, handle: String, kind: SecretKind, secret: String, deviceName: String, hold: Boolean) -> Unit,
    onCancel: () -> Unit,
) {
    var registrar by rememberSaveable { mutableStateOf(initialRegistrar) }
    var hold by rememberSaveable { mutableStateOf(false) }
    var handle by rememberSaveable { mutableStateOf(initialHandle) }
    var byCode by rememberSaveable { mutableStateOf(false) }
    // Not saveable: saved state is written to disk with the task.
    var secret by remember { mutableStateOf("") }
    var deviceName by rememberSaveable {
        mutableStateOf(
            android.os.Build.MODEL
                .orEmpty(),
        )
    }
    val working = restoring == Restoring.Working
    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.restore_title), style = MaterialTheme.typography.headlineMedium)
        OutlinedTextField(
            registrar,
            { registrar = it },
            label = { Text(stringResource(R.string.registrar)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            handle,
            { handle = it },
            label = { Text(stringResource(R.string.handle)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(!byCode, { byCode = false }, { Text(stringResource(R.string.passphrase)) })
            FilterChip(byCode, { byCode = true }, { Text(stringResource(R.string.recovery_code)) })
        }
        PasswordField(secret, { secret = it }, if (byCode) R.string.recovery_code else R.string.passphrase)
        OutlinedTextField(
            deviceName,
            { deviceName = it },
            label = { Text(stringResource(R.string.device_name)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Checked(hold, { hold = it }, stringResource(R.string.restore_hold))
        if (restoring is Restoring.NotHeld) {
            Text(
                stringResource(R.string.restore_not_held),
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
        if (restoring is Restoring.Failed) {
            Text(
                describe(restoring.problem),
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    val kind = if (byCode) SecretKind.RECOVERY_CODE else SecretKind.PASSPHRASE
                    onRestore(registrar.trim(), handle.trim(), kind, secret, deviceName.trim(), hold)
                },
                enabled = registrar.isNotBlank() && handle.isNotBlank() && secret.isNotEmpty() && !working,
            ) { Text(stringResource(if (working) R.string.restoring else R.string.restore)) }
            TextButton(onCancel, enabled = !working) { Text(stringResource(R.string.cancel)) }
        }
    }
}

@Composable
private fun describe(problem: RestoreProblem): String =
    when (problem) {
        RestoreProblem.NotFound -> stringResource(R.string.restore_not_found)
        RestoreProblem.NotARegistrar -> stringResource(R.string.restore_not_a_registrar)
        RestoreProblem.NoBackups -> stringResource(R.string.restore_no_backups)
        RestoreProblem.BadSecret -> stringResource(R.string.restore_bad_secret)
        RestoreProblem.BadDeviceName -> stringResource(R.string.restore_bad_device_name)
        RestoreProblem.RateLimited -> stringResource(R.string.restore_rate_limited)
        RestoreProblem.Unreachable -> stringResource(R.string.restore_unreachable)
        RestoreProblem.NotKept -> stringResource(R.string.restore_not_kept)
        RestoreProblem.TooOld -> describe(HolderRefusal.TooOld)
        RestoreProblem.NoScreenLock -> describe(HolderRefusal.NoScreenLock)
        RestoreProblem.SoftwareOnly -> describe(HolderRefusal.SoftwareOnly)
        RestoreProblem.Other -> stringResource(R.string.restore_failed)
    }

/**
 * Makes this phone a device of an identity whose key a holder keeps: by
 * the code it shows, after which the person sees whose device the phone
 * has become and keeps it only then (enrollment section 5.5).
 */
@Composable
fun EnrollScreen(
    enrolling: Enrolling,
    initialMailbox: String,
    onStart: () -> Unit,
    onRequest: (gen: Int, mailbox: String, code: String, deviceName: String) -> Unit,
    onConfirm: (gen: Int, shown: String) -> Unit,
    onCancel: () -> Unit,
) {
    var mailbox by rememberSaveable { mutableStateOf(initialMailbox) }
    var code by rememberSaveable { mutableStateOf("") }
    var deviceName by rememberSaveable { mutableStateOf("Hexline") }
    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.enroll_title), style = MaterialTheme.typography.headlineMedium)
        when (enrolling) {
            is Enrolling.Answered -> {
                Text(
                    stringResource(R.string.enroll_answered),
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                // Apart, and the fingerprint in its own face: a name cannot be made to look like it.
                Text(enrolling.name, style = MaterialTheme.typography.titleMedium)
                // Whole, in groups to read: a short prefix is cheap to grind out.
                Text(
                    stringResource(R.string.enroll_fingerprint, enrolling.fingerprint.chunked(4).joinToString(" ")),
                    fontFamily = FontFamily.Monospace,
                )
                if (enrolling.namesake) {
                    Text(stringResource(R.string.enroll_namesake, enrolling.name), color = MaterialTheme.colorScheme.error)
                }
                Text(capabilities(enrolling.info), style = MaterialTheme.typography.bodySmall)
                Text(
                    stringResource(R.string.enroll_until, expiry(enrolling.info.expires)),
                    style = MaterialTheme.typography.bodySmall,
                )
                enrolling.replaces?.let {
                    Text(stringResource(R.string.enroll_replaces))
                    Text(capabilities(it), style = MaterialTheme.typography.bodySmall)
                    Text(stringResource(R.string.enroll_until, expiry(it.expires)), style = MaterialTheme.typography.bodySmall)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button({ onConfirm(enrolling.gen, enrolling.fingerprint) }) { Text(stringResource(R.string.enroll_confirm)) }
                    TextButton(onCancel) { Text(stringResource(R.string.enroll_discard)) }
                }
            }
            is Enrolling.Saving -> {
                Text(
                    stringResource(R.string.enroll_saving, enrolling.name, enrolling.short),
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            is Enrolling.Waiting -> {
                Text(
                    stringResource(R.string.enroll_waiting, enrolling.device),
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                TextButton(onCancel) { Text(stringResource(R.string.cancel)) }
            }
            Enrolling.Idle, is Enrolling.Starting, is Enrolling.Done -> {
                Text(stringResource(R.string.enroll_starting))
                TextButton(onCancel) { Text(stringResource(R.string.cancel)) }
            }
            is Enrolling.Failed if enrolling.device.isEmpty() -> {
                Text(
                    describe(enrolling),
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onStart) { Text(stringResource(R.string.enroll_start_again)) }
                    TextButton(onCancel) { Text(stringResource(R.string.cancel)) }
                }
            }
            is Enrolling.Ready, is Enrolling.Failed -> {
                val (gen, device) =
                    (enrolling as? Enrolling.Ready)?.let { it.gen to it.device }
                        ?: (enrolling as Enrolling.Failed).let { it.gen to it.device }
                Text(stringResource(R.string.enroll_explained))
                OutlinedTextField(
                    mailbox,
                    { mailbox = it },
                    label = { Text(stringResource(R.string.mailbox)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    code,
                    { code = it },
                    label = { Text(stringResource(R.string.enroll_code)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
                    modifier = Modifier.fillMaxWidth(),
                )
                if (device.isNotEmpty()) Text(stringResource(R.string.enroll_device, device))
                OutlinedTextField(
                    deviceName,
                    { deviceName = it },
                    label = { Text(stringResource(R.string.device_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (enrolling is Enrolling.Failed) {
                    Text(
                        describe(enrolling),
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                    )
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { onRequest(gen, mailbox.trim(), code, deviceName.trim()) },
                        enabled = device.isNotEmpty() && mailbox.isNotBlank() && code.isNotBlank(),
                    ) { Text(stringResource(R.string.enroll_request)) }
                    TextButton(onCancel) { Text(stringResource(R.string.cancel)) }
                }
            }
        }
    }
}

@Composable
private fun describe(failed: Enrolling.Failed): String =
    when (failed.problem) {
        EnrollProblem.BadCode -> stringResource(R.string.enroll_bad_code)
        EnrollProblem.UnknownCode -> stringResource(R.string.enroll_unknown_code)
        EnrollProblem.BadMailbox -> stringResource(R.string.enroll_bad_mailbox)
        EnrollProblem.Cleartext -> stringResource(R.string.enroll_cleartext)
        EnrollProblem.NoMailbox -> stringResource(R.string.enroll_no_mailbox)
        EnrollProblem.BadDeviceName -> stringResource(R.string.enroll_bad_device_name)
        EnrollProblem.Denied ->
            failed.reason?.let { stringResource(R.string.enroll_denied_because, it) } ?: stringResource(R.string.enroll_denied)
        EnrollProblem.Expired -> stringResource(R.string.enroll_expired)
        EnrollProblem.AnswerLost -> stringResource(R.string.enroll_answer_lost)
        EnrollProblem.NotForThisPhone -> stringResource(R.string.enroll_not_for_this_phone)
        EnrollProblem.RateLimited -> stringResource(R.string.enroll_rate_limited)
        EnrollProblem.Unreachable -> stringResource(R.string.enroll_unreachable)
        EnrollProblem.NotKept -> stringResource(R.string.enroll_not_kept)
        EnrollProblem.AnswerNotKept -> stringResource(R.string.enroll_answer_not_kept)
        EnrollProblem.Unusable -> stringResource(R.string.enroll_unusable)
        EnrollProblem.Vouches -> stringResource(R.string.enroll_vouches)
        EnrollProblem.Clock -> stringResource(R.string.enroll_clock)
        EnrollProblem.RefusedHere -> stringResource(R.string.enroll_refused_here)
        EnrollProblem.Other -> stringResource(R.string.enroll_failed)
    }

/** A certificate's end, as a date the person reads. */
internal fun expiry(expires: ULong): String =
    java.text.DateFormat
        .getDateInstance(java.text.DateFormat.MEDIUM)
        .format(java.util.Date(expires.toLong() * 1000))
