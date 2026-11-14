package org.foggyden.hexline.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import org.foggyden.hexline.R
import org.foggyden.hexline.core.ClassicLogin
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.coreVersion
import org.foggyden.hexline.identity.RestoreProblem
import org.foggyden.hexline.identity.Restoring
import org.foggyden.hexline.identity.Standing
import org.foggyden.hexline.identity.StoredIdentity
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
    onRestore: (registrar: String, handle: String, kind: SecretKind, secret: String, deviceName: String) -> Unit,
    onRestoreSeen: () -> Unit,
    onDelete: (fingerprint: String) -> Unit,
    onTryAgain: (server: Server, fingerprint: String) -> Unit,
) {
    val form = rememberSaveable(stateSaver = FormSaver) { mutableStateOf(ConnectForm()) }
    // The registrar and handle the restore screen opens with: blank for a
    // new identity, an identity's own to renew it. Null while it is closed.
    var restoreFor by rememberSaveable { mutableStateOf<Pair<String, String>?>(null) }
    LaunchedEffect(restore) { if (restore is Restoring.Done) restoreFor = null }
    val opened = restoreFor
    if (opened != null) {
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
            restored = (restore as? Restoring.Done)?.fingerprint,
            error = error,
            connecting = connecting,
            onConnect = onConnect,
            onForget = onForget,
            onRestore = { renewing ->
                onRestoreSeen()
                restoreFor = (renewing?.registrar.orEmpty()) to (renewing?.handle.orEmpty())
            },
            onRestored = onRestoreSeen,
            onDelete = onDelete,
            onTryAgain = onTryAgain,
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
    onRestored: () -> Unit,
    onDelete: (fingerprint: String) -> Unit,
    onTryAgain: (server: Server, fingerprint: String) -> Unit,
) {
    var form by form
    val now = System.currentTimeMillis() / 1000
    var deleting by remember { mutableStateOf<StoredIdentity?>(null) }
    val refused = { server: Server, kept: StoredIdentity -> refusals[refusalKey(server, kept.info.device)] }
    // The servers arrive once read; the last fills only a form not yet begun.
    LaunchedEffect(saved.firstOrNull()) {
        val last = saved.firstOrNull()
        if (last != null && form.url.isEmpty() && form.login.isEmpty()) form = form.filled(last)
    }
    LaunchedEffect(restored) {
        if (restored != null) {
            form = form.copy(byIdentity = true, chosen = restored)
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
        for (kept in identities) {
            val banner =
                when (val s = standing(kept, now)) {
                    is Standing.Renew -> pluralStringResource(R.plurals.renew_banner, s.days.toInt(), named(kept), s.days.toInt())
                    Standing.Expired -> stringResource(R.string.expired_banner, named(kept))
                    else -> null
                } ?: continue
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(banner, Modifier.weight(1f), color = MaterialTheme.colorScheme.error)
                TextButton({ onRestore(kept) }) { Text(stringResource(R.string.renew)) }
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
                            .selectable(kept == identity, role = Role.RadioButton) { form = form.copy(chosen = kept.fingerprint) }
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
                    Row {
                        // Offered whatever a server said: a new device is the way back.
                        if (standing != Standing.Good || refusedHere != null) {
                            TextButton({ onRestore(kept) }) { Text(stringResource(R.string.renew)) }
                        }
                        // The server may have lifted it: asked again there.
                        if (refusedHere != null) {
                            TextButton({ onTryAgain(form.identityServer(kept), kept.fingerprint) }) {
                                Text(stringResource(R.string.try_again))
                            }
                        }
                        TextButton({ deleting = kept }) { Text(stringResource(R.string.delete)) }
                    }
                }
            }
            TextButton({ onRestore(null) }) { Text(stringResource(R.string.restore_identity)) }
            if (identity != null && standing(identity, now).usable && refused(form.identityServer(identity), identity) == null) {
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

/** What this device's certificate lets it do, in words. */
@Composable
private fun capabilities(identity: StoredIdentity): String {
    val info = identity.info
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
private fun PasswordField(
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
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun Checked(
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
    onRestore: (registrar: String, handle: String, kind: SecretKind, secret: String, deviceName: String) -> Unit,
    onCancel: () -> Unit,
) {
    var registrar by rememberSaveable { mutableStateOf(initialRegistrar) }
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
                    onRestore(registrar.trim(), handle.trim(), kind, secret, deviceName.trim())
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
        RestoreProblem.Other -> stringResource(R.string.restore_failed)
    }
