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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
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
import org.foggyden.hexline.identity.StoredIdentity
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn

@Composable
fun ConnectScreen(
    saved: List<Server>,
    identities: List<StoredIdentity>,
    restored: String?,
    error: Why?,
    connecting: Boolean,
    onConnect: (server: Server, password: String?, remember: Boolean, link: ClassicLogin?) -> Unit,
    onForget: (Server) -> Unit,
    onRestore: () -> Unit,
    onRestored: () -> Unit,
) {
    var form by rememberSaveable(stateSaver = FormSaver) { mutableStateOf(ConnectForm()) }
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
        if (saved.isNotEmpty()) {
            Text(stringResource(R.string.saved_servers), style = MaterialTheme.typography.titleSmall)
            for (server in saved) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton({ form = form.filled(server) }, Modifier.weight(1f)) {
                        Text(stringResource(R.string.saved_server, server.url, whom(server, identities)))
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
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .selectable(kept == identity, role = Role.RadioButton) { form = form.copy(chosen = kept.fingerprint) }
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(kept == identity, null)
                        Text(named(kept), Modifier.padding(start = 8.dp))
                    }
                }
            }
            TextButton(onRestore) { Text(stringResource(R.string.restore_identity)) }
            if (identity != null) {
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
        val request = form.request(identities)
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
): String =
    when (val how = server.signIn) {
        SignIn.Password -> server.login ?: stringResource(R.string.as_guest)
        is SignIn.Identity ->
            identities.find { it.fingerprint == how.fingerprint }?.let(::named) ?: how.fingerprint.take(16)
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
    onRestore: (registrar: String, handle: String, kind: SecretKind, secret: String, deviceName: String) -> Unit,
    onCancel: () -> Unit,
) {
    var registrar by rememberSaveable { mutableStateOf("") }
    var handle by rememberSaveable { mutableStateOf("") }
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
