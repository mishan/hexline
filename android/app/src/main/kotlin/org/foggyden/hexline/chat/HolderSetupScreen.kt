package org.foggyden.hexline.chat

import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import org.foggyden.hexline.R
import org.foggyden.hexline.core.RevokeReason
import org.foggyden.hexline.core.minPassphrase
import org.foggyden.hexline.identity.HolderRefusal
import org.foggyden.hexline.identity.MintedDevice
import org.foggyden.hexline.identity.SettingUp
import org.foggyden.hexline.identity.SetupProblem

/** What the screens of an identity this phone holds ask of the model; the prompt each needs is the activity's. */
interface SetupActions {
    fun start(
        registrar: String,
        handle: String,
        invite: String?,
        deviceName: String,
    )

    fun successorWritten()

    fun showSuccessorAgain()

    fun confirmSuccessor(typed: ByteArray)

    fun recoveryWritten()

    fun showRecoveryAgain()

    fun confirmRecovery(typed: ByteArray)

    fun hold()

    fun retry(
        handle: String,
        invite: String?,
    )

    fun finish(fingerprint: String)

    fun cancel()

    fun seen()

    /** Certifies this phone's device for [fingerprint] again. */
    fun renew(fingerprint: String)

    /** A new device for [fingerprint], in place of one a server revoked. */
    fun newDevice(fingerprint: String)

    fun retryNewRecoveryCode(fingerprint: String)

    fun renewSeen()

    fun backUpPassphrase(
        fingerprint: String,
        passphrase: String,
    )

    fun removePassphraseBackup(fingerprint: String)

    fun newRecoveryCode()

    fun newRecoveryCodeWritten()

    fun showNewRecoveryCodeAgain()

    fun confirmNewRecoveryCode(
        fingerprint: String,
        typed: ByteArray,
    )

    fun backupSeen()

    fun openDevices(fingerprint: String)

    fun startCertifying(
        fingerprint: String,
        mailbox: String,
    )

    fun approveDevice(
        fingerprint: String,
        manage: Boolean,
    )

    fun denyDevice(fingerprint: String)

    fun cancelCertifying()

    fun certifySeen()

    fun revokeDevice(
        fingerprint: String,
        device: MintedDevice,
        reason: RevokeReason,
    )

    fun revokingSeen()
}

/**
 * Makes an identity this phone holds (design §2.1): the registrar and the
 * handle, the two codes written down and typed back, then the key held
 * behind the screen lock and the identity registered.
 */
@Composable
fun HolderSetupScreen(
    state: SettingUp,
    actions: SetupActions,
    onClose: () -> Unit,
) {
    var registrar by rememberSaveable { mutableStateOf("") }
    var handle by rememberSaveable { mutableStateOf("") }
    var invite by rememberSaveable { mutableStateOf("") }
    var deviceName by rememberSaveable {
        mutableStateOf(
            android.os.Build.MODEL
                .orEmpty(),
        )
    }
    // Not saveable: saved state is written to disk with the task.
    var typed by remember(state::class) { mutableStateOf("") }
    val close = {
        actions.cancel()
        onClose()
    }
    // A code on screen is kept out of screenshots, recordings, casting and the recents thumbnail.
    val window = LocalActivity.current?.window
    val showsCode =
        state is SettingUp.Successor ||
            state is SettingUp.ConfirmSuccessor ||
            state is SettingUp.Recovery ||
            state is SettingUp.ConfirmRecovery
    DisposableEffect(window, showsCode) {
        if (showsCode) window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { if (showsCode) window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
    // Back lets go of the setup rather than leaving the app with a code shown.
    BackHandler(enabled = state != SettingUp.Working && state != SettingUp.Checking) { close() }
    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.holder_setup_title), style = MaterialTheme.typography.headlineMedium)
        when (state) {
            SettingUp.Idle -> {
                Text(stringResource(R.string.holder_setup_intro))
                Field(registrar, { registrar = it }, R.string.registrar, KeyboardType.Uri)
                Field(handle, { handle = it }, R.string.handle)
                Field(invite, { invite = it }, R.string.holder_invite)
                Field(deviceName, { deviceName = it }, R.string.device_name)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        { actions.start(registrar.trim(), handle.trim(), invite.trim(), deviceName.trim()) },
                        enabled = registrar.isNotBlank() && handle.isNotBlank() && deviceName.isNotBlank(),
                    ) { Text(stringResource(R.string.holder_continue)) }
                    TextButton(close) { Text(stringResource(R.string.cancel)) }
                }
            }
            SettingUp.Checking, SettingUp.Working -> Text(stringResource(R.string.holder_working))
            is SettingUp.Refused -> {
                Problem(describe(state.why))
                TextButton(close) { Text(stringResource(R.string.dismiss)) }
            }
            is SettingUp.Successor -> {
                Text(stringResource(R.string.holder_successor_title), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.holder_successor_body))
                Code(state.code)
                Button(actions::successorWritten) { Text(stringResource(R.string.holder_written)) }
                TextButton(close) { Text(stringResource(R.string.cancel)) }
            }
            is SettingUp.ConfirmSuccessor -> {
                Confirm(typed, { typed = it }, R.string.holder_confirm_successor, state.wrong)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button({ actions.confirmSuccessor(typed.toByteArray()) }, enabled = typed.isNotBlank()) {
                        Text(stringResource(R.string.holder_confirm))
                    }
                    TextButton(actions::showSuccessorAgain) { Text(stringResource(R.string.holder_show_again)) }
                }
            }
            is SettingUp.Recovery -> {
                Text(stringResource(R.string.holder_recovery_title), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.holder_recovery_body))
                if (state.replaces) Text(stringResource(R.string.holder_recovery_replaces), color = MaterialTheme.colorScheme.error)
                Code(state.code)
                Button(actions::recoveryWritten) { Text(stringResource(R.string.holder_written)) }
                TextButton(close) { Text(stringResource(R.string.cancel)) }
            }
            is SettingUp.ConfirmRecovery -> {
                Confirm(typed, { typed = it }, R.string.holder_confirm_recovery, state.wrong)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button({ actions.confirmRecovery(typed.toByteArray()) }, enabled = typed.isNotBlank()) {
                        Text(stringResource(R.string.holder_confirm))
                    }
                    TextButton(actions::showRecoveryAgain) { Text(stringResource(R.string.holder_show_again)) }
                }
            }
            SettingUp.ReadyToHold -> {
                Text(stringResource(R.string.holder_ready))
                Button(actions::hold) { Text(stringResource(R.string.holder_hold)) }
                TextButton(close) { Text(stringResource(R.string.cancel)) }
            }
            is SettingUp.Failed -> {
                Problem(describe(state.problem))
                var again by rememberSaveable(state) { mutableStateOf(state.handle) }
                if (!state.fixed && state.problem in setOf(SetupProblem.HandleTaken, SetupProblem.HandleInvalid)) {
                    Field(again, { again = it }, R.string.handle)
                }
                if (state.problem == SetupProblem.InviteNeeded || state.problem == SetupProblem.InviteWrong) {
                    Field(invite, { invite = it }, R.string.holder_invite)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (state.problem != SetupProblem.KeyLost) {
                        Button({ actions.retry(again.trim(), invite.trim()) }, enabled = again.isNotBlank()) {
                            Text(stringResource(R.string.try_again))
                        }
                    }
                    TextButton(close) { Text(stringResource(R.string.cancel)) }
                }
            }
            is SettingUp.Done -> Unit
        }
    }
}

@Composable
internal fun Field(
    value: String,
    onChange: (String) -> Unit,
    label: Int,
    type: KeyboardType = KeyboardType.Text,
) = OutlinedTextField(
    value,
    onChange,
    label = { Text(stringResource(label)) },
    singleLine = true,
    keyboardOptions = KeyboardOptions(keyboardType = type),
    modifier = Modifier.fillMaxWidth(),
)

@Composable
internal fun Code(code: String) = Text(code, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium)

@Composable
internal fun Confirm(
    typed: String,
    onChange: (String) -> Unit,
    label: Int,
    wrong: Boolean,
) {
    OutlinedTextField(
        typed,
        onChange,
        label = { Text(stringResource(label)) },
        isError = wrong,
        keyboardOptions =
            KeyboardOptions(
                capitalization = KeyboardCapitalization.Characters,
                autoCorrectEnabled = false,
                keyboardType = KeyboardType.Password,
            ),
        modifier = Modifier.fillMaxWidth(),
    )
    if (wrong) Problem(stringResource(R.string.holder_wrong_code))
}

@Composable
internal fun Problem(text: String) =
    Text(text, color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })

@Composable
internal fun describe(why: HolderRefusal): String =
    when (why) {
        HolderRefusal.TooOld -> stringResource(R.string.holder_too_old)
        HolderRefusal.NoScreenLock -> stringResource(R.string.holder_no_screen_lock)
        HolderRefusal.SoftwareOnly -> stringResource(R.string.holder_software_only)
    }

@Composable
internal fun describe(problem: SetupProblem): String =
    when (problem) {
        SetupProblem.NotARegistrar -> stringResource(R.string.restore_not_a_registrar)
        SetupProblem.NoBackups -> stringResource(R.string.holder_no_backups)
        SetupProblem.HandleTaken -> stringResource(R.string.holder_handle_taken)
        SetupProblem.HandleInvalid -> stringResource(R.string.holder_handle_invalid)
        SetupProblem.BadDeviceName -> stringResource(R.string.restore_bad_device_name)
        SetupProblem.BadPassphrase ->
            pluralStringResource(
                R.plurals.backup_bad_passphrase,
                minPassphrase().toInt(),
                minPassphrase().toInt(),
            )
        SetupProblem.NotRegistered -> stringResource(R.string.backup_not_registered)
        SetupProblem.InviteNeeded -> stringResource(R.string.holder_invite_needed)
        SetupProblem.InviteWrong -> stringResource(R.string.holder_invite_wrong)
        SetupProblem.NotBackedUp -> stringResource(R.string.holder_not_backed_up)
        SetupProblem.RateLimited -> stringResource(R.string.restore_rate_limited)
        SetupProblem.Unreachable -> stringResource(R.string.restore_unreachable)
        SetupProblem.KeyLost -> stringResource(R.string.holder_key_lost)
        SetupProblem.NotKept -> stringResource(R.string.restore_not_kept)
        SetupProblem.Other -> stringResource(R.string.holder_failed)
    }
