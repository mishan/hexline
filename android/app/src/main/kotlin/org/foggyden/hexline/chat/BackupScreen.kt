package org.foggyden.hexline.chat

import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.foggyden.hexline.R
import org.foggyden.hexline.core.minPassphrase
import org.foggyden.hexline.identity.Backed
import org.foggyden.hexline.identity.BackingUp

/**
 * A held identity's backups at its registrar (design §2.2): a passphrase
 * to restore it by, saved, changed or removed, and a new recovery code in
 * place of the one before.
 */
@Composable
fun BackupScreen(
    fingerprint: String,
    name: String,
    state: BackingUp,
    actions: SetupActions,
    onClose: () -> Unit,
) {
    // Not saveable: saved state is written to disk with the task.
    var passphrase by remember { mutableStateOf("") }
    var again by remember { mutableStateOf("") }
    var typed by remember(state::class) { mutableStateOf("") }
    val close = {
        actions.backupSeen()
        onClose()
    }
    // A passphrase typed or a code shown: the whole screen kept from screenshots,
    // recordings, casting and the recents thumbnail.
    val window = LocalActivity.current?.window
    DisposableEffect(window) {
        window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
    var removing by remember { mutableStateOf(false) }
    BackHandler(enabled = state != BackingUp.Working) { close() }
    Column(
        Modifier
            .fillMaxSize()
            .safeDrawingPadding()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(stringResource(R.string.backup_title, name), style = MaterialTheme.typography.headlineMedium)
        when (state) {
            is BackingUp.Recovery -> {
                Text(stringResource(R.string.holder_recovery_title), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.backup_recovery_replaces))
                Code(state.code)
                Button(actions::newRecoveryCodeWritten) { Text(stringResource(R.string.holder_written)) }
                TextButton(close) { Text(stringResource(R.string.cancel)) }
            }
            is BackingUp.ConfirmRecovery -> {
                Confirm(typed, { typed = it }, R.string.holder_confirm_recovery, state.wrong)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button({ actions.confirmNewRecoveryCode(fingerprint, typed.toByteArray()) }, enabled = typed.isNotBlank()) {
                        Text(stringResource(R.string.holder_confirm))
                    }
                    TextButton(actions::showNewRecoveryCodeAgain) { Text(stringResource(R.string.holder_show_again)) }
                }
            }
            BackingUp.Working -> Text(stringResource(R.string.holder_working))
            is BackingUp.RecoveryNotSaved -> {
                Problem(describe(state.problem))
                Text(stringResource(R.string.backup_recovery_maybe))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button({ actions.retryNewRecoveryCode(fingerprint) }) { Text(stringResource(R.string.try_again)) }
                    TextButton(close) { Text(stringResource(R.string.dismiss)) }
                }
            }
            else -> {
                when (state) {
                    is BackingUp.Done -> Text(stringResource(describe(state.backed)))
                    is BackingUp.Failed -> Problem(describe(state.problem))
                    else -> Unit
                }
                Text(pluralStringResource(R.plurals.backup_passphrase_intro, minPassphrase().toInt(), minPassphrase().toInt()))
                PasswordField(passphrase, { passphrase = it }, R.string.passphrase)
                PasswordField(again, { again = it }, R.string.backup_passphrase_again)
                if (again.isNotEmpty() && again != passphrase) Problem(stringResource(R.string.backup_passphrase_differs))
                Button(
                    {
                        actions.backUpPassphrase(fingerprint, passphrase)
                        passphrase = ""
                        again = ""
                    },
                    enabled = passphrase.isNotBlank() && again == passphrase,
                ) { Text(stringResource(R.string.backup_save_passphrase)) }
                TextButton({ removing = true }) { Text(stringResource(R.string.backup_remove_passphrase)) }
                TextButton(actions::newRecoveryCode) { Text(stringResource(R.string.backup_new_recovery_code)) }
                TextButton(close) { Text(stringResource(R.string.dismiss)) }
            }
        }
    }
    if (removing) {
        AlertDialog(
            onDismissRequest = { removing = false },
            title = { Text(stringResource(R.string.backup_remove_title)) },
            text = { Text(stringResource(R.string.backup_remove_body)) },
            confirmButton = {
                TextButton({
                    removing = false
                    actions.removePassphraseBackup(fingerprint)
                }) { Text(stringResource(R.string.backup_remove_passphrase)) }
            },
            dismissButton = { TextButton({ removing = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

private fun describe(backed: Backed) =
    when (backed) {
        Backed.PassphraseSaved -> R.string.backup_passphrase_saved
        Backed.PassphraseRemoved -> R.string.backup_passphrase_removed
        Backed.RecoveryCodeSaved -> R.string.backup_recovery_saved
    }
