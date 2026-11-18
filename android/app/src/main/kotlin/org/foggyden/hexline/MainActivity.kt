package org.foggyden.hexline

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.foggyden.hexline.chat.ChatScreen
import org.foggyden.hexline.chat.ChatViewModel
import org.foggyden.hexline.chat.ConnectFlow
import org.foggyden.hexline.chat.Link
import org.foggyden.hexline.chat.SetupActions
import org.foggyden.hexline.identity.BiometricAuthorizer
import org.foggyden.hexline.secrets.Authorizer

/** A FragmentActivity, as the prompt an identity's key asks by needs one. */
class MainActivity : FragmentActivity() {
    private val chat: ChatViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val authorizer = BiometricAuthorizer(this, getString(R.string.holder_prompt_title), getString(R.string.holder_prompt_subtitle))
        setContent { MaterialTheme { Surface { Hexline(chat, authorizer) } } }
    }
}

/** The setup screen's asks, each to [chat], the key's prompt by [authorizer]. */
fun setupActions(
    chat: ChatViewModel,
    authorizer: Authorizer,
) = object : SetupActions {
    override fun start(
        registrar: String,
        handle: String,
        invite: String?,
        deviceName: String,
    ) = chat.startHolderSetup(registrar, handle, invite, deviceName)

    override fun successorWritten() = chat.successorWritten()

    override fun showSuccessorAgain() = chat.showSuccessorAgain()

    override fun confirmSuccessor(typed: ByteArray) = chat.confirmSuccessor(typed)

    override fun recoveryWritten() = chat.recoveryWritten()

    override fun showRecoveryAgain() = chat.showRecoveryAgain()

    override fun confirmRecovery(typed: ByteArray) = chat.confirmRecovery(typed)

    override fun hold() = chat.holdSetup(authorizer)

    override fun retry(
        handle: String,
        invite: String?,
    ) = chat.retrySetup(handle, invite)

    override fun finish(fingerprint: String) = chat.finishSetup(fingerprint, authorizer)

    override fun cancel() = chat.cancelHolderSetup()

    override fun seen() = chat.holderSetupSeen()

    override fun renew(fingerprint: String) = chat.renewHeld(fingerprint, authorizer)

    override fun renewSeen() = chat.renewingSeen()

    override fun newDevice(fingerprint: String) = chat.newDeviceHeld(fingerprint, authorizer)

    override fun retryNewRecoveryCode(fingerprint: String) = chat.retryNewRecoveryCode(fingerprint, authorizer)

    override fun backUpPassphrase(
        fingerprint: String,
        passphrase: String,
    ) = chat.backUpPassphrase(fingerprint, passphrase, authorizer)

    override fun removePassphraseBackup(fingerprint: String) = chat.removePassphraseBackup(fingerprint, authorizer)

    override fun newRecoveryCode() = chat.newRecoveryCode()

    override fun newRecoveryCodeWritten() = chat.newRecoveryCodeWritten()

    override fun showNewRecoveryCodeAgain() = chat.showNewRecoveryCodeAgain()

    override fun confirmNewRecoveryCode(
        fingerprint: String,
        typed: ByteArray,
    ) = chat.confirmNewRecoveryCode(fingerprint, typed, authorizer)

    override fun backupSeen() = chat.backupSeen()
}

@Composable
fun Hexline(
    chat: ChatViewModel,
    authorizer: Authorizer,
) {
    val state by chat.chat.collectAsStateWithLifecycle()
    val saved by chat.saved.collectAsStateWithLifecycle()
    val identities by chat.identityList.collectAsStateWithLifecycle()
    val refusals by chat.refusals.collectAsStateWithLifecycle()
    val restore by chat.restore.collectAsStateWithLifecycle()
    val enrolling by chat.enrollment.collectAsStateWithLifecycle()
    val heldLost by chat.heldLostNotices.collectAsStateWithLifecycle()
    val settingUp by chat.holderSetup.collectAsStateWithLifecycle()
    val renewing by chat.renewing.collectAsStateWithLifecycle()
    val backingUp by chat.backingUp.collectAsStateWithLifecycle()
    when (val link = state.link) {
        Link.Live, is Link.Reconnecting -> ChatScreen(state, chat::send, chat::loadEarlier, chat::disconnect)
        else ->
            ConnectFlow(
                saved = saved,
                identities = identities,
                refusals = refusals,
                restore = restore,
                error = (link as? Link.Ended)?.why,
                connecting = link == Link.Connecting,
                onConnect = chat::connect,
                onForget = chat::forget,
                onRestore = { registrar, handle, kind, secret, deviceName, hold ->
                    chat.restore(registrar, handle, kind, secret, deviceName, authorizer.takeIf { hold })
                },
                onRestoreSeen = chat::restoreSeen,
                onDelete = chat::deleteIdentity,
                onTryAgain = chat::tryAgain,
                enrolling = enrolling,
                onStartEnroll = chat::startEnroll,
                onRequestEnroll = chat::requestEnroll,
                onConfirmEnroll = chat::confirmEnroll,
                onDiscardEnroll = chat::discardEnroll,
                onEnrollSeen = chat::enrollSeen,
                heldLost = heldLost,
                onHeldLostSeen = chat::dismissHeldLost,
                settingUp = settingUp,
                renewing = renewing,
                backingUp = backingUp,
                setup = setupActions(chat, authorizer),
            )
    }
}
