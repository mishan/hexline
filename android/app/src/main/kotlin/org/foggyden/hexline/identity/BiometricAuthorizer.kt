package org.foggyden.hexline.identity

import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.foggyden.hexline.secrets.Authorizer
import org.foggyden.hexline.secrets.Seal
import javax.crypto.Cipher
import kotlin.coroutines.resume

/**
 * The system's prompt, by a strong biometric or the screen lock, for one
 * use of a Key B: the Keystore lets that one cipher through and nothing
 * else. Called on the main thread, from [activity] while it is shown.
 */
class BiometricAuthorizer(
    private val activity: FragmentActivity,
    private val title: String,
    private val subtitle: String,
) : Authorizer {
    override suspend fun allow(seal: Seal): Boolean {
        val cipher = seal.cipher ?: return false
        return withContext(Dispatchers.Main.immediate) { ask(cipher) }
    }

    private suspend fun ask(cipher: Cipher): Boolean =
        suspendCancellableCoroutine { done ->
            val prompt =
                BiometricPrompt(
                    activity,
                    activity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (done.isActive) done.resume(true)
                        }

                        // A failed finger is tried again in the prompt; only its end answers.
                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence,
                        ) {
                            if (done.isActive) done.resume(false)
                        }
                    },
                )
            // Cancellation may come from any thread; the prompt is the main thread's.
            done.invokeOnCancellation { activity.mainExecutor.execute { prompt.cancelAuthentication() } }
            prompt.authenticate(
                BiometricPrompt.PromptInfo
                    .Builder()
                    .setTitle(title)
                    .setSubtitle(subtitle)
                    .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
                    .build(),
                BiometricPrompt.CryptoObject(cipher),
            )
        }
}
