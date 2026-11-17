package org.foggyden.hexline.debug

import android.os.Build
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.foggyden.hexline.BuildConfig
import org.foggyden.hexline.R
import org.foggyden.hexline.core.holderMint
import org.foggyden.hexline.core.newIdentity
import org.foggyden.hexline.identity.BiometricAuthorizer
import org.foggyden.hexline.identity.HeldSeeds
import org.foggyden.hexline.identity.Identities
import org.foggyden.hexline.secrets.KeystoreHolderKeys
import org.foggyden.hexline.secrets.NoHolderKeys
import org.foggyden.hexline.secrets.NoScreenLock
import org.foggyden.hexline.secrets.SoftwareKeysOnly
import java.io.File

/**
 * Holder mode's Key B end to end, before its screens exist (slice 6b
 * makes an identity; this makes a throwaway one): hold a new identity's
 * seed behind the prompt, then mint this phone's device from it behind
 * the prompt again. Compiled into debug builds alone.
 */
class HolderDebugActivity : FragmentActivity() {
    val held by lazy {
        HeldSeeds(
            File(filesDir, "held"),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) KeystoreHolderKeys(this) else NoHolderKeys,
            Dispatchers.IO,
            softwareKeys = BuildConfig.DEBUG,
        )
    }
    private val identities by lazy { Identities(this) }
    private val authorizer by lazy { BiometricAuthorizer(this, "Hexline", "Use this phone's identity key") }
    private var card: ByteArray? = null
    var fingerprint: String? = null
        private set
    private val status = mutableStateOf("")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface {
                    Column(Modifier.padding(24.dp)) {
                        Button({ lifecycleScope.launch { status.value = held() } }) { Text("Hold a new identity") }
                        Button({ lifecycleScope.launch { status.value = "minted: ${mint()}" } }) { Text("Mint this phone's device") }
                        Text(status.value)
                    }
                }
            }
        }
    }

    private suspend fun held() =
        try {
            "held: ${hold()}"
        } catch (_: SoftwareKeysOnly) {
            getString(R.string.holder_software_only)
        } catch (_: NoScreenLock) {
            "Set a screen lock first"
        }

    /** A new identity's seed held behind the prompt; whether the person allowed it. */
    suspend fun hold(): Boolean {
        val made = newIdentity("Hexline holder test")
        return try {
            held.hold(made.fingerprint, made.seed, authorizer).also {
                if (it) {
                    card = made.card
                    fingerprint = made.fingerprint
                }
            }
        } finally {
            made.seed.fill(0)
        }
    }

    /** This phone's device, minted from the held seed and kept: its fingerprint, or null. */
    suspend fun mint(): String? {
        val fp = fingerprint ?: return null
        val card = card ?: return null
        return held.use(fp, authorizer) { seed ->
            val minted = holderMint(seed, card, "Hexline")
            try {
                withContext(Dispatchers.IO) { identities.save(minted.deviceSeed, minted.cert, card, null, null) }.fingerprint
            } finally {
                minted.deviceSeed.fill(0)
            }
        }
    }
}
