package org.foggyden.hexline.identity

import org.foggyden.hexline.core.CertTime
import org.foggyden.hexline.core.CertifyEnd
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.DeviceStanding
import org.foggyden.hexline.core.HolderRequest
import org.foggyden.hexline.core.HolderSessionInterface
import org.foggyden.hexline.core.NotYetReset
import org.foggyden.hexline.core.Qr
import org.foggyden.hexline.core.certTime
import org.foggyden.hexline.core.certifyEnd

/** A session at a mailbox the model drives (the core's, or a test's), closed to let it go. */
interface CertifySession :
    HolderSessionInterface,
    AutoCloseable

/**
 * Where certifying another device for a held identity stands: a code shown
 * for it to type, or a QR code to scan, then its request asked about. Each
 * state past [Idle] is [identity]'s, the identity it certifies for, and
 * shown on that identity's screen alone.
 */
sealed interface Certifying {
    val identity: String?

    data object Idle : Certifying {
        override val identity: String? = null
    }

    data class Opening(
        override val identity: String,
    ) : Certifying

    /** Waiting for a device to ask by [code] at [host], or by scanning [qr] where there is one; [shown] is the identity as §5.1 shows it. */
    data class Showing(
        override val identity: String,
        val shown: String,
        val code: String,
        val host: String,
        /** Seconds the code lasted when it was shown. */
        val lasts: Long,
        val qr: Qr?,
    ) : Certifying {
        override fun toString() = "Showing($identity, code=redacted, host=$host)"
    }

    /** A device asked: whether to certify it, and whether to let it manage the account. One [revoked] here is not to be. */
    data class Asked(
        override val identity: String,
        val request: HolderRequest,
        val revoked: Revoked = Revoked.No,
    ) : Certifying

    data class Answering(
        override val identity: String,
    ) : Certifying

    data class Approved(
        override val identity: String,
        val device: MintedDevice,
    ) : Certifying

    data class Denied(
        override val identity: String,
    ) : Certifying

    /** The code admits nobody now, for [why]: a new one is to be shown. */
    data class Ended(
        override val identity: String,
        val why: CertifyEnd,
    ) : Certifying

    data class Failed(
        override val identity: String,
        val problem: SetupProblem,
    ) : Certifying
}

/** Whether a device asking was revoked here, as far as this phone can tell. */
enum class Revoked {
    No,
    Yes,

    /** The list of devices certified here did not read: it cannot say. */
    Unknown,
}

/** The end a waiting session was refused as, if it is one; null for any other trouble. */
fun certifyEnd(e: CoreException): CertifyEnd? = (e as? CoreException.Refused)?.let { certifyEnd(it.code) }

/** Where revoking a device certified here stands, for [identity]. */
sealed interface Revoking {
    val identity: String?

    data object Idle : Revoking {
        override val identity: String? = null
    }

    data class Working(
        override val identity: String,
    ) : Revoking

    data class Done(
        override val identity: String,
        val device: MintedDevice,
    ) : Revoking

    data class Failed(
        override val identity: String,
        val problem: SetupProblem,
    ) : Revoking
}

/**
 * The devices [identity]'s key certified here, this phone's own first;
 * [unreadable] when the list would not open just now, and [setAside] when
 * one that did not read is kept aside, [setAsideLoses] when part of that
 * cannot be read at all. [standing] is what the identity's
 * registrars last said of each, by its fingerprint, and [unchecked] that
 * none of their lists read.
 */
data class DeviceList(
    val identity: String,
    val devices: List<MintedDevice>,
    val unreadable: Boolean = false,
    val setAside: Boolean = false,
    val setAsideLoses: Boolean = false,
    val standing: Map<String, DeviceStanding> = emptyMap(),
    val unchecked: Boolean = false,
    /** The devices, by fingerprint, whose revocation a read of the records has shown: confirmed, whatever their standing reads as. */
    val confirmed: Set<String> = emptySet(),
    /** The identity's device epoch kept here: a device certified below it was signed out by a reset. */
    val floor: Long = 0,
    /** The identity's last reset made here, if any. */
    val reset: ResetKept? = null,
    /** The registrar the identity is kept at, which a reset is made at with those its card names. */
    val registrar: String? = null,
) {
    /** Whether [device] is revoked, as this phone marked it or as the registrars publish it. */
    fun revoked(device: MintedDevice) = device.revoked || standing[device.fingerprint] == DeviceStanding.REVOKED

    /**
     * Whether [device] was signed out by a reset: as the registrars say, or,
     * where they have not been read since, as this phone's own floor does.
     */
    fun signedOut(device: MintedDevice) = standing[device.fingerprint] == DeviceStanding.SIGNED_OUT || device.epoch < floor
}

/** What a reset came to, as the screen tells it. */
data class ResetShown(
    val done: List<String>,
    val notDone: List<NotYetReset>,
    val notRegistrars: List<String>,
    /** Of [notDone], those a retry is kept for. */
    val later: List<String>,
)

/** Resetting a held identity's devices. */
sealed interface Resetting {
    val identity: String?

    data object Idle : Resetting {
        override val identity: String? = null
    }

    data class Working(
        override val identity: String,
    ) : Resetting

    data class Done(
        override val identity: String,
        val reset: ResetShown,
    ) : Resetting

    data class Failed(
        override val identity: String,
        val problem: SetupProblem,
    ) : Resetting
}

/** A device certified by a held identity's key on this phone, this phone's own among them. */
class MintedDevice(
    val device: ByteArray,
    /** The device's key as a holder's prompt showed it. */
    val fingerprint: String,
    val name: String?,
    /** When its certificate ends, in seconds. */
    val expires: Long,
    val canManage: Boolean,
    val revoked: Boolean = false,
    /** This phone's own device: revoked only with the identity. */
    val own: Boolean = false,
    /** The device epoch it was certified in. */
    val epoch: Long = 0,
) {
    fun with(revoked: Boolean = this.revoked) = MintedDevice(device, fingerprint, name, expires, canManage, revoked, own, epoch)

    override fun equals(other: Any?) =
        other is MintedDevice &&
            device.contentEquals(other.device) &&
            fingerprint == other.fingerprint &&
            name == other.name &&
            expires == other.expires &&
            canManage == other.canManage &&
            revoked == other.revoked &&
            own == other.own &&
            epoch == other.epoch

    /**
     * Whether it is still listed at [now]: revoked, as that is what refuses
     * its key a renewal, or its certificate in its time as the core judges
     * it, skew included.
     */
    fun listed(now: Long) = revoked || certTime(0uL, expires.toULong(), now.toULong()) != CertTime.EXPIRED

    override fun hashCode() = device.contentHashCode()

    override fun toString() = "MintedDevice($fingerprint, $name, revoked=$revoked, own=$own)"
}
