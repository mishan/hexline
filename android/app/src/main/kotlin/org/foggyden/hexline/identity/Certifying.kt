package org.foggyden.hexline.identity

import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.HolderRequest
import org.foggyden.hexline.core.HolderSessionInterface
import org.foggyden.hexline.core.Qr

/** A session at a mailbox the model drives (the core's, or a test's), closed to let it go. */
interface CertifySession :
    HolderSessionInterface,
    AutoCloseable

/**
 * Where certifying another device for a held identity stands: a code shown
 * for it to type, or a QR code to scan, then its request asked about.
 */
sealed interface Certifying {
    data object Idle : Certifying

    data object Opening : Certifying

    /**
     * Waiting for a device to ask by [code] at [host], or by scanning [qr]
     * where there is one, to be certified for the identity [identity], shown
     * as [shown].
     */
    data class Showing(
        val identity: String,
        val shown: String,
        val code: String,
        val host: String,
        val expiresIn: Long,
        val qr: Qr?,
    ) : Certifying {
        override fun toString() = "Showing($identity, code=redacted, host=$host)"
    }

    /**
     * A device asked to be certified for [identity]: whether to, and whether
     * to let it manage the account. One [revoked] here is not to be.
     */
    data class Asked(
        val identity: String,
        val request: HolderRequest,
        val revoked: Boolean = false,
    ) : Certifying

    data object Answering : Certifying

    data class Approved(
        val device: MintedDevice,
    ) : Certifying

    data object Denied : Certifying

    /** The code admits nobody now, for [why]: a new one is to be shown. */
    data class Ended(
        val why: CertifyEnd,
    ) : Certifying

    data class Failed(
        val problem: SetupProblem,
    ) : Certifying
}

enum class CertifyEnd {
    Expired,

    /** The server keeps no mailbox to certify through. */
    NoMailbox,

    /** A device that scanned some other QR code, or tampered with this one's: said no to unasked. */
    Unpaired,

    /** A request from a device whose clock is far from this phone's: said no to unasked. */
    Stale,

    /** A request no device makes: said no to unasked. */
    Unreadable,

    /** A request for a certificate that signs in nowhere: said no to unasked. */
    NoLogin,
}

/** The end a waiting session was refused as, if it is one; null for any other trouble. */
fun certifyEnd(e: CoreException): CertifyEnd? =
    when ((e as? CoreException.Refused)?.code) {
        "expired", "used" -> CertifyEnd.Expired
        "no_mailbox" -> CertifyEnd.NoMailbox
        "unpaired_request" -> CertifyEnd.Unpaired
        "stale_request" -> CertifyEnd.Stale
        "unreadable_request" -> CertifyEnd.Unreadable
        "no_login_request" -> CertifyEnd.NoLogin
        else -> null
    }

/** Why a device is revoked, as the registrar's record says it (registrar §4.4). */
enum class RevokeReason(
    val code: ULong,
) {
    Lost(1u),
    Stolen(2u),
    Retired(3u),
}

/** Where revoking a device this phone certified stands. */
sealed interface Revoking {
    data object Idle : Revoking

    data object Working : Revoking

    data class Done(
        val device: MintedDevice,
    ) : Revoking

    data class Failed(
        val problem: SetupProblem,
    ) : Revoking
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
) {
    override fun equals(other: Any?) =
        other is MintedDevice &&
            device.contentEquals(other.device) &&
            fingerprint == other.fingerprint &&
            name == other.name &&
            expires == other.expires &&
            canManage == other.canManage &&
            revoked == other.revoked &&
            own == other.own

    override fun hashCode() = device.contentHashCode()

    override fun toString() = "MintedDevice($fingerprint, $name, revoked=$revoked, own=$own)"
}
