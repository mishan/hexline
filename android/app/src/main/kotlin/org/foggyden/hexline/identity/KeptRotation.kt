package org.foggyden.hexline.identity

import android.util.Base64
import org.foggyden.hexline.core.Posted
import org.json.JSONArray
import org.json.JSONObject

/** How far a rotation has gone on this phone. */
enum class RotationState {
    /** About to hold the successor's key: nothing signed. */
    Holding,

    /** Signed, and not yet sent anywhere. */
    Signed,

    /** A send to a registrar may have reached it: the rotation can only be finished. */
    Sent,
}

/** How far a rotation has gone at one registrar. */
enum class RegistrarState {
    Signed,
    Sent,
    Pending,
    PendingElsewhere,

    /** Frozen there by its operator: posted again later, published once the freeze is lifted. */
    Frozen,

    /**
     * Refused there for good, as [RotationRegistrar.refused] says: not posted to again. At the
     * home registrar nothing else is posted either, and the identity stays as it was; what the
     * person does then is the rotation screen's to offer.
     */
    Refused,

    /**
     * Another rotation to the same successor was published there first, under the commitment
     * [RotationRegistrar.supersededBy] names: another phone, or whoever holds the old key and the
     * successor code. Not posted to again; at the home registrar, nothing else is.
     */
    Superseded,

    /**
     * The identity was rotated there to a key other than this rotation's, which
     * [RotationRegistrar.rotatedTo] names: whoever holds the old key, or another phone with a
     * successor code of its own. Not posted to again; at the home registrar, nothing else is.
     */
    RotatedAway,
    Published,
    Reattested,
    CardPut,
}

/** What a rotation's file holds: none, one that does not read, or the rotation. */
sealed interface FoundRotation {
    data object None : FoundRotation

    data object Unreadable : FoundRotation

    data class Read(
        val rotation: KeptRotation,
    ) : FoundRotation
}

/** The rotation found, if one was and it read. */
val FoundRotation.read: KeptRotation? get() = (this as? FoundRotation.Read)?.rotation

/** A registrar a rotation is posted to, and the handles there to reissue. */
data class RotationRegistrar(
    val base: String,
    val handles: List<String>,
    val home: Boolean,
    val state: RegistrarState = RegistrarState.Signed,
    /**
     * Where [state] is [RegistrarState.Pending], when the registrar publishes it, and where
     * [RegistrarState.PendingElsewhere], when the rotation held before it does, in seconds:
     * 0 where it did not say.
     */
    val until: Long = 0,
    /** Where [state] is [RegistrarState.Refused], the registrar's code. */
    val refused: String? = null,
    /** Where [state] is [RegistrarState.Superseded], the commitment the published rotation names. */
    val supersededBy: String? = null,
    /** Where [state] is [RegistrarState.RotatedAway], the key the identity was rotated to. */
    val rotatedTo: String? = null,
    /** When it was last posted to, answered or not, in seconds. */
    val postedAt: Long = 0,
    /** How long after [postedAt] it is posted to again, in seconds. */
    val wait: Long = 0,
    /** The posts in a row that changed nothing, no answer or the same one again, each doubling [wait]. */
    val failures: Int = 0,
)

/**
 * How long a registrar is left after an answer that changed something, in seconds, whatever its
 * clock says of its times; doubled for each post in a row that changed nothing, up to
 * [REPOST_CEILING], so a freeze or a registrar that will not answer costs it and the phone's
 * battery little however long it lasts.
 */
const val REPOST_FLOOR = 60L
const val REPOST_CEILING = 3600L

/** The longest a `rate_limited` answer's `retry_after` is waited for, in seconds. */
const val RETRY_AFTER_CEILING = 86_400L

/**
 * A rotation of the identity [from] to its successor [to] under way: what a
 * start resumes it from, or discards it by. Not secret, but powerful: anyone
 * may post [record], to the owner's own successor alone.
 */
data class KeptRotation(
    val from: String,
    val to: String,
    /** [from]'s card, to read the successor code against again if the successor's hold is lost. */
    val card0: ByteArray,
    val state: RotationState,
    /** Signed once, and sent as these bytes however often it is sent. */
    val record: ByteArray? = null,
    val registrars: List<RotationRegistrar> = emptyList(),
    /** The successor's recovery envelope is stored at the home registrar. */
    val backedUp: Boolean = false,
) {
    init {
        require(state == RotationState.Holding || record != null) { "a rotation signed has its record" }
    }

    /**
     * As [registrar]'s [answer] to [record], posted at [now], leaves it: null where none came,
     * with the [retryAfter] seconds a `rate_limited` one asked for, up to [RETRY_AFTER_CEILING].
     */
    fun posted(
        registrar: String,
        answer: Posted?,
        now: Long,
        retryAfter: Long? = null,
    ): KeptRotation {
        require(state == RotationState.Sent) { "posted only once marked sent" }
        require(registrars.any { it.base == registrar }) { "posted to a registrar of its own" }
        return copy(
            registrars =
                registrars.map {
                    if (it.base != registrar) return@map it
                    val cleared = RotationRegistrar(it.base, it.handles, it.home)
                    val answered =
                        when (answer) {
                            null -> it
                            Posted.Published -> cleared.copy(state = RegistrarState.Published)
                            Posted.Frozen -> cleared.copy(state = RegistrarState.Frozen)
                            is Posted.Pending -> cleared.copy(state = RegistrarState.Pending, until = answer.until.toLong())
                            is Posted.PendingElsewhere ->
                                cleared.copy(state = RegistrarState.PendingElsewhere, until = answer.until?.toLong() ?: 0)
                            is Posted.Superseded -> cleared.copy(state = RegistrarState.Superseded, supersededBy = answer.next)
                            is Posted.RotatedAway -> cleared.copy(state = RegistrarState.RotatedAway, rotatedTo = answer.successor)
                            is Posted.Refused -> cleared.copy(state = RegistrarState.Refused, refused = answer.code)
                        }
                    // The same answer again, a freeze's or a hold's past its time, is waited on
                    // longer each time, as no answer is.
                    if (answer != null && answered != it.copy(postedAt = 0, wait = 0, failures = 0)) {
                        return@map answered.copy(postedAt = now, wait = REPOST_FLOOR)
                    }
                    val backoff = minOf(REPOST_FLOOR shl minOf(it.failures, 6), REPOST_CEILING)
                    val retry = minOf(retryAfter ?: 0, RETRY_AFTER_CEILING)
                    answered.copy(postedAt = now, wait = maxOf(backoff, retry), failures = it.failures + 1)
                },
        )
    }

    /**
     * The registrars [record] is to be posted to at [now], in seconds: none before it is
     * marked sent, the home registrar alone until it has published, none posted to within its
     * [RotationRegistrar.wait] (but one the clock now puts in the future, set back since), a
     * held one only once its time has come, and never one that refused it for good, was
     * superseded or rotated away, or has published it.
     */
    fun due(now: Long): List<RotationRegistrar> {
        if (state != RotationState.Sent) return emptyList()
        val home = registrars.filter { it.home }
        val asked = if (home.all { it.state >= RegistrarState.Published }) registrars else home
        return asked.filter {
            (it.postedAt > now || now >= it.postedAt + it.wait) &&
                when (it.state) {
                    RegistrarState.Signed, RegistrarState.Sent, RegistrarState.Frozen -> true
                    RegistrarState.Pending, RegistrarState.PendingElsewhere -> now >= it.until
                    else -> false
                }
        }
    }

    fun encode(): ByteArray =
        JSONObject()
            .put("from", from)
            .put("to", to)
            .put("card0", b64(card0))
            .put("state", state.name)
            .put(
                "registrars",
                JSONArray().apply {
                    for (r in registrars) {
                        put(
                            JSONObject()
                                .put("base", r.base)
                                .put("handles", JSONArray(r.handles))
                                .put("home", r.home)
                                .put("state", r.state.name)
                                .put("until", r.until)
                                .put("posted_at", r.postedAt)
                                .put("wait", r.wait)
                                .put("failures", r.failures)
                                .apply {
                                    r.refused?.let { put("refused", it) }
                                    r.supersededBy?.let { put("superseded_by", it) }
                                    r.rotatedTo?.let { put("rotated_to", it) }
                                },
                        )
                    }
                },
            ).apply {
                record?.let { put("record", b64(it)) }
                if (backedUp) put("backed_up", true)
            }.toString()
            .toByteArray()

    companion object {
        /** What [bytes] say, or null if they do not read as a rotation. */
        fun decode(bytes: ByteArray): KeptRotation? =
            try {
                val json = JSONObject(String(bytes))
                val registrars = json.getJSONArray("registrars")
                KeptRotation(
                    json.getString("from"),
                    json.getString("to"),
                    unb64(json.getString("card0")),
                    RotationState.valueOf(json.getString("state")),
                    json.optString("record").ifEmpty { null }?.let(::unb64),
                    (0 until registrars.length()).map { i ->
                        val r = registrars.getJSONObject(i)
                        val handles = r.getJSONArray("handles")
                        RotationRegistrar(
                            r.getString("base"),
                            (0 until handles.length()).map(handles::getString),
                            r.getBoolean("home"),
                            RegistrarState.valueOf(r.getString("state")),
                            r.getLong("until"),
                            r.optString("refused").ifEmpty { null },
                            r.optString("superseded_by").ifEmpty { null },
                            r.optString("rotated_to").ifEmpty { null },
                            r.optLong("posted_at"),
                            r.optLong("wait"),
                            r.optInt("failures"),
                        )
                    },
                    json.optBoolean("backed_up"),
                )
            } catch (_: Exception) {
                null
            }

        private fun b64(b: ByteArray) = Base64.encodeToString(b, Base64.NO_WRAP)

        private fun unb64(s: String) = Base64.decode(s, Base64.NO_WRAP)
    }
}
