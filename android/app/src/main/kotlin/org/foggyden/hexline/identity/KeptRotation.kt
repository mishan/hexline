package org.foggyden.hexline.identity

import android.util.Base64
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
enum class RegistrarState { Signed, Sent, Pending, PendingElsewhere, Published, Reattested, CardPut }

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
    /** Where [state] is [RegistrarState.Pending], when the registrar publishes it, in seconds. */
    val until: Long = 0,
)

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
                                .put("until", r.until),
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
