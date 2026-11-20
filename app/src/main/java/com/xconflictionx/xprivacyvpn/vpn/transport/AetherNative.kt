package com.xconflictionx.xprivacyvpn.vpn.transport

import kotlinx.coroutines.delay
import org.json.JSONObject

/**
 * Thin JNI facade for Aether's upstream JSON C ABI.
 *
 * Async operations return {"job": id}; awaitJob() polls the job and returns its
 * final JSON result. This facade does not claim to provide Android socket
 * protection or TUN packet forwarding yet.
 */
object AetherNative {
    init {
        System.loadLibrary("aether")
        System.loadLibrary("xprivacy_aether_jni")
    }

    external fun nativeVersion(): String
    external fun nativeIdentityOpen(payloadJson: String): String
    external fun nativeIdentitySummary(identity: Long): String
    external fun nativeIdentityFree(identity: Long): String
    external fun nativeScanStart(identity: Long, payloadJson: String): String
    external fun nativeVerifyStart(identity: Long, payloadJson: String): String
    external fun nativeTunnelStart(identity: Long, payloadJson: String): String
    external fun nativeJobPoll(job: Long): String
    external fun nativeJobCancel(job: Long): String
    external fun nativeJobFree(job: Long): String
    external fun nativeTeamSignIn(payloadJson: String): String
    external fun nativeTeamCodeRequest(payloadJson: String): String
    external fun nativeTeamCodeResend(session: Long): String
    external fun nativeTeamCodeSubmit(session: Long, code: String): String
    external fun nativeTeamSessionFree(session: Long): String
    external fun nativeTeamTokenSet(token: String): String
    external fun nativeTeamTokenClear(): String

    /**
     * Poll an Aether asynchronous operation until it finishes.
     *
     * The returned JSONObject is the completed operation's result (including
     * its "ok" field). The native job handle is always released.
     */
    suspend fun awaitJob(startReply: String, timeoutMs: Long = 180_000L): JSONObject {
        val start = JSONObject(startReply)
        if (!start.optBoolean("ok", false)) {
            throw IllegalStateException(start.optString("error", "Aether operation could not start"))
        }
        val jobId = start.optLong("job", 0L)
        require(jobId > 0L) { "Aether did not return a valid job handle" }

        val deadline = android.os.SystemClock.elapsedRealtime() + timeoutMs
        try {
            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                val poll = JSONObject(nativeJobPoll(jobId))
                if (!poll.optBoolean("ok", false)) {
                    throw IllegalStateException(poll.optString("error", "Aether job polling failed"))
                }
                when (poll.optString("state")) {
                    "running" -> delay(150L)
                    "done" -> {
                        val result = poll.optJSONObject("result")
                            ?: throw IllegalStateException("Aether returned an empty job result")
                        if (!result.optBoolean("ok", false)) {
                            throw IllegalStateException(result.optString("error", "Aether operation failed"))
                        }
                        return result
                    }
                    else -> throw IllegalStateException("Unknown Aether job state: ${poll.optString("state")}")
                }
            }
            nativeJobCancel(jobId)
            throw kotlinx.coroutines.TimeoutCancellationException("Aether operation timed out after ${timeoutMs}ms")
        } finally {
            nativeJobFree(jobId)
        }
    }
}
