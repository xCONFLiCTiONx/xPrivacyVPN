package com.xconflictionx.xprivacyvpn.vpn.transport

/**
 * Thin JNI facade for Aether's upstream JSON C ABI.
 *
 * All returned strings are JSON replies. Job-producing calls return a job handle;
 * callers must poll and eventually free that handle. This class deliberately does
 * not claim to provide Android socket protection or TUN packet forwarding yet.
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
}
