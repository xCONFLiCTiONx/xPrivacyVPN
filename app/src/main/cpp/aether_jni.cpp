#include <jni.h>
#include <cstdint>
#include <string>

#include "aether_ffi.h"

namespace {

std::string from_java(JNIEnv *env, jstring value) {
    if (value == nullptr) return {};
    const char *chars = env->GetStringUTFChars(value, nullptr);
    if (chars == nullptr) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

jstring to_java(JNIEnv *env, char *raw) {
    if (raw == nullptr) {
        return env->NewStringUTF("{\"ok\":false,\"error\":\"Aether returned a null response\"}");
    }
    jstring result = env->NewStringUTF(raw);
    aether_string_free(raw);
    return result;
}

jstring call_string(JNIEnv *env, jstring value, char *(*function)(const char *)) {
    const std::string input = from_java(env, value);
    return to_java(env, function(input.c_str()));
}

jstring call_id(JNIEnv *env, jlong id, char *(*function)(uint64_t)) {
    return to_java(env, function(static_cast<uint64_t>(id)));
}

jstring call_id_string(JNIEnv *env, jlong id, jstring value,
                       char *(*function)(uint64_t, const char *)) {
    const std::string input = from_java(env, value);
    return to_java(env, function(static_cast<uint64_t>(id), input.c_str()));
}

} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeVersion(
        JNIEnv *env, jobject) {
    return to_java(env, aether_version());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeIdentityOpen(
        JNIEnv *env, jobject, jstring payload) {
    return call_string(env, payload, aether_identity_open);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeIdentitySummary(
        JNIEnv *env, jobject, jlong identity) {
    return call_id(env, identity, aether_identity_summary);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeIdentityFree(
        JNIEnv *env, jobject, jlong identity) {
    return call_id(env, identity, aether_identity_free);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeScanStart(
        JNIEnv *env, jobject, jlong identity, jstring payload) {
    return call_id_string(env, identity, payload, aether_scan_start);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeVerifyStart(
        JNIEnv *env, jobject, jlong identity, jstring payload) {
    return call_id_string(env, identity, payload, aether_verify_start);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeTunnelStart(
        JNIEnv *env, jobject, jlong identity, jstring payload) {
    return call_id_string(env, identity, payload, aether_tunnel_start);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeJobPoll(
        JNIEnv *env, jobject, jlong job) {
    return call_id(env, job, aether_job_poll);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeJobCancel(
        JNIEnv *env, jobject, jlong job) {
    return call_id(env, job, aether_job_cancel);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeJobFree(
        JNIEnv *env, jobject, jlong job) {
    return call_id(env, job, aether_job_free);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeTeamSignIn(
        JNIEnv *env, jobject, jstring payload) {
    return call_string(env, payload, aether_team_sign_in);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeTeamCodeRequest(
        JNIEnv *env, jobject, jstring payload) {
    return call_string(env, payload, aether_team_code_request);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeTeamCodeResend(
        JNIEnv *env, jobject, jlong session) {
    return call_id(env, session, aether_team_code_resend);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeTeamCodeSubmit(
        JNIEnv *env, jobject, jlong session, jstring code) {
    return call_id_string(env, session, code, aether_team_code_submit);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeTeamSessionFree(
        JNIEnv *env, jobject, jlong session) {
    return call_id(env, session, aether_team_session_free);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeTeamTokenSet(
        JNIEnv *env, jobject, jstring token) {
    return call_string(env, token, aether_team_token_set);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_xconflictionx_xprivacyvpn_vpn_transport_AetherNative_nativeTeamTokenClear(
        JNIEnv *env, jobject) {
    return to_java(env, aether_team_token_clear());
}
