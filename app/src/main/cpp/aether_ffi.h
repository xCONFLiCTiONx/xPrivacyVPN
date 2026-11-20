#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

char *aether_version(void);
void aether_string_free(char *raw);
char *aether_job_poll(uint64_t id);
char *aether_job_cancel(uint64_t id);
char *aether_job_free(uint64_t id);
char *aether_identity_open(const char *payload);
char *aether_identity_summary(uint64_t id);
char *aether_identity_free(uint64_t id);
char *aether_scan_start(uint64_t identity, const char *payload);
char *aether_verify_start(uint64_t identity, const char *payload);
char *aether_tunnel_start(uint64_t identity, const char *payload);
char *aether_team_sign_in(const char *payload);
char *aether_team_code_request(const char *payload);
char *aether_team_code_resend(uint64_t session);
char *aether_team_code_submit(uint64_t session, const char *code);
char *aether_team_session_free(uint64_t session);
char *aether_team_token_set(const char *token);
char *aether_team_token_clear(void);

#ifdef __cplusplus
}
#endif
