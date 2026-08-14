#!/usr/bin/env bash
#
# Client container entrypoint: make the things a login needs exist, start a
# syslog sink so the PAM module's own log survives, then run sshd in the
# foreground.

set -euo pipefail

mkdir -p /run/sshd /harness/logs

# Host keys are per-container, and the harness never checks them.
ssh-keygen -A

# /home is a volume shared with the broker, which writes
# /home/<user>/.ssh/authorized_keys. A named volume can be initialised by
# whichever container starts first, so do not rely on the home directories the
# image built — make them here, after the mount.
for user in alice bob; do
    mkdir -p "/home/${user}"
    chown "${user}:${user}" "/home/${user}"
    chmod 0755 "/home/${user}"
done

# pam_oidc.so logs to syslog (LOG_AUTHPRIV), and a container has no syslog
# daemon, so everything the module says about a failed login would be discarded.
# busybox's syslogd is enough to land it in a file the cases can grep.
busybox syslogd -n -O /harness/logs/pam.log &

echo "harness client: sshd starting; module log at /harness/logs/pam.log"
exec /usr/sbin/sshd -D -e
