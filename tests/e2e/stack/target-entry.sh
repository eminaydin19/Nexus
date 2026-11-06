#!/bin/sh
set -e
mkdir -p /run/sshd /var/log/nginx
touch /var/log/auth.log /var/log/kern.log /var/log/nginx/access.log
rsyslogd
/usr/sbin/sshd
nginx
exec sleep infinity
