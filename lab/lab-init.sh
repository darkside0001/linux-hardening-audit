#!/bin/bash
# Stand-in for systemd in the lab container: starts what a booted VPS would run.
# Services the hardening script enabled are started too, the way systemd would
# start enabled units after a reboot.
ssh-keygen -A >/dev/null
/usr/sbin/sshd
# A forgotten development server listening on every interface.
mkdir -p /var/www
python3 -m http.server 8080 --directory /var/www >/dev/null 2>&1 &
[ -f /etc/lab/enabled/nftables ] && nft -f /etc/nftables.conf
[ -f /etc/lab/enabled/fail2ban ] && fail2ban-server -b >/dev/null 2>&1
exec sleep infinity
