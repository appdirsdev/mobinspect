#!/bin/bash
# Find the MobInspect prod server on the LAN and report its URL + health.
# The VM's DHCP IP changes across reboots, so we identify it by its SSH host
# key fingerprint, not by address.
#
# Usage:
#   ./prod.sh          find server, print URL + health
#   ./prod.sh ssh      find server, then open an SSH session to it
#   SUBNET=10.249.54 ./prod.sh   (override the /24 to scan)
set -u
SUBNET="${SUBNET:-10.249.54}"
HOSTKEY="AAAAC3NzaC1lZDI1NTE5AAAAIHldKXWj+kHYr/IbrNENUXaeMfy4uEIhOKkVC3Y5cy6/"
CACHE="$HOME/.mobinspect-prod-ip"

is_server() {
    ssh-keyscan -t ed25519 -T 2 "$1" 2>/dev/null | grep -qF "$HOSTKEY"
}

ip=""
# 1) last known IP (fast path)
if [ -f "$CACHE" ]; then
    last=$(cat "$CACHE")
    if is_server "$last"; then ip="$last"; fi
fi
# 2) ARP neighbors on the subnet
if [ -z "$ip" ]; then
    SUBNET_RE="${SUBNET//./\\.}"
    for c in $(arp -a 2>/dev/null | grep -oE "${SUBNET_RE}\.[0-9]+" | sort -u); do
        if is_server "$c"; then ip="$c"; break; fi
    done
fi
# 3) full /24 sweep
if [ -z "$ip" ]; then
    echo "Scanning $SUBNET.0/24 for the MobInspect server (by SSH fingerprint)..." >&2
    ip=$(for i in $(seq 1 254); do
        ( is_server "$SUBNET.$i" && echo "$SUBNET.$i" ) &
    done; wait)
    ip=$(echo "$ip" | head -n1)
fi

if [ -z "$ip" ]; then
    echo "ERROR: MobInspect server not found on $SUBNET.0/24 (is the VM up?)" >&2
    exit 1
fi
echo "$ip" > "$CACHE"

# The key already matched the trusted fingerprint above, so it is safe to
# record it under this (possibly new) IP and avoid the ssh prompt.
if ! ssh-keygen -F "$ip" > /dev/null 2>&1; then
    ssh-keyscan -t ed25519 -T 3 "$ip" 2>/dev/null >> "$HOME/.ssh/known_hosts"
fi

if [ "${1:-}" = "ssh" ]; then
    exec ssh "mobinspect@$ip"
fi

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$ip/" || echo "unreachable")
health=$(curl -s --max-time 10 "http://$ip/healthz" || echo "unreachable")
echo "MobInspect prod : http://$ip/"
echo "HTTP status     : $code"
echo "Health          : $health"
if [ "$code" = "400" ]; then
    echo "NOTE: 400 = ALLOWED_HOSTS not yet refreshed; the on-server watch timer"
    echo "fixes this within ~2 min. To force it now:"
    echo "  ssh mobinspect@$ip 'sudo /usr/local/bin/mobinspect-hosts-refresh --apply'"
fi
