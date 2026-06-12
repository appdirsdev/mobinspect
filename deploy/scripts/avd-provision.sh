#!/usr/bin/env bash
# MobInspect — one-time AVD provisioning for dynamic analysis.
#
# Makes the emulator's /system partition writable so mobsfy_init can push the
# Frida server + Burp/MobInspect CA into /system. On API 29+ this REQUIRES
# disabling dm-verity, which only takes effect after a guest reboot. Because
# the AVD unit runs with -no-snapshot (cold boot every start), this must run
# once after each cold boot — hence it's wired as a systemd oneshot ordered
# After=mobinspect-avd.service (see mobinspect-avd-provision.service).
#
# HOST REQUIREMENT: the host's KVM must be able to reboot the emulator guest.
# Bare-metal Linux with KVM works. Some nested-virt hosts (e.g. an ESXi guest
# with marginal VT-x/EPT + I/O) WEDGE the AVD on the post-verity reboot — the
# guest goes 'offline' and never reaches sys.boot_completed. On such hosts
# dynamic analysis is not achievable; use bare metal, a properly-provisioned
# nested-virt host, Genymotion, or a physical device. This script detects the
# wedge, attempts one overlay-wipe cold-boot recovery, and exits non-zero with
# a clear message rather than hanging forever.
set -uo pipefail

ADB="${ANDROID_HOME:-$HOME/android-sdk}/platform-tools/adb"
AVD_DIR="${ANDROID_AVD_HOME:-$HOME/.android/avd}/MobInspect_AVD.avd"
DEVICE="${ANALYZER_IDENTIFIER:-emulator-5554}"
BOOT_TIMEOUT="${AVD_BOOT_TIMEOUT:-300}"   # seconds to wait for a boot

log() { printf '[avd-provision] %s\n' "$*"; }

wait_boot() {
  local waited=0
  "$ADB" start-server >/dev/null 2>&1 || true
  while [ "$waited" -lt "$BOOT_TIMEOUT" ]; do
    if [ "$("$ADB" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
      log "boot_completed after ${waited}s"
      return 0
    fi
    sleep 10; waited=$((waited + 10))
  done
  log "WEDGED: device did not reach boot_completed within ${BOOT_TIMEOUT}s"
  return 1
}

is_writable() {
  "$ADB" -s "$DEVICE" shell 'touch /system/.mi_wtest 2>/dev/null && rm -f /system/.mi_wtest && echo ok' 2>/dev/null | grep -q ok
}

provision() {
  "$ADB" -s "$DEVICE" root >/dev/null 2>&1 || true; sleep 3
  if is_writable; then log "/system already writable — nothing to do"; return 0; fi
  log "disabling dm-verity"
  "$ADB" -s "$DEVICE" disable-verity 2>&1 | sed 's/^/[avd-provision]   /'
  log "rebooting to apply verity change"
  "$ADB" -s "$DEVICE" reboot 2>&1 || true
  sleep 5
  wait_boot || return 1
  "$ADB" -s "$DEVICE" root >/dev/null 2>&1 || true; sleep 3
  "$ADB" -s "$DEVICE" remount 2>&1 | sed 's/^/[avd-provision]   /'
  if is_writable; then log "/system is now WRITABLE — dynamic analysis ready"; return 0; fi
  log "remount did not yield a writable /system"; return 1
}

log "waiting for initial AVD boot"
wait_boot || { log "initial boot wedged; aborting"; exit 1; }

if provision; then exit 0; fi

# One recovery attempt: a wedged post-verity reboot leaves the qcow2 overlay
# dirty, which wedges every subsequent boot. Wipe overlays for a pristine cold
# boot and retry once.
log "first attempt failed; wiping qcow2 overlays and retrying once"
sudo systemctl stop mobinspect-avd.service 2>/dev/null || true
pkill -9 -f 'qemu-system-x86_64.*MobInspect_AVD' 2>/dev/null || true
sleep 3
rm -f "$AVD_DIR"/*.qcow2 "$AVD_DIR"/*.lock "$AVD_DIR"/*.lock.lock 2>/dev/null || true
sudo systemctl start mobinspect-avd.service 2>/dev/null || true
wait_boot || { log "recovery boot wedged; host cannot reboot this AVD — dynamic analysis unavailable on this host"; exit 1; }
if provision; then exit 0; fi
log "ABORT: /system could not be made writable on this host (emulator reboot wedges). See script header for host requirements."
exit 1
