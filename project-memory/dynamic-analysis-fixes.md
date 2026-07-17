---
name: dynamic-analysis-fixes
description: Fixes required to make Dynamic Analysis work on a local Android 11 (API 30) emulator
metadata: 
  node_type: memory
  type: project
  originSessionId: ddb6a3a9-3aa7-4d11-bc01-6d22ba1f4ff1
---

Getting MobInspect Dynamic Analysis working against a local Android Studio emulator required three fixes (the first two surface as the misleading UI error "Cannot connect to <identifier>"):

1. **Emulator identifier must be TCP, not `emulator-5554`.** MobInspect connects via `adb connect <identifier>`, which only works for `host:port` targets. `adb connect emulator-5554` fails ("failed to resolve host"). Fix: `export MOBINSPECT_ANALYZER_IDENTIFIER=127.0.0.1:5555` (the emulator's adb TCP port) and `adb connect 127.0.0.1:5555`. Baked into [[start-script]].

2. **API level ceiling → settled on API 30 (Android 11).** `system_check()` rejects any device with `api > ANDROID_API_SUPPORTED` (=30). Raising the constant 30→34 to keep the API 34 AVD did NOT fix DA — installs still failed with "This APK cannot be installed... adb install failed". So that edit was **reverted (constant back to 30, file git-clean)** and an API-30 image was set up instead:
   - Downloaded `system-images;android-30;google_apis;arm64-v8a` via brew `sdkmanager` (needs `JAVA_HOME=/opt/homebrew/opt/openjdk@17` + `--sdk_root=~/Library/Android/sdk`).
   - `avdmanager` resolves its SDK root from its OWN install path and ignores `ANDROID_SDK_ROOT`, so it couldn't see the image. Fix: **copy** brew's `cmdline-tools/latest` into `~/Library/Android/sdk/cmdline-tools/latest` (a symlink fails — Java canonicalizes it back to the brew path, which has no system-images).
   - Created AVD `MobInspect_API30` (pixel_5). `start.sh` now uses `AVD="${AVD:-MobInspect_API30}"`. Old `MobInspect_API34` AVD kept as fallback.

3. **Frida spawn failed with `unable to load libart.so` — root cause was the `/system` install path (CODE FIX).** After API 30 + connect worked, Frida instrumentation still failed: `frida.NotSupportedError: unable to load libart.so: dlopen failed: library "libart.so" not found` at `device.spawn()` (`frida_core.py:175`). **Empirically proven root cause:** MobInspect pushed frida-server to `/system/fd_server`; a binary run from `/system` gets the SELinux `system_file` context, whose restricted linker namespace CANNOT dlopen the ART runtime from the `/apex/com.android.art/` APEX mount (on Android 10+/API 29+, `libart.so` lives only at `/apex/com.android.art/lib64/libart.so`, not `/system/lib64`). Same binary from `/data/local/tmp` (`shell_data_file` context) has an unrestricted namespace and spawns fine. Proof: identical binary, `/system/fd_server` → error; `/data/local/tmp/frida-server` → works.
   - **Fix (in `environment.py`):** added `FRIDA_SERVER_REMOTE = '/data/local/tmp/fd_server'` and changed `frida_setup()` (push+chmod) and `run_frida_server()` (exec path) to use it instead of `/system/fd_server`. Basename kept as `fd_server` so the `b'fd_server' in ps` running-check still matches. No longer needs `/system` writable for frida.
   - Verified E2E through MobInspect's own path: mobinspecty pushes to `/data/local/tmp/fd_server` (shell_data_file), `POST /frida_instrument/ spawn` → all 5 hooks load, live API monitor captures calls, inDrive runs under Frida, ZERO libart errors.

Verified working on API 30: TCP `adb connect 127.0.0.1:5555`, `adb root` uid=0, `remount` succeeded (overlayfs), `/system` writable, and full Frida spawn+inject.

**Why:** non-obvious because (a) the UI collapses connect/API failures into one generic "Cannot connect" message, and (b) the libart.so error looks like a Frida/version bug but is purely an SELinux-context/linker-namespace consequence of the install path.
**How to apply:** if DA breaks again, check the gunicorn log / `~/.MobInspect/debug.log` for the real cause (API check / connect / mobinspecty / libart) rather than trusting the UI text. frida-server binary is cached at `~/.MobInspect/downloads/frida-server-<ver>-android-arm64` and must run from `/data/local/tmp`.
