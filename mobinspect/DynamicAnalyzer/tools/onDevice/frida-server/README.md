# Pre-bundled frida-server (air-gap)

Place `frida-server-<version>-android-<arch>` here to let MobInspect use a
vetted local copy instead of downloading (offline / air-gap deployments).
The SHA-256 for each version+arch is pinned in
`DynamicAnalyzer/views/common/frida/server_update.py` (FRIDA_SERVER_SHA256)
and enforced when MOBINSPECT_FRIDA_VERIFY=1.

Currently staged (not committed — see .gitignore):
  frida-server-17.8.2-android-x86_64   sha256 d1f3d239...96174c
