#!/bin/sh
set -eu

ScriptName="Detect-SSHConfig-Risks"
LogPath="/tmp/${ScriptName}.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
RunStart=$(date +%s)

WriteLog() {
  level="${1:-INFO}"; message="$2"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$level] $message"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath"
}
RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}
iso_now(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

BeginNDJSON(){ TMP_AR="$(mktemp)"; }
AddRecord(){
  ts="$(iso_now)"
  issue="$1"; path="$2"; owner="$3"; perms="$4"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"issue":"%s","path":"%s","owner":"%s","perms":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" \
    "$(escape_json "$issue")" "$(escape_json "$path")" "$(escape_json "$owner")" "$(escape_json "$perms")" >> "$TMP_AR"
}
AddStatus(){
  ts="$(iso_now)"; st="${1:-info}"; msg="$(escape_json "${2:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"%s","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$st" "$msg" >> "$TMP_AR"
}
CommitNDJSON(){
  [ -s "$TMP_AR" ] || AddStatus "no_results" "no risky SSH config files found"
  AR_DIR="$(dirname "$ARLog")"
  [ -d "$AR_DIR" ] || WriteLog "WARN" "Directory missing: $AR_DIR (will attempt write anyway)"
  if mv -f "$TMP_AR" "$ARLog"; then
    WriteLog "INFO" "Wrote NDJSON to $ARLog"
  else
    WriteLog "WARN" "Primary write FAILED to $ARLog"
    if mv -f "$TMP_AR" "$ARLog.new"; then
      WriteLog "WARN" "Wrote NDJSON to $ARLog.new (fallback)"
    else
      keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "ERROR" "Failed to write both $ARLog and $ARLog.new; saved $keep"
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "INFO" "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}"
    fi
  done
}

file_owner(){ stat -c '%U' "$1" 2>/dev/null || echo "unknown"; }
file_perms(){ stat -c '%a' "$1" 2>/dev/null || echo "-"; }
check_world_writable(){
  find /home/*/.ssh/ -type f \( -name config -o -name authorized_keys \) -perm -0002 2>/dev/null \
  | while IFS= read -r f; do
      [ -f "$f" ] || continue
      AddRecord "world_writable" "$f" "$(file_owner "$f")" "$(file_perms "$f")"
    done
}

check_hidden_outside_home(){
  find / -type f \( -name config -o -name authorized_keys \) -path "*/.ssh/*" ! -path "/home/*" 2>/dev/null \
  | while IFS= read -r f; do
      [ -f "$f" ] || continue
      AddRecord "hidden_outside_home" "$f" "$(file_owner "$f")" "$(file_perms "$f")"
    done
}

RotateLog
WriteLog "INFO" "=== SCRIPT START : $ScriptName (host=$HostName) ==="
BeginNDJSON

check_world_writable
check_hidden_outside_home

CommitNDJSON

Duration=$(( $(date +%s) - RunStart ))
WriteLog "INFO" "=== SCRIPT END : duration ${Duration}s ==="
