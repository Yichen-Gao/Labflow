#!/usr/bin/env bash
set -euo pipefail

RULES_DIR=${RULES_DIR:-/etc/audit/rules.d}
RULES_PATH=${RULES_PATH:-${RULES_DIR}/labflow-exec.rules}

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

mkdir -p "${RULES_DIR}"
cat > "${RULES_PATH}" <<'EOF'
-a always,exit -F arch=b64 -S execve -k labflow-exec
-a always,exit -F arch=b32 -S execve -k labflow-exec
EOF

if command -v augenrules >/dev/null 2>&1; then
  augenrules --load
  echo "Installed auditd execve rules via augenrules: ${RULES_PATH}"
  exit 0
fi

if command -v auditctl >/dev/null 2>&1; then
  auditctl -R "${RULES_PATH}"
  echo "Installed auditd execve rules via auditctl: ${RULES_PATH}"
  exit 0
fi

echo "Wrote ${RULES_PATH}, but auditd tooling was not found." >&2
echo "Please install auditd first, then reload the rules." >&2
