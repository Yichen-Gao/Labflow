#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
TARGET_PATH=/usr/local/bin/lab

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

cat > "${TARGET_PATH}" <<LAUNCHER
#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="${REPO_ROOT}"
export PYTHONPATH="\${REPO_ROOT}/src\${PYTHONPATH:+:\$PYTHONPATH}"
CONFIG_PATH=\${LABFLOW_CONFIG:-\${REPO_ROOT}/labflow.json}

if [[ \$# -eq 0 || "\$1" == "monitor" ]]; then
  shift \$(( \$# > 0 ? 1 : 0 ))
  exec python3 -m labflow --config "\${CONFIG_PATH}" monitor "\$@"
fi

if [[ "\$1" == "menu" ]]; then
  shift
  exec python3 -m labflow --config "\${CONFIG_PATH}" menu "\$@"
fi

exec python3 -m labflow --config "\${CONFIG_PATH}" "\$@"
LAUNCHER

chmod 755 "${TARGET_PATH}"
echo "Installed system-wide launcher at ${TARGET_PATH}"
echo "All users can now run: lab monitor"
