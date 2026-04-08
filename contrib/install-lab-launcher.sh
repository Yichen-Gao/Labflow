#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
TARGET_DIR="${HOME}/.local/bin"
TARGET_PATH="${TARGET_DIR}/lab"

mkdir -p "${TARGET_DIR}"

cat > "${TARGET_PATH}" <<EOF
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
EOF

chmod +x "${TARGET_PATH}"
echo "Installed launcher at ${TARGET_PATH}"
echo "You can now run: lab monitor"
