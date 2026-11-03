
#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

mkdir -p bin

found_command=false
for command_dir in cmd/*/; do
    [[ -d "$command_dir" && -f "${command_dir}main.go" ]] || continue

    found_command=true
    command_name=${command_dir%/}
    command_name=${command_name##*/}

    echo "Building ${command_name} for linux/amd64..."
    GOOS=linux GOARCH=amd64 go build -v -trimpath -ldflags "-s -w" \
        -o "bin/${command_name}" "./${command_dir%/}"
done

if [[ "$found_command" != true ]]; then
    echo "No command packages with main.go found under cmd/." >&2
    exit 1
fi

echo "Build process completed."
