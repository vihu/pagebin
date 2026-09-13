set dotenv-load := false

tw_version := "4.3.3"
tw_sha256 := "dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a"

# Generate the stylesheet embedded by Rust. No Node.js or npm is involved.
css:
    ./bin/tailwindcss -i css/tailwind-input.css -o static/app.css --minify

# Fetch the pinned Linux x64 compiler only when absent or mismatched.
tailwind:
    #!/bin/sh
    set -eu
    mkdir -p bin
    if test -f bin/tailwindcss && printf '%s  %s\n' '{{ tw_sha256 }}' bin/tailwindcss | sha256sum --check --status; then
        exit 0
    fi
    output=$(mktemp bin/tailwindcss.XXXXXX)
    curl --fail --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 180 --output "$output" \
        'https://github.com/tailwindlabs/tailwindcss/releases/download/v{{ tw_version }}/tailwindcss-linux-x64'
    printf '%s  %s\n' '{{ tw_sha256 }}' "$output" | sha256sum --check
    chmod 0755 "$output"
    mv "$output" bin/tailwindcss
