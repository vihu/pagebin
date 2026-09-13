---
name: pagebin
description: Publish generated HTML mockups, diagrams, architecture documents, or static-site output to Pagebin and return the shareable link. Use only when the user explicitly asks to publish to Pagebin or replace an existing Pagebin page, not merely to generate an artifact.
compatibility: Python 3.10+ with TLS and zlib support. Requires HTTPS access to Pagebin and locally configured PAGEBIN_URL and PAGEBIN_API_TOKEN environment variables.
---

# Publish to Pagebin

Use the bundled `scripts/publish.py`. No third-party Python packages are required.
Resolve script paths relative to this file, not the project being worked on.

## Workflow

1. Select the exact HTML file or dedicated static-site output directory requested by the user. Generate or review it with other skills as needed. Use relative asset links: Pagebin serves sites under `/s/{slug}/`, not `/`. Never select the whole codebase or include secrets in generated content.
2. Treat an explicit publishing request as authorization to upload that artifact. Create an open page by default, with a generated slug and no expiry. Anyone with its link can view it. Password protection can be added manually in Pagebin.
3. Run the uploader once. Use `--replace SLUG` only when the user explicitly requests replacement of that page. Take the exact slug from the user's target or an earlier successful result, never infer it from a title. Replacement removes all old content, including omitted assets, but preserves the URL, title, password protection, and expiry.
4. On exit code `0`, return the JSON `url` verbatim as a clickable link. State `visibility` and `expires_at` (`null` means no expiry; otherwise Unix seconds). Retain the returned `slug` in the conversation for explicit updates. Do not claim the page was visually checked unless it was.

If a replacement URL belongs to a different or unknown instance, ask before targeting its slug.
Set `SKILL_DIR` to the absolute directory containing this file before these commands.
Upload commands make network writes to the configured instance.

```sh
python3 "$SKILL_DIR/scripts/publish.py" /absolute/path/mockup.html --title "Checkout mockup"
python3 "$SKILL_DIR/scripts/publish.py" /absolute/path/site-output/
python3 "$SKILL_DIR/scripts/publish.py" /absolute/path/site-output/ --replace exact-existing-slug
```

Single HTML files must be UTF-8 (`.html` or `.htm`).
Directories are zipped at their root, preserving nested assets and binary files.
Include `index.html` or exactly one top-level HTML file as the entry point.
`--title` is create-only. Replacement sends content only and never resets access settings.

## Install once

Run from the Pagebin repository root. These links make the same skill available from any codebase.
If a `pagebin` entry already exists, inspect it rather than overwriting it.

```sh
mkdir -p "$HOME/.agents/skills" "$HOME/.claude/skills"
ln -s "$PWD/skills/pagebin" "$HOME/.agents/skills/"
ln -s "$PWD/skills/pagebin" "$HOME/.claude/skills/"
```

Start a new agent session after installation.
Pi discovers `~/.agents/skills/pagebin`; Claude Code discovers `~/.claude/skills/pagebin`.
Explicit invocation: `/skill:pagebin` in pi or `/pagebin` in Claude Code.

## Configure locally

The operator must first enable `PAGEBIN_API_TOKEN` on the server.
Use a nonempty printable ASCII token without spaces.
`PAGEBIN_URL` is the HTTPS **admin origin**, not the viewer host or `/api/sites` endpoint.

Run in a local Bash terminal, not an agent tool call. Replace only the example URL.
Start pi or Claude Code from that shell so it inherits the variables.

```bash
export PAGEBIN_URL=https://pages.example.com
read -rsp 'Pagebin API token: ' PAGEBIN_API_TOKEN; printf '\n'
export PAGEBIN_API_TOKEN
```

Never request a token in chat, inspect secret files, dump the environment, or print request headers.
The script reads inherited variables directly. It does not load `.env` or store credentials.
Optional: use an existing credential manager to inject these variables for persistent setup.
The API token controls all sites, including deletion. This skill is not a sandbox or a scoped credential.

## Limits and failures

- The script refuses hidden paths, credential-like filenames, dependency directories, symlinks, and non-regular files. Do not bypass these checks; select a clean output directory. Name checks do not detect secrets embedded in ordinary HTML or assets.
- Limits: 50 MiB uncompressed input and encoded upload, 10,000 files. The server may impose a lower limit. Uploads are buffered in memory; larger artifacts need a streaming client.
- HTTPS certificate checks stay enabled. No redirects, automatic retries, SSH, password changes, or deletion. Socket timeout: 60 seconds.
- Nonzero exit means no success link. Report the error without inventing a URL. A timeout, server error, or malformed response can follow a completed upload: have the user check Pagebin before retrying. Never switch from create to replace after a conflict.

Offline check: `python3 -B skills/pagebin/scripts/check.py` from the Pagebin repository root.
