"""Publish an explicitly selected static artifact to Pagebin over HTTPS."""

import argparse
import http.client
import io
import json
import os
import re
import secrets
import sys
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 50 * 1024 * 1024
MAX_FILES = 10_000
MAX_RESPONSE = 64 * 1024
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{1,62}[a-z0-9]\Z")
RESERVED = {"api", "static", "login", "logout", "new", "s", "health"}


class PublishError(Exception):
    """An actionable message safe to display without credentials or remote text."""


def https_url(value):
    parsed = urlsplit(value)
    if (
        not value.isascii()
        or any(char.isspace() or ord(char) < 32 for char in value)
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port == 0
        or parsed.query
        or parsed.fragment
    ):
        raise PublishError("Use an HTTPS URL without credentials, query or fragment.")
    return parsed


def slug(value):
    if not SLUG.fullmatch(value) or value in RESERVED:
        raise PublishError(
            "Use a non-reserved slug of 3-64 lowercase letters, digits or hyphens."
        )
    return value


def safe_path(path):
    name = path.name.lower()
    if (
        name.startswith((".", "id_rsa", "id_ed25519", "secrets", "credentials"))
        or name.endswith((".pem", ".key"))
        or name in {"node_modules", "__pycache__", "__unlock"}
        or "\\" in name
        or path.is_symlink()
    ):
        raise PublishError(
            "Refusing hidden, credential-like, dependency, reserved or symlink paths."
        )


def content(source):
    root = Path(source).absolute()
    if any(
        path.is_symlink() or path.name.lower().startswith(("secrets", "credentials"))
        for path in (root, *root.parents)
    ):
        raise PublishError("Refusing symlink or credential-directory components.")
    safe_path(root)
    directory = root.is_dir()
    if not directory and root.suffix.lower() not in {".html", ".htm"}:
        raise PublishError("Select an HTML file or a dedicated output directory.")
    pending, files, total = [root], {}, 0
    while pending:
        path = pending.pop()
        safe_path(path)
        if path.is_dir():
            pending.extend(path.iterdir())
            continue
        if not path.is_file():
            raise PublishError(
                "Select an existing HTML file or static-site directory of regular files."
            )
        with path.open("rb") as handle:
            data = handle.read(MAX_BYTES - total + 1)
        total += len(data)
        if total > MAX_BYTES or len(files) >= MAX_FILES:
            raise PublishError("Artifact exceeds 50 MiB uncompressed or 10,000 files.")
        files[path.relative_to(root).as_posix() if directory else path.name] = data
    html = [
        name
        for name in files
        if "/" not in name and Path(name).suffix.lower() in {".html", ".htm"}
    ]
    if not html or (directory and "index.html" not in files and len(html) != 1):
        raise PublishError("Provide index.html or exactly one top-level HTML file.")
    if not directory:
        data = files[root.name]
        if not data.decode("utf-8").strip():
            raise PublishError("HTML must contain non-whitespace UTF-8 text.")
        return "html", data
    # NOTE: buffers up to 50 MiB input plus ZIP/multipart copies; stream for larger artifacts.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return "zip", buffer.getvalue()


def multipart(fields, kind, data):
    boundary = secrets.token_hex(24)
    chunks = []
    for name, value in [*fields.items(), (kind, data)]:
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if name == "zip":
            disposition += '; filename="site.zip"'
        value = value.encode("utf-8") if isinstance(value, str) else value
        chunks.extend(
            [f"--{boundary}\r\n{disposition}\r\n\r\n".encode(), value, b"\r\n"]
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    body = b"".join(chunks)
    if len(body) > MAX_BYTES:
        raise PublishError("Encoded upload exceeds the client's 50 MiB limit.")
    return body, f"multipart/form-data; boundary={boundary}"


def publish(args):
    base = https_url(os.environ.get("PAGEBIN_URL", ""))
    if base.path not in ("", "/"):
        raise PublishError("PAGEBIN_URL must be the admin origin without a path.")
    token = os.environ.get("PAGEBIN_API_TOKEN", "")
    if (
        not token
        or not token.isascii()
        or any(ord(char) < 33 or ord(char) > 126 for char in token)
    ):
        raise PublishError(
            "Set PAGEBIN_API_TOKEN to a nonempty printable ASCII token without spaces."
        )
    if args.replace is not None and args.title is not None:
        raise PublishError("--replace preserves settings; omit --title.")
    target = slug(args.replace) if args.replace is not None else None
    fields = {}
    if target is None:
        fields = {"visibility": "open", "expires_in": "never"}
        if args.title is not None:
            if len(args.title) > 200 or any(char in args.title for char in "\0\r\n"):
                raise PublishError("Title must be one line of at most 200 characters.")
            fields["title"] = args.title
    kind, data = content(args.path)
    body, content_type = multipart(fields, kind, data)
    connection = http.client.HTTPSConnection(
        base.hostname, base.port or 443, timeout=60
    )
    try:
        # Network writes are explicit: exactly one POST or PUT, never redirects or retries.
        connection.request(
            "PUT" if target else "POST",
            f"/api/sites/{target}" if target else "/api/sites",
            body=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": content_type},
        )
        response = connection.getresponse()
        if response.status != (200 if target else 201):
            hint = {
                400: "Check HTML, filenames and metadata.",
                401: "Check the locally configured API token.",
                404: "Check the admin URL, enabled API and replacement slug.",
                409: "Slug already exists; no replacement was attempted.",
                413: "Upload exceeds the server limit.",
            }.get(response.status, "Check the server; redirects are not followed.")
            raise PublishError(
                f"HTTP {response.status}. {hint} No automatic retry was attempted."
            )
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise PublishError(
                "Oversized API response; verify publication before retrying."
            )
        site = json.loads(raw)
        if not isinstance(site, dict) or not all(
            isinstance(site.get(key), str) for key in ("url", "slug", "visibility")
        ):
            raise PublishError(
                "Unexpected API response; verify publication before retrying."
            )
        result = {key: site[key] for key in ("url", "slug", "visibility", "expires_at")}
        url = https_url(result["url"])
        if (
            result["url"] != url.geturl()
            or url.path != f"/s/{slug(result['slug'])}/"
            or url.query
            or url.fragment
            or result["visibility"] not in ("open", "password")
            or (
                result["expires_at"] is not None
                and type(result["expires_at"]) is not int
            )
            or (target is not None and result["slug"] != target)
        ):
            raise PublishError(
                "Unexpected API response; verify publication before retrying."
            )
        return result
    finally:
        connection.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "path", help="HTML file or dedicated static-site output directory"
    )
    parser.add_argument(
        "--replace",
        metavar="SLUG",
        help="replace all content at this exact slug; keep settings",
    )
    parser.add_argument("--title", help="title for a new page")
    args = parser.parse_args(argv)
    try:
        result = publish(args)
    except PublishError as error:
        print(f"pagebin: {error}", file=sys.stderr)
        return 1
    except (OSError, http.client.HTTPException):
        print(
            "pagebin: File or network failure. If a request was sent, verify publication before retrying.",
            file=sys.stderr,
        )
        return 1
    except (ValueError, KeyError, TypeError):
        # Never echo exception bodies: a remote response or local config could contain credentials.
        print(
            "pagebin: Invalid configuration, artifact or API response. Check inputs and server state before retrying.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
