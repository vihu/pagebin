"""Offline publishing regression: run with python3 skills/pagebin/scripts/check.py."""

import io
import json
import os
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

import publish


def check():
    token = "synthetic-check-token"
    site = {
        "url": "https://view.example/s/diagram/",
        "slug": "diagram",
        "visibility": "open",
        "expires_at": None,
    }
    connection = Mock()
    response = connection.getresponse.return_value
    response.status = 201
    response.read.return_value = json.dumps(site).encode()

    def run(arguments, success=True, message=""):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = publish.main(arguments)
        assert token not in out.getvalue() + err.getvalue()
        assert (status == 0) == success, err.getvalue()
        if success:
            assert not err.getvalue()
            assert json.loads(out.getvalue()) == site
        else:
            assert not out.getvalue() and message in err.getvalue()

    def parts():
        args, kwargs = connection.request.call_args
        headers = kwargs["headers"]
        assert headers["Authorization"] == f"Bearer {token}"
        envelope = f"Content-Type: {headers['Content-Type']}\r\n\r\n".encode()
        message = BytesParser(policy=default).parsebytes(envelope + kwargs["body"])
        return args, {
            part.get_param("name", header="Content-Disposition"): part
            for part in message.iter_parts()
        }

    environment = {
        "PAGEBIN_URL": "https://admin.example:8443/",
        "PAGEBIN_API_TOKEN": token,
    }
    with (
        TemporaryDirectory() as temporary,
        patch.dict(os.environ, environment, clear=True),
        patch.object(
            publish.http.client, "HTTPSConnection", return_value=connection
        ) as connect,
    ):
        root = Path(temporary)
        html = root / "diagram ü.html"
        html.write_text("<!doctype html><h1>Architecture ü</h1>", encoding="utf-8")
        run([str(html), "--title", "Architecture ü"])
        connect.assert_called_with("admin.example", 8443, timeout=60)
        args, fields = parts()
        assert args == ("POST", "/api/sites")
        assert fields["html"].get_filename() is None
        assert fields["html"].get_payload(decode=True) == html.read_bytes()
        assert fields["title"].get_payload(decode=True).decode() == "Architecture ü"
        assert fields["visibility"].get_payload(decode=True) == b"open"
        assert fields["expires_in"].get_payload(decode=True) == b"never"
        assert "slug" not in fields

        output = root / "site"
        (output / "assets").mkdir(parents=True)
        (output / "index.html").write_bytes(html.read_bytes())
        (output / "assets" / "image ü.bin").write_bytes(b"\x00\xff\x01")
        site["visibility"], response.status = "password", 200
        response.read.return_value = json.dumps(site).encode()
        run([str(output), "--replace", "diagram"])
        args, fields = parts()
        assert args == ("PUT", "/api/sites/diagram") and set(fields) == {"zip"}
        with zipfile.ZipFile(
            io.BytesIO(fields["zip"].get_payload(decode=True))
        ) as archive:
            assert set(archive.namelist()) == {"index.html", "assets/image ü.bin"}
            assert archive.read("assets/image ü.bin") == b"\x00\xff\x01"
        connection.close.assert_called()

        connection.request.reset_mock()
        run(
            [str(html), "--replace", "diagram", "--title", "change"],
            False,
            "preserves settings",
        )
        for invalid in ("../diagram", "", "login", "https://view.example/s/diagram/"):
            run([str(html), "--replace", invalid], False, "slug")
        run([str(root / "missing.html")], False, "existing HTML")
        for name in (".env", "secrets.json", "private.key", "id_rsa", "node_modules"):
            blocked = output / name
            blocked.touch()
            run([str(output)], False, "Refusing")
            blocked.unlink()
        link = output / "linked.html"
        link.symlink_to(html)
        run([str(output)], False, "symlink")
        link.unlink()
        private = root / "secrets" / "page.html"
        private.parent.mkdir()
        private.touch()
        run([str(private)], False, "credential-directory")
        for url in (
            f"https://{token}@admin.example",
            "http://admin.example",
            "https://admin.example:0",
            "https://admin.example/path",
        ):
            with patch.dict(os.environ, {"PAGEBIN_URL": url}):
                run([str(html)], False)
        with patch.dict(os.environ, {"PAGEBIN_API_TOKEN": ""}):
            run([str(html)], False, "PAGEBIN_API_TOKEN")
        with patch.object(publish, "MAX_BYTES", 8):
            run([str(html)], False, "50 MiB")
        with patch.object(publish, "MAX_BYTES", 100):
            run([str(html)], False, "Encoded upload")
        with patch.object(publish, "MAX_FILES", 1):
            run([str(output)], False, "10,000 files")
        connection.request.assert_not_called()

        for status in (302, 401, 404, 409, 413, 500):
            response.status = status
            before = connection.request.call_count
            run([str(html)], False, f"HTTP {status}")
            assert connection.request.call_count == before + 1
        response.status = 201
        for body in (
            b"not json",
            b"[]",
            b"{}",
            json.dumps({**site, "url": None}).encode(),
            json.dumps({**site, "url": "https://view.example/s/wrong/"}).encode(),
            json.dumps({**site, "url": site["url"] + "\n"}).encode(),
        ):
            response.read.return_value = body
            run([str(html)], False)
        connection.request.side_effect = OSError(token)
        run([str(html)], False, "network failure")
    print("Publishing check passed (offline).")


if __name__ == "__main__":
    check()
