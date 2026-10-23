#!/usr/bin/env python3
"""Runtime smoke test: untouched Kafbat bootJar + external PKCE JAR + mock OAuth IdP."""
import base64
import hashlib
import http.cookiejar
import http.server
import json
import os
import pathlib
import re
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]
app_jars = sorted((ROOT / "api/build/libs").glob("api-*.jar"))
extension_jars = sorted((ROOT / "pkce-starter/build/libs").glob("pkce-starter-*.jar"))
assert len(app_jars) == 1, f"Expected one app JAR: {app_jars}"
assert len(extension_jars) == 1, f"Expected one external starter JAR: {extension_jars}"
app_jar = app_jars[0]
extension_jar = extension_jars[0]
import zipfile
with zipfile.ZipFile(app_jar) as archive:
    assert "org/springframework/boot/loader/launch/PropertiesLauncher.class" in archive.namelist(), (
        "Original bootJar lacks PropertiesLauncher; external loader.path approach cannot work."
    )
with zipfile.ZipFile(extension_jar) as archive:
    assert "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports" in archive.namelist()

events = {"authorize": None, "token": None, "userinfo": False}

class IdentityProvider(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("mock-idp: " + fmt % args, flush=True)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/authorize":
            args = urllib.parse.parse_qs(parsed.query)
            assert args.get("code_challenge_method") == ["S256"], args
            assert len(args.get("code_challenge", [])) == 1, args
            assert len(args.get("state", [])) == 1, args
            events["authorize"] = args
            callback = args["redirect_uri"][0]
            joiner = "&" if "?" in callback else "?"
            uri = callback + joiner + urllib.parse.urlencode({"code": "test-code", "state": args["state"][0]})
            self.send_response(302)
            self.send_header("Location", uri)
            self.end_headers()
        elif parsed.path == "/userinfo":
            events["userinfo"] = True
            payload = json.dumps({"sub": "pkce-test-user", "name": "PKCE Test User"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_error(404)

    def do_POST(self):
        assert urllib.parse.urlparse(self.path).path == "/token"
        data = self.rfile.read(int(self.headers["Content-Length"]))
        args = urllib.parse.parse_qs(data.decode())
        assert args.get("code") == ["test-code"], args
        assert events["authorize"] is not None, "Token call before authorization"
        assert len(args.get("code_verifier", [])) == 1, args
        verifier = args["code_verifier"][0]
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert expected == events["authorize"]["code_challenge"][0], "PKCE verifier mismatch"
        events["token"] = args
        payload = json.dumps({"access_token": "mock-access-token", "token_type": "Bearer", "expires_in": 3600}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

idp = http.server.ThreadingHTTPServer(("127.0.0.1", 0), IdentityProvider)
threading.Thread(target=idp.serve_forever, daemon=True).start()
idp_url = f"http://127.0.0.1:{idp.server_port}"
app_port = 18087
cmd = [
    "java", f"-Dloader.path={extension_jar.resolve()}",
    "-cp", str(app_jar.resolve()),
    "org.springframework.boot.loader.launch.PropertiesLauncher",
    "--server.port=" + str(app_port),
    "--auth.type=OAUTH2",
    "--auth.oauth2.client.test.provider=test",
    "--auth.oauth2.client.test.client-id=pkce-test",
    "--auth.oauth2.client.test.client-secret=test-secret",
    "--auth.oauth2.client.test.authorization-grant-type=authorization_code",
    "--auth.oauth2.client.test.scope=profile",
    "--auth.oauth2.client.test.authorization-uri=" + idp_url + "/authorize",
    "--auth.oauth2.client.test.token-uri=" + idp_url + "/token",
    "--auth.oauth2.client.test.user-info-uri=" + idp_url + "/userinfo",
    "--auth.oauth2.client.test.user-name-attribute=sub",
    "--auth.oauth2.client.test.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
]
print("Starting unchanged app jar:", app_jar, "with extension:", extension_jar, flush=True)
log = ROOT / "pkce-runtime.log"
with log.open("wb") as log_file:
    proc = subprocess.Popen(cmd, stdout=log_file, stderr=subprocess.STDOUT, cwd=ROOT)
    try:
        base = f"http://127.0.0.1:{app_port}"
        jar = http.cookiejar.CookieJar()
        browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        ready = False
        for _ in range(120):
            if proc.poll() is not None:
                raise AssertionError(f"Application exited {proc.returncode}")
            try:
                urllib.request.urlopen(base + "/actuator/health", timeout=1).close()
                ready = True
                break
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError):
                time.sleep(1)
        assert ready, "Application never became reachable"
        with browser.open(base + "/oauth2/authorization/test", timeout=30) as response:
            landing = response.geturl()
            status = response.status
            response.read()
        assert events["authorize"], "Authorization endpoint not reached"
        assert events["token"], "Token endpoint not reached"
        assert events["userinfo"], "Userinfo endpoint not reached: login did not finish"
        assert "/login?error" not in landing, f"OAuth2 login failure: {landing}"
        print(f"PASS: untouched Kafbat bootJar + external starter: login HTTP {status}, landing {landing}")
        print("PASS: S256 code_challenge matches code_verifier at mock token endpoint")
    except Exception:
        log_file.flush()
        print(log.read_text(errors="replace")[-14000:], flush=True)
        raise
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        idp.shutdown()
