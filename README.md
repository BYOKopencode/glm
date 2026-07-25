# GLM Proxy

An OpenAI-compatible `/v1/chat/completions` endpoint backed by a real browser
driving `chat.z.ai`. Playwright loads the page, Aliyun's JavaScript mints the
captcha token that the raw HTTP API refuses to work without, and the resulting
SSE stream is teed out of the page and re-emitted in OpenAI shape.

Version 2.1.0.

---

## Quick start (local)

```bash
unzip glm-proxy.zip && cd glm-proxy
chmod +x setup_local.sh verify.sh
./setup_local.sh
python3 main.py
```

In another shell:

```bash
./verify.sh
```

`setup_local.sh` installs the pip dependencies **and** `playwright install
chromium`. Skipping that second step is what produces:

```
BrowserType.launch: Executable doesn't exist at
  ~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell
```

---

## Deploy to Railway

```bash
git add -A && git commit -m "v2.1.0" && git push
```

`railway.toml` selects the Dockerfile build. Give the service **at least 1 GB
of RAM** -- Chromium will be OOM-killed below that.

Recommended variables:

```bash
railway variables set API_KEY=$(openssl rand -hex 32)
railway variables set ALLOWED_ORIGINS=https://your-frontend.example
```

### Two build modes

| | `Dockerfile` | `Dockerfile.cdp` |
|---|---|---|
| Browser | local Chromium | remote, via `BROWSER_CDP_URL` |
| Image size | ~1.8 GB | ~150 MB |
| Build time | several minutes | under a minute |
| Needs `BROWSER_CDP_URL` | no | **yes** |
| Beats datacenter-IP captcha blocks | no | yes |

To switch, point `dockerfilePath` in `railway.toml` at `Dockerfile.cdp` and set
`BROWSER_CDP_URL`.

---

## Authentication

Unset by default -- the proxy runs open. Set either variable to require a
bearer token:

```bash
API_KEY=sk-your-secret
# or several
API_KEYS=key_one,key_two
```

Enforced on `POST /v1/chat/completions` and `GET /v1/models`. `/` and `/health`
stay open so platform healthchecks pass. Comparison uses
`hmac.compare_digest`, so it is timing-safe. `X-API-Key` and `?api_key=` work
as fallbacks for clients that cannot set an `Authorization` header.

Set `REQUIRE_AUTH=1` to make the app refuse to boot without a key configured --
worth doing in production so a missing variable fails loudly instead of
silently exposing the endpoint.

---

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/` | no | version banner |
| GET | `/health` | no | never touches the browser |
| GET | `/v1/models` | yes | lists the four GLM models |
| POST | `/v1/chat/completions` | yes | `stream: true` or `false` |

Models: `glm-4.7`, `glm-5.2`, `glm-z1-flash`, `glm-z1-air`.

---

## Configuration

See `.env.example` for the full annotated list. The ones that matter most:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8000` | injected by Railway |
| `DEBUG` | `0` | verbose browser logging |
| `API_KEY` / `API_KEYS` | unset | bearer auth |
| `ALLOWED_ORIGINS` | `*` | CORS allowlist |
| `PROXY_SERVER` | unset | residential proxy |
| `BROWSER_CDP_URL` | unset | remote browser |
| `THINK_MODE` | `reasoning` | `reasoning`, `hide`, or `raw` |
| `FIRST_CHUNK_TIMEOUT_S` | `60` | cold-start allowance |

A credentialed browser request (one carrying `Authorization`) is refused while
`ALLOWED_ORIGINS` is `*` -- that is a CORS rule, not a bug. Name your origin
explicitly once auth is on.

---

## Integrity check

This file has been corrupted by copy-paste more than once. `main.py` can
validate itself with no dependencies installed:

```bash
python3 main.py --selfcheck
```

Expected: `SELFCHECK OK: 1460 lines, pure ascii, no markdown damage.`

It scans for zero-width and non-ASCII characters, for markdown damage such as
`def **init**` or `launch(launch_kwargs)`, and for required tokens that must
survive intact. Both Dockerfiles run it at build time, so a mangled file fails
the build rather than the first request.

**Always transfer this project as a zip.** Pasting Python into a terminal
through a markdown renderer is what injected the U+200B characters.

---

## Troubleshooting

**`405 Method Not Allowed` from a browser client.** The CORS preflight is
hitting a server without CORS middleware -- an old build. Confirm with
`verify.sh` check 3.

**`SyntaxError: invalid non-printable character U+200B`.** The file was
pasted, not unzipped. Re-extract from the zip, or strip in place:

```python
import pathlib
p = pathlib.Path('main.py')
s = p.read_text('utf-8')
clean = s.translate(dict.fromkeys(map(ord, '\u200b\u200c\u200d\ufeff\u2060\u180e'), None)).replace('\u00a0', ' ')
p.write_text(clean, 'utf-8')
```

**`browser_unavailable`.** Run `python3 -m playwright install chromium`. If the
binary exists but will not start, `sudo python3 -m playwright install-deps
chromium`.

**`captcha_challenge` or a timeout with `captcha_dom=[]`.** Aliyun flagged the
IP. Set `PROXY_SERVER` or `BROWSER_CDP_URL`.

**Empty completions.** Run with `DEBUG=1` and watch for
`warning: expose_function failed`. On managed remote browsers the in-page hook
cannot install and the code falls back to buffered capture at the Playwright
layer -- slower, but it should still return text.

---

## Known gaps

- `usage` is always zero. No token counting is implemented, and
  `stream_options: {"include_usage": true}` is accepted but ignored.
- One conversation at a time. `send_lock` serialises requests; concurrent
  callers queue.
- No conversation persistence. Every request starts a new chat and replays the
  flattened message history as a single prompt.
