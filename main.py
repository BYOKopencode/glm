"""
GLM (chat.z.ai) -> OpenAI-compatible proxy, Playwright/browser-backed.

WHY A BROWSER:
chat.z.ai's guest flow now requires an Alibaba Cloud (Aliyun) CAPTCHA token
(`captcha_verify_param`) on every /api/v2/chat/completions request. That token
can only be minted by Aliyun's JS running in a real browser, so a pure-Python
HMAC signature is not enough (the backend returns FRONTEND_CAPTCHA_REQUIRED /
captcha_error_type=missing_param without it).

APPROACH:
We drive a real headless Chromium via Playwright. The site itself performs
guest auth, computes the X-Signature, solves/passes the captcha, and issues
the real fetch(). We monkey-patch window.fetch (via an init script) to TEE the
streaming SSE response body out to Python through an exposed function, then we
re-emit those chunks in OpenAI's /v1/chat/completions SSE shape.

To trigger a send we type the (flattened) prompt into the composer and press
Enter -- the site does everything else.

KNOWN-FRAGILE POINTS (expect to tune on Railway):
* Datacenter IPs are high-risk for Aliyun; a residential PROXY_SERVER helps.
* UI selectors (composer) can change -> override via COMPOSER_SELECTORS env.
* Model switching is best-effort; if it fails the site's default model
  answers. Watch the logs.
* If Aliyun shows an interactive slider we cannot solve it; you'll get a clear
  captcha_challenge error.

ENV VARS:
PORT                      (Railway sets this) default 8000
DEBUG=1                   verbose logging
HEADLESS=0                run headed (local debugging only)
PROXY_SERVER              e.g. http://user:pass@host:port  (recommended on Railway)
NAV_TIMEOUT_MS            page nav / ready timeout (default 60000)
FIRST_CHUNK_TIMEOUT_S     wait for first SSE chunk after send (default 60)
IDLE_TIMEOUT_S            max gap between chunks (default 120)
COMPOSER_SELECTORS        comma-separated CSS selectors for the input box
SET_MODEL                 "1" (default) attempt best-effort model selection

AUTH / CORS:
API_KEY                   if set, callers must send `Authorization: Bearer <key>`
API_KEYS                  optional comma-separated list of accepted keys
REQUIRE_AUTH              "1" to hard-fail startup when no key is configured
ALLOWED_ORIGINS           comma-separated CORS origins (default "*")

INTEGRITY:
Run `python3 main.py --selfcheck` to verify the file was not mangled in
transit (markdown renderers eat underscores and asterisks).
"""

import asyncio
import hmac
import json
import os
import sys
import time
import uuid
from typing import Any, Optional, Union


# ---------------------------------------------------------------------------
# Integrity self-check
#
# Deliberately placed BEFORE the third-party imports so that
# `python3 main.py --selfcheck` works on any machine, with or without
# fastapi/playwright installed. Markdown renderers eat underscores and
# asterisks; this catches that damage before it reaches a container.
# ---------------------------------------------------------------------------

CORRUPTION_MARKERS = [
    ("def " + "**init**", "dunder __init__ was turned into markdown bold"),
    ("**" + "name" + "**", "dunder __name__ was turned into markdown bold"),
    ("chromium.launch(" + "launch_kwargs)",
     "launch() lost its argument unpacking"),
    ("catch (" + ") {", "a JS catch clause lost its parameter"),
    ("](" + "http", "a URL was turned into a markdown link"),
    ("\\" + "{", "markdown-escaped braces are present"),
    ("\\" + "[", "markdown-escaped brackets are present"),
    ("\t", "tab characters are present"),
]

# NOTE: every marker above is written as a concatenation on purpose. A literal
# would match itself when selfcheck() reads this file, so the check would
# always fail.

REQUIRED_TOKENS = [
    "chromium.launch(" + "**" + "launch_kwargs)",
    "def " + "__init__" + "(self):",
    "CORSMiddleware,",
    "hmac.compare_digest",
]

INVISIBLE_CODEPOINTS = (0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x00A0, 0x180E)


def selfcheck() -> int:
    """Return 0 when this file is intact, 1 when it looks mangled."""
    import pathlib

    src = pathlib.Path(__file__).read_text("utf-8")
    problems = []

    invisible = [c for c in src if ord(c) in INVISIBLE_CODEPOINTS]
    if invisible:
        codes = sorted(set("U+%04X" % ord(c) for c in invisible))
        problems.append("invisible unicode (%d chars: %s)"
                        % (len(invisible), ", ".join(codes)))

    non_ascii = sorted(set(c for c in src if ord(c) > 126))
    if non_ascii:
        problems.append("non-ascii characters: "
                        + ", ".join("U+%04X" % ord(c) for c in non_ascii[:10]))

    for marker, description in CORRUPTION_MARKERS:
        if marker in src:
            problems.append(description)

    for token in REQUIRED_TOKENS:
        if token not in src:
            problems.append("expected code is missing: " + token)

    if not src.endswith("\n"):
        problems.append("missing trailing newline")

    if problems:
        print("SELFCHECK FAILED - do not deploy this file:")
        for p in problems:
            print("  - " + p)
        print("\nThis file was almost certainly copy-pasted through a")
        print("markdown renderer. Transfer it with git, scp, or base64.")
        return 1

    print("SELFCHECK OK: %d lines, pure ascii, no markdown damage."
          % src.count("\n"))
    return 0


if __name__ == "__main__" and "--selfcheck" in sys.argv:
    raise SystemExit(selfcheck())


from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

from playwright.async_api import async_playwright, Page, BrowserContext

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CHAT_Z_BASE = "https://chat.z.ai"
HOMEPAGE_URL = CHAT_Z_BASE + "/"

DEBUG = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
HEADLESS = os.environ.get("HEADLESS", "1").lower() not in ("0", "false", "no")
PROXY_SERVER = os.environ.get("PROXY_SERVER", "").strip()
# Remote managed browser (e.g. Bright Data Scraping Browser) CDP endpoint.
# When set, CAPTCHA solving + residential IP rotation happen on their side and
# we connect Playwright to it instead of launching local Chromium.
BROWSER_CDP_URL = os.environ.get("BROWSER_CDP_URL", "").strip()
NAV_TIMEOUT_MS = int(os.environ.get("NAV_TIMEOUT_MS", "60000"))
FIRST_CHUNK_TIMEOUT_S = float(os.environ.get("FIRST_CHUNK_TIMEOUT_S", "60"))
IDLE_TIMEOUT_S = float(os.environ.get("IDLE_TIMEOUT_S", "120"))
SET_MODEL = os.environ.get("SET_MODEL", "1").lower() not in ("0", "false", "no")
# How to handle GLM's chain-of-thought (streamed with phase == "thinking"):
#   reasoning -> put it in delta.reasoning_content (default; keeps content
#                clean for coding tools, thinking still available separately)
#   hide      -> drop thinking entirely; only the final answer is returned
#   raw       -> keep thinking inline in content (original behaviour)
THINK_MODE = os.environ.get("THINK_MODE", "reasoning").strip().lower()
# Reuse ONE Bright Data session across rapid back-to-back requests. Kept well
# under Bright Data's 5-min idle and 60-min max caps, and always on ONE domain.
# 0 = always fresh. This only saves startup latency; conversation memory does
# NOT depend on it -- the client resends the full history every request.
SESSION_TTL_S = float(os.environ.get("SESSION_TTL_S", "120"))
SESSION_MAX_AGE_S = float(os.environ.get("SESSION_MAX_AGE_S", "3000"))


# ---- Auth -----------------------------------------------------------------

def load_api_keys() -> set:
    """Accept either a single API_KEY or a comma-separated API_KEYS list."""
    keys = set()
    single = os.environ.get("API_KEY", "").strip()
    if single:
        keys.add(single)
    multi = os.environ.get("API_KEYS", "").strip()
    for k in multi.split(","):
        k = k.strip()
        if k:
            keys.add(k)
    return keys


API_KEYS = load_api_keys()
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "").lower() in ("1", "true", "yes")

ORIGINS_ENV = os.environ.get("ALLOWED_ORIGINS", "*").strip()
ALLOWED_ORIGINS = [o.strip() for o in ORIGINS_ENV.split(",") if o.strip()]
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = ["*"]

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

FALLBACK_COMPOSER_SELECTORS = [
    "textarea#chat-input",
    "textarea[placeholder]",
    "div[contenteditable='true']",
    ".ProseMirror",
    "textarea",
]
COMPOSER_ENV = os.environ.get("COMPOSER_SELECTORS", "").strip()
COMPOSER_SELECTORS = [s.strip() for s in COMPOSER_ENV.split(",") if s.strip()]
if not COMPOSER_SELECTORS:
    COMPOSER_SELECTORS = FALLBACK_COMPOSER_SELECTORS

MODELS = [
    {"id": "glm-4.7", "object": "model", "created": 1735689600, "owned_by": "z.ai"},
    {"id": "glm-5.2", "object": "model", "created": 1743465600, "owned_by": "z.ai"},
    {"id": "glm-z1-flash", "object": "model", "created": 1743465600, "owned_by": "z.ai"},
    {"id": "glm-z1-air", "object": "model", "created": 1743465600, "owned_by": "z.ai"},
]
VALID_MODELS = set(m["id"] for m in MODELS)


def log(*a):
    if DEBUG:
        print("[glm]", *a, flush=True)


# ---------------------------------------------------------------------------
# Init script injected into every page BEFORE site JS runs.
#   1) light stealth
#   2) tee /chat/completions response bodies out to Python
# ---------------------------------------------------------------------------

INIT_SCRIPT = r"""
(function () {
  try { Object.defineProperty(navigator, 'webdriver', { get: function () { return undefined; } }); } catch (e) {}
  try { if (!window.chrome) { window.chrome = { runtime: {} }; } } catch (e) {}

  // Tee the /chat/completions stream regardless of transport (fetch, XHR, or
  // EventSource). The site's URL carries query params, so it may not be fetch.
  var MATCH = function (u) { return (typeof u === 'string' && u.indexOf('/chat/completions') !== -1); };
  var dbg = function (m) { try { console.log('[glmhook] ' + m); } catch (e) {} };
  var push = function (t) { if (t && window.glmChunkSink) { try { window.glmChunkSink(t); } catch (e) {} } };
  var done = function () { if (window.glmDoneSink) { try { window.glmDoneSink(); } catch (e) {} } };
  var fail = function (e) { if (window.glmErrorSink) { try { window.glmErrorSink(String(e)); } catch (e2) {} } };

  // 1) fetch (streaming ReadableStream)
  try {
    var origFetch = window.fetch;
    window.fetch = function () {
      var args = arguments;
      var url = '';
      try {
        var a0 = args[0];
        url = (a0 && a0.url) ? a0.url : (typeof a0 === 'string' ? a0 : '');
      } catch (e) {}
      var self = this;
      return origFetch.apply(self, args).then(function (resp) {
        try {
          if (MATCH(url) && resp && resp.body) {
            dbg('fetch ' + url);
            var clone = resp.clone();
            (function () {
              var reader = clone.body.getReader();
              var dec = new TextDecoder();
              var pump = function () {
                return reader.read().then(function (r) {
                  if (r.done) { done(); return; }
                  push(dec.decode(r.value, { stream: true }));
                  return pump();
                });
              };
              pump().catch(function (e) { fail(e); done(); });
            })();
          }
        } catch (e) {}
        return resp;
      });
    };
  } catch (e) {}

  // 2) XMLHttpRequest (progressive responseText)
  try {
    var OpenOrig = window.XMLHttpRequest.prototype.open;
    var SendOrig = window.XMLHttpRequest.prototype.send;
    window.XMLHttpRequest.prototype.open = function (m, u) {
      try { this.glmTargetUrl = u; } catch (e) {}
      return OpenOrig.apply(this, arguments);
    };
    window.XMLHttpRequest.prototype.send = function () {
      var xhr = this;
      try {
        if (MATCH(xhr.glmTargetUrl)) {
          dbg('xhr ' + xhr.glmTargetUrl);
          var last = 0;
          var drain = function () {
            try {
              var f = xhr.responseText || '';
              if (f.length > last) { push(f.slice(last)); last = f.length; }
            } catch (e) {}
          };
          xhr.addEventListener('progress', drain);
          xhr.addEventListener('readystatechange', function () {
            if (xhr.readyState === 3 || xhr.readyState === 4) { drain(); }
          });
          xhr.addEventListener('loadend', function () { drain(); done(); });
          xhr.addEventListener('error', function () { fail('xhr error'); });
        }
      } catch (e) {}
      return SendOrig.apply(this, arguments);
    };
  } catch (e) {}

  // 3) EventSource (SSE over GET)
  try {
    var OrigES = window.EventSource;
    if (OrigES) {
      var Wrapped = function (url, cfg) {
        var es = new OrigES(url, cfg);
        try {
          if (MATCH(url)) {
            dbg('eventsource ' + url);
            es.addEventListener('message', function (ev) { push('data: ' + ev.data + '\n\n'); });
            es.addEventListener('done', function () { done(); });
          }
        } catch (e) {}
        return es;
      };
      Wrapped.prototype = OrigES.prototype;
      try {
        Wrapped.CONNECTING = OrigES.CONNECTING;
        Wrapped.OPEN = OrigES.OPEN;
        Wrapped.CLOSED = OrigES.CLOSED;
      } catch (e) {}
      window.EventSource = Wrapped;
    }
  } catch (e) {}
})();
"""


# ---------------------------------------------------------------------------
# OpenAI-compatible request model
# ---------------------------------------------------------------------------

# Real OpenAI clients (Cursor, Cline, Continue, the openai SDK) send content as
# null on tool-call turns, or as a list of content parts. A strict str type
# rejected those with a 400 that looked like a proxy bug.
class Message(BaseModel):
    role: str
    content: Optional[Union[str, list, dict]] = None

    class Config:
        extra = "allow"


def content_to_text(content: Any) -> str:
    """Flatten OpenAI content (str, None, list-of-parts, dict) into text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return str(content.get("text") or content.get("content") or "")
    if isinstance(content, list):
        out = []
        for part in content:
            if isinstance(part, str):
                out.append(part)
            elif isinstance(part, dict):
                ptype = part.get("type")
                if ptype in (None, "text", "input_text", "output_text"):
                    t = part.get("text")
                    if t:
                        out.append(str(t))
                elif ptype in ("image_url", "input_image", "image"):
                    # The browser composer is text-only; note the omission.
                    out.append("[image omitted]")
        return "\n".join(out)
    return str(content)


class ChatCompletionRequest(BaseModel):
    model: str
    messages: list
    stream: bool = True

    class Config:
        extra = "allow"


def normalize_messages(messages) -> list:
    """Return a list of (role, text) tuples with empty turns removed."""
    pairs = []
    for m in messages:
        if isinstance(m, Message):
            role, content = m.role, m.content
        elif isinstance(m, dict):
            role, content = m.get("role", "user"), m.get("content")
        else:
            role, content = getattr(m, "role", "user"), getattr(m, "content", None)
        text = content_to_text(content)
        if text.strip():
            pairs.append((str(role).lower(), text))
    return pairs


def flatten_messages(messages) -> str:
    """Collapse an OpenAI-style conversation into a single prompt to type.

    The browser UI is single-turn from our perspective (we start a fresh chat
    each request), so we linearize history with role labels. If there is only a
    single user turn we send it verbatim.
    """
    pairs = normalize_messages(messages)
    if not pairs:
        return ""

    user_turns = [c for r, c in pairs if r == "user"]
    simple = (
        len(pairs) == 1
        or (
            len(user_turns) == 1
            and pairs[-1][0] == "user"
            and all(r in ("user", "system") for r, _ in pairs)
        )
    )
    if simple:
        sys_text = "\n".join(c for r, c in pairs if r == "system").strip()
        usr = user_turns[-1] if user_turns else pairs[-1][1]
        if sys_text:
            return (sys_text + "\n\n" + usr).strip()
        return usr.strip()

    parts = []
    for role, text in pairs:
        if role == "system":
            parts.append("[System]\n" + text)
        elif role == "assistant":
            parts.append("[Assistant]\n" + text)
        else:
            parts.append("[User]\n" + text)
    parts.append("[Assistant]")
    return "\n\n".join(parts).strip()


# ---------------------------------------------------------------------------
# SSE chunk parsing (raw upstream line -> normalized delta)
# ---------------------------------------------------------------------------

def process_chunk(line: str) -> Optional[dict]:
    if line.startswith("data: "):
        data_str = line[len("data: "):]
    elif line.startswith("data:"):
        data_str = line[len("data:"):]
    else:
        return None

    data_str = data_str.strip()
    if data_str == "[DONE]":
        return {"type": "done"}

    try:
        chunk = json.loads(data_str)
    except json.JSONDecodeError:
        return None

    data = chunk.get("data", chunk)
    if not isinstance(data, dict):
        return None

    # Spelled out explicitly: the original one-liner relied on `or` binding
    # tighter than the ternary, which was not what the layout implied.
    err = data.get("error")
    inner = data.get("data")
    if not err and isinstance(inner, dict):
        err = inner.get("error")
    if isinstance(err, dict) and err:
        return {"type": "upstream_error", "error": err}

    phase = data.get("phase", "")
    done = data.get("done", False)
    delta_content = data.get("delta_content") or data.get("delta") or ""
    delta_reasoning = (
        data.get("delta_reasoning_content") or data.get("reasoning_content") or ""
    )
    edit_content = data.get("edit_content") or ""

    if delta_content or delta_reasoning or edit_content:
        return {
            "type": "delta",
            "content": delta_content or "",
            "reasoning_content": delta_reasoning or "",
            "edit_content": edit_content or "",
            "phase": phase,
        }
    if done:
        return {"type": "done"}
    return None


# ---------------------------------------------------------------------------
# Browser manager (one send at a time)
# ---------------------------------------------------------------------------

class BrowserManager(object):
    def __init__(self):
        self.pw = None
        self.browser = None
        self.context = None
        self.page = None
        self.ready = False
        self.start_lock = asyncio.Lock()
        self.send_lock = asyncio.Lock()
        self.queue = None
        self.loop = None
        # Reusable Bright Data CDP session kept alive within SESSION_TTL_S.
        self.cdp_session = None
        self.cdp_opened_at = 0.0
        self.cdp_last_used = 0.0
        self.cdp_model = None
        # True once an in-page hook delivers a chunk, so the Playwright-layer
        # body capture knows not to double-emit.
        self.got_inpage_chunk = False
        # Guarantees the HTTP-body fallback fires at most once per request.
        self.fallback_emitted = False

    @property
    def is_ready(self) -> bool:
        return self.ready

    # -- callbacks exposed to page JS --

    def on_chunk(self, text: str):
        self.got_inpage_chunk = True
        if self.queue is not None:
            self.queue.put_nowait(("chunk", text))

    def on_done(self):
        if self.queue is not None:
            self.queue.put_nowait(("done", None))

    def on_error(self, msg: str):
        if self.queue is not None:
            self.queue.put_nowait(("error", msg))

    async def expose_sinks(self, context):
        try:
            await context.expose_function("glmChunkSink", self.on_chunk)
            await context.expose_function("glmDoneSink", self.on_done)
            await context.expose_function("glmErrorSink", self.on_error)
        except Exception as e:
            # Some managed browsers restrict bindings. If this fails on a
            # remote browser, prefer using it as PROXY_SERVER instead.
            log("warning: expose_function failed (remote browser?):", e)

    async def start(self):
        async with self.start_lock:
            if self.ready:
                return
            self.loop = asyncio.get_running_loop()
            self.pw = await async_playwright().start()

            if BROWSER_CDP_URL:
                # Bright Data limits each session to ONE domain and to short
                # lifetimes, so we do not hold a persistent remote browser.
                log("CDP mode: sessions are opened per request")
                self.ready = True
                return

            launch_kwargs = {
                "headless": HEADLESS,
                "args": [
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-gpu",
                ],
            }
            if PROXY_SERVER:
                launch_kwargs["proxy"] = {"server": PROXY_SERVER}
                log("using proxy", PROXY_SERVER)

            # launch() is keyword-only; passing the dict positionally raises
            # TypeError and breaks local-Chromium mode entirely.
            self.browser = await self.pw.chromium.launch(**launch_kwargs)
            self.context = await self.browser.new_context(
                user_agent=USER_AGENT,
                locale="en-US",
                viewport={"width": 1536, "height": 864},
            )
            self.context.set_default_timeout(NAV_TIMEOUT_MS)
            await self.context.add_init_script(INIT_SCRIPT)
            await self.expose_sinks(self.context)

            pages = self.context.pages
            self.page = pages[0] if pages else await self.context.new_page()
            self.attach_diagnostics(self.page)
            self.attach_capture(self.page)
            await self.warm_up()
            self.ready = True
            log("browser ready")

    async def warm_up(self):
        if self.page is None:
            return
        # wait_until="commit" fires as soon as navigation commits, so a slow
        # sub-resource cannot make goto hang for the full timeout.
        try:
            await self.page.goto(
                HOMEPAGE_URL, wait_until="commit", timeout=NAV_TIMEOUT_MS
            )
        except Exception as e:
            log("warm_up goto slow (continuing):", str(e)[:160])
        try:
            await self.page.wait_for_function(
                "function () { return !!(localStorage.getItem('token') "
                "|| localStorage.getItem('access_token')); }",
                timeout=NAV_TIMEOUT_MS,
            )
            log("guest token present")
        except Exception:
            log("warning: no guest token detected in localStorage after load")

    async def new_chat(self):
        """Start a fresh conversation so history from prior requests is gone."""
        if self.page is None:
            return
        try:
            await self.page.goto(
                HOMEPAGE_URL, wait_until="commit", timeout=NAV_TIMEOUT_MS
            )
        except Exception as e:
            log("new_chat goto slow (continuing):", str(e)[:160])
        await asyncio.sleep(1.0)

    def model_init_js(self, model: str) -> str:
        """Best-effort model selection persisted in localStorage."""
        return (
            "(function () { try {"
            "  var m = " + json.dumps(model) + ";"
            "  try { localStorage.setItem('selectedModels', JSON.stringify([m])); } catch (e) {}"
            "  try { localStorage.setItem('models', JSON.stringify([m])); } catch (e) {}"
            "  try { var s = JSON.parse(localStorage.getItem('settings') || '{}');"
            "        s.models = [m];"
            "        localStorage.setItem('settings', JSON.stringify(s)); } catch (e) {}"
            "} catch (e) {} })();"
        )

    async def try_select_model(self, model: str):
        if not SET_MODEL or self.page is None:
            return
        try:
            await self.page.evaluate(self.model_init_js(model))
            log("set model localStorage ->", model)
        except Exception as e:
            log("model select failed:", e)

    async def find_composer(self):
        if self.page is None:
            return None, None
        for sel in COMPOSER_SELECTORS:
            try:
                el = await self.page.wait_for_selector(
                    sel, timeout=4000, state="visible"
                )
                if el:
                    log("composer selector matched:", sel)
                    return el, sel
            except Exception:
                continue
        return None, None

    def attach_diagnostics(self, page):
        """Log browser-side network/console activity (DEBUG only)."""
        if not DEBUG:
            return

        def on_response(resp):
            try:
                u = resp.url
                low = u.lower()
                if "/chat/completions" in u or "/api/v2/" in u or "captcha" in low:
                    log("[net]", resp.status, u[:140])
            except Exception:
                pass

        def on_console(msg):
            try:
                t = msg.text
                if not t:
                    return
                low = t.lower()
                if ("glmhook" in low or "captcha" in low
                        or "error" in low or "fail" in low):
                    log("[console]", t[:300])
            except Exception:
                pass

        def on_pageerror(exc):
            log("[pageerror]", str(exc)[:300])

        def on_requestfailed(req):
            try:
                if "/chat/completions" in req.url or "captcha" in req.url.lower():
                    log("[net-failed]", req.url[:140], req.failure)
            except Exception:
                pass

        page.on("response", on_response)
        page.on("console", on_console)
        page.on("pageerror", on_pageerror)
        page.on("requestfailed", on_requestfailed)

    def attach_capture(self, page):
        """Transport-agnostic capture at the Playwright layer, used as a
        fallback when the in-page JS hooks cannot see the stream."""

        def on_resp(resp):
            try:
                if "/chat/completions" in resp.url:
                    asyncio.ensure_future(self.capture_body(resp))
            except Exception:
                pass

        page.on("response", on_resp)

        def on_ws(ws):
            try:
                log("[ws] open", str(ws.url)[:120])
            except Exception:
                pass

            def on_frame(payload):
                try:
                    if isinstance(payload, (bytes, bytearray)):
                        s = "<binary %d bytes>" % len(payload)
                    else:
                        s = str(payload)
                    low = s.lower()
                    if (DEBUG or "completion" in low or "content" in low
                            or "delta" in low):
                        log("[ws-recv]", s[:400])
                except Exception:
                    pass

            try:
                ws.on("framereceived", on_frame)
            except Exception:
                pass

        page.on("websocket", on_ws)

    async def capture_body(self, resp):
        """Read the full /chat/completions HTTP body. Only used when no in-page
        chunk was captured."""
        try:
            body = await resp.text()
        except Exception as e:
            log("[capture] body unavailable:", str(e)[:200])
            return
        log("[capture] /chat/completions body len=", len(body))
        if DEBUG:
            log("[capture-head]", repr(body[:400]))
        # Checking got_inpage_chunk exactly once (at the moment the HTTP
        # response resolved) raced the in-page hook and could duplicate the
        # whole answer. Yield to the loop, re-check, and latch.
        await asyncio.sleep(0.75)
        if self.got_inpage_chunk or self.fallback_emitted:
            return
        if self.queue is not None and body:
            self.fallback_emitted = True
            log("[capture] using HTTP body fallback")
            self.queue.put_nowait(("chunk", body))
            self.queue.put_nowait(("done", None))

    async def dump_state(self, tag: str):
        """Save a screenshot plus basic page info so we can see what blocked us."""
        if self.page is None:
            return
        try:
            path = "/tmp/glm-" + tag + ".png"
            await self.page.screenshot(path=path, full_page=True)
            title = await self.page.title()
            log("state dump ->", path, "| url=", self.page.url, "| title=", title)
        except Exception as e:
            log("state dump failed:", e)

    async def detect_captcha(self):
        """Return matched captcha DOM descriptors with visibility, or [].

        Visibility matters: the site keeps an idle hidden Aliyun container in
        the DOM, which is NOT an active challenge.
        """
        if self.page is None:
            return []
        script = r"""
        (function () {
          var vis = function (el) {
            if (!el) { return false; }
            var r = el.getBoundingClientRect();
            var s = getComputedStyle(el);
            return r.width > 2 && r.height > 2 &&
                   s.visibility !== 'hidden' && s.display !== 'none';
          };
          var out = [];
          var frames = document.querySelectorAll('iframe');
          for (var i = 0; i < frames.length; i++) {
            var f = frames[i];
            var src = f.src || '';
            if (/captcha|aliyun|nocaptcha|x5sec|geetest/i.test(src)) {
              out.push('iframe:' + src.slice(0, 60) + (vis(f) ? ' [visible]' : ' [hidden]'));
            }
          }
          var sels = ['[id*=captcha]', '[class*=captcha]', '.nc_wrapper',
                      '#nc_1_wrapper', '.geetest_panel', '[class*=aliyun]',
                      '[class*=nc_]'];
          for (var j = 0; j < sels.length; j++) {
            var el = document.querySelector(sels[j]);
            if (el) {
              out.push('el:' + sels[j] + (vis(el) ? ' [visible]' : ' [hidden]'));
            }
          }
          return out;
        })();
        """
        try:
            info = await self.page.evaluate(script)
            return info or []
        except Exception:
            return []

    async def open_cdp_session(self, model: str):
        """Open a fresh Bright Data Scraping Browser session for one request."""
        log("opening fresh CDP session")
        browser = await self.pw.chromium.connect_over_cdp(
            BROWSER_CDP_URL, timeout=NAV_TIMEOUT_MS
        )
        if browser.contexts:
            context = browser.contexts[0]
        else:
            context = await browser.new_context()
        context.set_default_timeout(NAV_TIMEOUT_MS)
        await context.add_init_script(INIT_SCRIPT)
        # Apply the model selection BEFORE the first navigation so the app
        # reads it on load, avoiding a second navigation.
        if SET_MODEL:
            await context.add_init_script(self.model_init_js(model))
            log("model init script set ->", model)
        await self.expose_sinks(context)
        pages = context.pages
        page = pages[0] if pages else await context.new_page()
        self.attach_diagnostics(page)
        self.attach_capture(page)
        return (browser, context, page)

    async def close_session(self, session):
        """Disconnect a CDP session promptly to free the domain/time budget."""
        browser, context, page = session
        try:
            await context.close()
        except Exception:
            pass
        try:
            await browser.close()
        except Exception:
            pass

    async def acquire_cdp_session(self, model: str):
        """Return a live Bright Data session for this request.

        Reuses the existing session when it is still within the TTL and age
        budget, otherwise opens a fresh one. Reuse only ever resets to a new
        chat on the SAME domain, so the one-domain limit is never crossed.
        """
        now = time.time()
        session = self.cdp_session
        reused = False

        if session is not None:
            if SESSION_TTL_S <= 0:
                await self.close_session(session)
                self.cdp_session = None
                session = None
            else:
                last_used = self.cdp_last_used or self.cdp_opened_at
                idle = now - last_used
                age = now - self.cdp_opened_at
                fresh = (
                    idle < min(SESSION_TTL_S, 270.0)
                    and age < SESSION_MAX_AGE_S
                    and self.cdp_model == model
                )
                if fresh:
                    reused = True
                else:
                    log("recycling CDP session (age=%.0fs idle=%.0fs model=%s)"
                        % (age, idle, self.cdp_model))
                    await self.close_session(session)
                    self.cdp_session = None
                    session = None

        if session is None:
            session = await self.open_cdp_session(model)
            self.cdp_session = session
            self.cdp_opened_at = time.time()
            self.cdp_model = model
            self.page = session[2]
            await self.warm_up()
        else:
            self.page = session[2]
            try:
                await self.new_chat()
            except Exception as e:
                log("reused session broke, opening fresh:", str(e)[:160])
                await self.close_session(session)
                self.cdp_session = None
                session = await self.open_cdp_session(model)
                self.cdp_session = session
                self.cdp_opened_at = time.time()
                self.cdp_model = model
                self.page = session[2]
                await self.warm_up()
                reused = False

        log("CDP session ready (%s)" % ("reused" if reused else "fresh"))
        return session

    async def generate(self, request: ChatCompletionRequest):
        """Async generator yielding OpenAI-format SSE strings."""
        # NOTE: self.start() is deliberately NOT called here. It is called
        # below, inside a try/except, once error_frames() exists -- otherwise a
        # browser launch failure escapes this generator as an unhandled
        # exception and the client gets an opaque 500 instead of a readable
        # OpenAI-shaped error.
        model = request.model
        created = int(time.time())
        cmpl_id = "chatcmpl-" + uuid.uuid4().hex

        def sse(obj: dict) -> str:
            return "data: " + json.dumps(obj) + "\n\n"

        def delta_frame(content="", reasoning="", finish=None) -> dict:
            d = {}
            if content:
                d["content"] = content
            if reasoning:
                d["reasoning_content"] = reasoning
            return {
                "id": cmpl_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": d, "finish_reason": finish}],
            }

        # Mid-stream errors are invisible to OpenAI clients, which ignore an
        # error key inside a chunk and render an empty completion. Emit the
        # message as visible content as well.
        def error_frames(message: str, etype: str, code: str):
            frames = [
                sse({
                    "id": cmpl_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "error": {"message": message, "type": etype, "code": code},
                    "choices": [{"index": 0, "delta": {}, "finish_reason": None}],
                }),
                sse(delta_frame(content="\n\n[" + code + "] " + message)),
            ]
            return frames

        if model not in VALID_MODELS:
            msg = ("Unknown model '" + str(model) + "'. Available: "
                   + ", ".join(sorted(VALID_MODELS)))
            for f in error_frames(msg, "invalid_request_error", "model_not_found"):
                yield f
            yield sse(delta_frame(finish="stop"))
            yield "data: [DONE]\n\n"
            return

        # Bring up the browser. Playwright raises here when the Chromium
        # binaries were never downloaded (`playwright install chromium`), when
        # a shared library is missing, or when a remote CDP endpoint refuses
        # the connection. Report all of that as a normal error response.
        try:
            await self.start()
        except Exception as exc:
            detail = str(exc).strip().split("\n")[0]
            hint = ""
            low = detail.lower()
            if "executable doesn't exist" in low or "playwright install" in low:
                hint = (" The Chromium binaries are not installed. Run"
                        " 'python3 -m playwright install chromium' (add"
                        " 'install-deps' on a bare Linux host).")
            elif "cannot open shared object" in low or "error while loading" in low:
                hint = (" A system library is missing. Run"
                        " 'sudo python3 -m playwright install-deps chromium'.")
            elif BROWSER_CDP_URL:
                hint = " Check BROWSER_CDP_URL and the remote browser quota."
            log("browser start failed:", detail)
            for f in error_frames("Browser failed to start: " + detail + hint,
                                  "proxy_error", "browser_unavailable"):
                yield f
            yield sse(delta_frame(finish="stop"))
            yield "data: [DONE]\n\n"
            return

        # Serialize: one browser conversation at a time.
        async with self.send_lock:
            self.queue = asyncio.Queue()
            q = self.queue
            self.got_inpage_chunk = False
            self.fallback_emitted = False
            prompt = flatten_messages(request.messages)
            log("generate start model=", model, "cdp=", bool(BROWSER_CDP_URL),
                "prompt_len=", len(prompt))

            if not prompt.strip():
                for f in error_frames(
                    "No usable text content in messages.",
                    "invalid_request_error", "empty_prompt",
                ):
                    yield f
                yield sse(delta_frame(finish="stop"))
                yield "data: [DONE]\n\n"
                self.queue = None
                return

            session = None
            try:
                # ---- prepare a browser session ----
                if BROWSER_CDP_URL:
                    session = await self.acquire_cdp_session(model)
                else:
                    await self.try_select_model(model)
                    await self.new_chat()

                # ---- submit the prompt via the UI ----
                composer, sel = await self.find_composer()
                if composer is None:
                    for f in error_frames(
                        "Could not find the chat composer input. "
                        "Set COMPOSER_SELECTORS.",
                        "proxy_error", "composer_not_found",
                    ):
                        yield f
                    yield sse(delta_frame(finish="stop"))
                    yield "data: [DONE]\n\n"
                    return

                await composer.click()
                try:
                    await composer.fill(prompt)
                except Exception:
                    await self.page.keyboard.insert_text(prompt)
                await asyncio.sleep(0.2)
                await self.page.keyboard.press("Enter")
                log("prompt submitted via", sel, "len=", len(prompt))

                # ---- assistant role frame ----
                yield sse({
                    "id": cmpl_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "delta": {"role": "assistant"},
                        "finish_reason": None,
                    }],
                })

                buffer = ""
                emitted = ""       # for edit_content (full-snapshot) diffing
                got_first = False
                finished = False

                while True:
                    timeout = IDLE_TIMEOUT_S if got_first else FIRST_CHUNK_TIMEOUT_S
                    try:
                        kind, payload = await asyncio.wait_for(
                            q.get(), timeout=timeout
                        )
                    except asyncio.TimeoutError:
                        cap = await self.detect_captcha()
                        visible = [c for c in cap if "[visible]" in c]
                        await self.dump_state("timeout")
                        if not got_first and visible:
                            log("timeout + VISIBLE captcha:", visible)
                            msg = ("Interactive Aliyun captcha appeared and was "
                                   "not auto-solved: " + str(visible)
                                   + ". A residential IP or captcha-solving "
                                   "browser is required.")
                            frames = error_frames(
                                msg, "captcha_challenge", "captcha_required"
                            )
                        else:
                            which = "first chunk" if not got_first else "next chunk"
                            log("timeout waiting for", which,
                                "; captcha_dom=", cap)
                            msg = ("Timed out waiting for " + which
                                   + " (no /chat/completions response captured). "
                                   "captcha_dom=" + str(cap))
                            frames = error_frames(msg, "proxy_error", "timeout")
                        for f in frames:
                            yield f
                        break

                    if kind == "error":
                        log("browser stream error:", payload)
                        for f in error_frames(
                            "Browser stream error: " + str(payload),
                            "proxy_error", "stream_error",
                        ):
                            yield f
                        break

                    if kind == "done":
                        log("browser signalled done")
                        finished = True
                        break

                    # kind == "chunk": raw SSE text, may hold many/partial lines
                    got_first = True
                    if DEBUG:
                        log("[raw]", repr(payload[:300]))
                    buffer += payload

                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.rstrip("\r")
                        if not line.strip():
                            continue
                        parsed = process_chunk(line)
                        if not parsed:
                            continue

                        if parsed["type"] == "upstream_error":
                            log("upstream error:", parsed["error"])
                            code = parsed["error"].get("code") or "upstream_error"
                            for f in error_frames(
                                json.dumps(parsed["error"]),
                                "upstream_error", str(code),
                            ):
                                yield f
                            finished = True
                            break

                        if parsed["type"] == "delta":
                            phase = parsed.get("phase") or ""
                            content = parsed.get("content") or ""
                            reasoning = parsed.get("reasoning_content") or ""
                            edit = parsed.get("edit_content") or ""

                            # edit_content is a full snapshot; emit the new tail.
                            if edit and not content:
                                if edit.startswith(emitted):
                                    content = edit[len(emitted):]
                                else:
                                    content = edit
                                emitted = edit
                            elif content and phase != "thinking":
                                emitted += content

                            # GLM streams chain-of-thought as delta_content
                            # with phase == "thinking"; route per THINK_MODE.
                            if phase == "thinking" and content and not reasoning:
                                reasoning = content
                                content = ""
                            if THINK_MODE == "hide":
                                reasoning = ""
                            elif THINK_MODE == "raw" and reasoning:
                                content = reasoning + content
                                reasoning = ""

                            if content or reasoning:
                                yield sse(delta_frame(
                                    content=content, reasoning=reasoning
                                ))
                        elif parsed["type"] == "done":
                            finished = True
                            break

                    if finished:
                        break

                # flush any complete trailing line
                if finished and buffer.strip():
                    parsed = process_chunk(buffer.strip())
                    if parsed and parsed.get("type") == "delta":
                        c = parsed.get("content") or ""
                        if c:
                            yield sse(delta_frame(content=c))

                yield sse(delta_frame(finish="stop"))
                yield "data: [DONE]\n\n"

            except Exception as e:
                import traceback
                print("[glm] generate() EXCEPTION:\n" + traceback.format_exc(),
                      flush=True)
                for f in error_frames("Proxy internal error: " + str(e),
                                      "proxy_error", "internal_error"):
                    yield f
                yield sse(delta_frame(finish="stop"))
                yield "data: [DONE]\n\n"
            finally:
                self.queue = None
                if session is not None:
                    if BROWSER_CDP_URL and SESSION_TTL_S > 0:
                        # Keep alive for the next request.
                        self.cdp_last_used = time.time()
                    else:
                        await self.close_session(session)
                        self.cdp_session = None
                        self.page = None

    async def collect(self, request: ChatCompletionRequest) -> dict:
        """Non-streaming: accumulate the full answer into one OpenAI response."""
        content_parts = []
        reasoning_parts = []
        async for frame in self.generate(request):
            if not frame.startswith("data: "):
                continue
            body = frame[len("data: "):].strip()
            if body == "[DONE]":
                break
            try:
                obj = json.loads(body)
            except Exception:
                continue
            if "error" in obj:
                return {"errorPayload": obj["error"]}
            for ch in obj.get("choices", []):
                d = ch.get("delta", {})
                if d.get("content"):
                    content_parts.append(d["content"])
                if d.get("reasoning_content"):
                    reasoning_parts.append(d["reasoning_content"])
        return {
            "content": "".join(content_parts),
            "reasoning": "".join(reasoning_parts),
        }

    async def shutdown(self):
        try:
            if self.cdp_session is not None:
                await self.close_session(self.cdp_session)
                self.cdp_session = None
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.pw:
                await self.pw.stop()
        except Exception:
            pass


manager = BrowserManager()


# ---------------------------------------------------------------------------
# FastAPI
# ---------------------------------------------------------------------------

app = FastAPI(title="GLM Proxy (Playwright)", version="2.2.0")

# THE CAUSE OF THE 405s: with Authorization plus a custom header like
# X-Proxied, the browser sends a CORS preflight OPTIONS to
# /v1/chat/completions. Only POST was registered, so Starlette answered
# 405 Method Not Allowed and the real POST never ran. CORSMiddleware installs
# the OPTIONS handler and the allow headers.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    # Credentials cannot be combined with a wildcard origin per the CORS spec.
    allow_credentials=("*" not in ALLOWED_ORIGINS),
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
)


# ---- Bearer key auth ------------------------------------------------------

def unauthorized(message: str) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={
            "error": {
                "message": message,
                "type": "invalid_request_error",
                "code": "invalid_api_key",
            }
        },
        headers={"WWW-Authenticate": "Bearer"},
    )


def check_auth(request: Request):
    """Validate Authorization: Bearer <key>.

    Returns None when the caller is allowed, or a 401 JSONResponse otherwise.
    When no key is configured the proxy stays open; set REQUIRE_AUTH=1 to make
    that a startup error instead.
    """
    if not API_KEYS:
        return None

    header = request.headers.get("authorization", "")
    if header:
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer":
            return unauthorized("Authorization header must use the Bearer scheme.")
        token = token.strip()
    else:
        # Some clients only support a query param or a custom header.
        token = (request.query_params.get("api_key")
                 or request.headers.get("x-api-key", "")).strip()

    if not token:
        return unauthorized("Missing API key. Send Authorization: Bearer <key>.")

    for k in API_KEYS:
        if hmac.compare_digest(token, k):
            return None
    return unauthorized("Incorrect API key provided.")


@app.on_event("startup")
async def on_startup():
    if REQUIRE_AUTH and not API_KEYS:
        raise RuntimeError(
            "REQUIRE_AUTH=1 but neither API_KEY nor API_KEYS is set"
        )
    if API_KEYS:
        print("[glm] bearer auth ENABLED (%d key(s))" % len(API_KEYS), flush=True)
    else:
        print("[glm] WARNING: no API_KEY set, this proxy is open to the internet",
              flush=True)
    print("[glm] CORS allow_origins=" + str(ALLOWED_ORIGINS), flush=True)

    # Warm the browser in the BACKGROUND so the HTTP server binds immediately.
    # Awaiting start() here is dangerous: if Playwright hangs on cold boot,
    # uvicorn never signals startup complete, the healthcheck fails, and
    # Railway's edge returns 502. generate() also awaits start(), so the first
    # real request still warms the browser lazily.
    async def warm():
        try:
            await manager.start()
            print("[glm] browser warm-up complete", flush=True)
        except Exception as e:
            print("[glm] browser warm-up failed at startup:", e, flush=True)

    asyncio.create_task(warm())


@app.on_event("shutdown")
async def on_shutdown():
    await manager.shutdown()


@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": "glm-proxy",
        "mode": "playwright",
        "auth_required": bool(API_KEYS),
        "models": sorted(VALID_MODELS),
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "browser_ready": manager.is_ready}


@app.get("/v1/models")
async def list_models(request: Request):
    denied = check_auth(request)
    if denied is not None:
        return denied
    return {"object": "list", "data": MODELS}


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    denied = check_auth(request)
    if denied is not None:
        return denied

    try:
        raw = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={
            "error": {
                "message": "Request body is not valid JSON.",
                "type": "invalid_request_error",
            }
        })

    try:
        req = ChatCompletionRequest(**raw)
    except Exception as e:
        return JSONResponse(status_code=400, content={
            "error": {"message": str(e), "type": "invalid_request_error"}
        })

    if req.stream:
        return StreamingResponse(
            manager.generate(req),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    result = await manager.collect(req)
    if "errorPayload" in result:
        return JSONResponse(status_code=502,
                            content={"error": result["errorPayload"]})

    return {
        "id": "chatcmpl-" + uuid.uuid4().hex,
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": result["content"]},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        },
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
