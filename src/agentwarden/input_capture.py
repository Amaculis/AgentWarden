"""Input injection and screen/clipboard capture detectors (spec 031): pure regex, no I/O.

`injection(command)` / `capture(command)` look at a shell command; `script_technique(text,
ext)` looks at the content of a script file being written. Each returns a short technique
name for the verdict's reason, or `None`.

Multi-term families are tuples of regexes that must all match the same text (no gap between
the terms), and every remaining gap is bounded, so the scan stays linear on megabyte input.
Tools are matched in command position only (`grep xdotool notes.md` is not a match); API
names (SendKeys, user32, ...) anywhere in the command.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import re
import shlex
from collections.abc import Iterator

# ---------------------------------------------------------------------------
# Gated patterns: a regex runs only when one of its literal gates is in the lowercased text.
# Linear either way, but a case-insensitive alternation costs ~30 ms per megabyte and `in`
# almost nothing, so ordinary large input skips the regexes.
# ---------------------------------------------------------------------------

_I = re.IGNORECASE


class _Gated:
    def __init__(self, gates: tuple[str, ...], pattern: str) -> None:
        self.gates = gates
        self.regex = re.compile(pattern, re.IGNORECASE)

    def search(self, text: str, low: str) -> bool:
        return any(g in low for g in self.gates) and self.regex.search(text) is not None


def _gate(gates: str | tuple[str, ...], pattern: str) -> _Gated:
    return _Gated((gates,) if isinstance(gates, str) else gates, pattern)


# API families: every pattern of a tuple must match somewhere in the text.
Family = tuple[str, tuple[_Gated, ...]]

INJECTION_API: tuple[Family, ...] = (
    ("SendKeys", (_gate("sendkeys", r"\bSendKeys\]?\s*::\s*Send(?:Wait)?\s*\("),)),
    (
        "WScript.Shell SendKeys",
        (
            _gate("wscript.shell", r"\bWScript\.Shell\b"),
            _gate(("sendkeys", "appactivate"), r"\.(?:SendKeys|AppActivate)\b"),
        ),
    ),
    (
        "user32 input API",
        (
            _gate("user32", r"\buser32\b"),
            _gate(
                (
                    "keybd_event",
                    "sendinput",
                    "mouse_event",
                    "setcursorpos",
                    "setforegroundwindow",
                    "postmessage",
                    "sendmessage",
                ),
                r"\b(?:keybd_event|SendInput|mouse_event|SetCursorPos|SetForegroundWindow"
                r"|PostMessage[AW]?|SendMessage[AW]?)\b",
            ),
        ),
    ),
    (
        "UI Automation",
        (
            _gate(
                ("system.windows.automation", "uiautomationclient"),
                r"\bSystem\.Windows\.Automation\b|\bUIAutomationClient\b",
            ),
            _gate(("invokepattern", "valuepattern"), r"\b(?:InvokePattern|ValuePattern)\b"),
        ),
    ),
)

# Python and AppleScript APIs: in a command they count only with their interpreter
# (`python -c`, `osascript`); in a script file being written, on their own.
_PY_INJECTION: tuple[Family, ...] = (
    (
        "pyautogui",
        (
            _gate("pyautogui", r"\bpyautogui\b"),
            _gate(
                ("press", "write", "hotkey", "click", "key", "move", "drag", "mouse", "scroll"),
                r"\.(?:press|write|typewrite|hotkey|click|doubleClick|rightClick|keyDown|keyUp"
                r"|moveTo|moveRel|dragTo|mouseDown|mouseUp|scroll)\s*\(",
            ),
        ),
    ),
    ("pynput", (_gate("pynput", r"\bpynput\b"),)),
    (
        "keyboard",
        (_gate("keyboard.", r"\bkeyboard\.(?:write|press|send|press_and_release)\s*\("),),
    ),
)
_PY_IMPORT = _gate("pyautogui", r"\bimport\s+pyautogui\b|\bfrom\s+pyautogui\s+import\b")
_AS_INJECTION = (
    _gate("system events", r"\bSystem Events\b"),
    _gate(("keystroke", "key code", "click"), r"\b(?:keystroke|key code|click)\b"),
)
_OSASCRIPT = _gate("osascript", r"\bosascript\b")
# Each repetition consumes a whole flag, so the unbounded `*` stays linear (a cap on the
# flag count would let `python -u -u -u -u -u -c ...` through).
_PY_INVOKE = _gate(
    "py",
    r"(?<![\w.-])(?:python[\d.]*|pythonw|py)(?:\.exe)?['\"]?(?:\s+-[A-Za-z]+)*?"
    r"\s+(?:-[A-Za-z]*c\b|-?\s*<<)"
    r"|\|\s*(?:python[\d.]*|pythonw|py)(?:\.exe)?\b",
)
_PY_NAME_RE = re.compile(r"python[\d.]*w?|py|pyw")
_PY_CODE_FLAG_RE = re.compile(r"-[a-z]*c")
# AutoHotkey commands that send input or switch windows (checked on .ahk files only).
_AHK_INPUT = _gate(
    ("send", "click", "mouse", "winactivate"),
    r"\b(?:Send(?:Input|Event|Play|Raw|Text)?|ControlSend|ControlClick|Click|MouseMove"
    r"|MouseClick|WinActivate)\b",
)

CAPTURE_API: tuple[Family, ...] = (
    (
        "ffmpeg desktop grab",
        (
            _gate("ffmpeg", r"\bffmpeg\b"),
            _gate(
                ("gdigrab", "x11grab", "avfoundation", "kmsgrab", "ddagrab"),
                r"-f\s+(?:gdigrab|x11grab|avfoundation|kmsgrab)\b|\bddagrab\b",
            ),
        ),
    ),
    (
        "ffmpeg desktop grab",
        (
            _gate("ffmpeg", r"\bffmpeg\b"),
            _gate("dshow", r"-f\s+dshow\b"),
            _gate("screen-capture-recorder", r"screen-capture-recorder"),
        ),
    ),
    ("CopyFromScreen", (_gate("copyfromscreen", r"\bCopyFromScreen\b"),)),
    ("Get-Clipboard", (_gate("get-clipboard", r"\bGet-Clipboard\b"),)),
    ("clipboard read", (_gate("clipboard]", r"\bClipboard\]\s*::\s*GetText\b"),)),
)

_PY_CAPTURE = _gate(
    ("imagegrab", "mss", "pyautogui", "pyperclip", "getclipboarddata"),
    r"\bImageGrab\.grab\b|\bimport\s+mss\b|\bfrom\s+mss\s+import\b|\bmss\.mss\s*\("
    r"|\bpyautogui\.screenshot\s*\(|\bpyperclip\.paste\s*\(|\bGetClipboardData\b",
)


def _all(patterns: tuple[_Gated, ...], text: str, low: str) -> bool:
    return all(p.search(text, low) for p in patterns)


def _api_match(text: str, low: str, families: tuple[Family, ...]) -> str | None:
    for name, patterns in families:
        if _all(patterns, text, low):
            return name
    return None


# ---------------------------------------------------------------------------
# Tools in command position
# ---------------------------------------------------------------------------

_CHAIN_TOKENS = frozenset({"&&", "||", "|", ";", "&", "(", ")", "|&", ";;"})
_PREFIX_WORDS = frozenset(
    {
        "sudo", "doas", "env", "nohup", "exec", "time", "xargs", "nice", "timeout", "command",
        "builtin", "watch", "start", "start-process", "saps", "invoke-item", "ii", "call",
    }
)  # fmt: skip
_ASSIGN_RE = re.compile(r"[A-Za-z_]\w*=.*", re.DOTALL)
_PREFIX_ARG_RE = re.compile(r"-.*|\d[\d.]*[smhd]?", re.DOTALL)
# `bash -c "..."`, `bash -lc`, `pwsh -Command`, `cmd /c`: the next token is a command too.
_INLINE_FLAG_RE = re.compile(r"-[a-z]*c|-command|-commandwithargs|/[ck]", _I)

_INJECTION_TOOLS = frozenset({"xdotool", "ydotool", "wtype", "xte"})
_AUTOHOTKEY_RE = re.compile(r"autohotkey(?:u?(?:32|64))?(?:ux)?|.*\.ahk")
_NIRCMD = frozenset({"nircmd", "nircmdc"})
_NIRCMD_INPUT = frozenset(
    {"sendkey", "sendkeypress", "sendmouse", "setcursor", "setcursorwin", "movecursor"}
)
_NIRCMD_CAPTURE = frozenset({"savescreenshot", "savescreenshotwin", "savescreenshotfull"})
_SCREENSHOT_TOOLS = frozenset(
    {"screencapture", "scrot", "gnome-screenshot", "spectacle", "grim", "maim"}
)
_CLIPBOARD_TOOLS = frozenset({"pbpaste", "wl-paste", "gcb"})
_XSEL_OUTPUT_RE = re.compile(r"--output|-[a-z]*o[a-z]*")

# Cheap pre-filter: only tokenize when one of the tool names appears at all.
_TOOL_HINTS = (
    "xdotool", "ydotool", "wtype", "xte", "autohotkey", ".ahk", "nircmd", "screencapture",
    "scrot", "gnome-screenshot", "spectacle", "grim", "maim", "import", "pbpaste", "wl-paste",
    "gcb", "xclip", "xsel",
)  # fmt: skip
_MAX_DEPTH = 2


_FALLBACK_TOKEN_RE = re.compile(r"&&|\|\||[;&|()]|[^\s;&|()]+")


def _tokens(command: str) -> Iterator[str]:
    """Shell-ish tokens with operators as their own tokens (same lexer as `rules`), lazily."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.escape = ""
    # Newlines become `;` before lexing, so a `#` comment would swallow every later line.
    lexer.commenters = ""
    try:
        yield from lexer
    except ValueError:  # unbalanced quote: the whole command again, as plain words
        yield ";"
        yield from (tok.strip("\"'") for tok in _FALLBACK_TOKEN_RE.findall(command))


def _segments(command: str) -> Iterator[list[str]]:
    segment: list[str] = []
    for tok in _tokens(command.replace("\n", " ; ")):
        if tok in _CHAIN_TOKENS:
            if segment:
                yield segment
            segment = []
        else:
            segment.append(tok)
    if segment:
        yield segment


def _name(tok: str) -> str:
    return posixpath.basename(tok.strip("\"'").replace("\\", "/")).lower().removesuffix(".exe")


def invocations(command: str, depth: int = 0) -> Iterator[tuple[str, list[str]]]:
    """`(command name, lowercased args)` per pipeline segment, inline shells included.

    Lazy, so a caller that stops at the first match does not lex the rest of a huge command.
    """
    for seg in _segments(command):
        i, after_prefix = 0, False
        while i < len(seg):
            tok = seg[i]
            if _name(tok) in _PREFIX_WORDS:
                after_prefix = True
            elif not (
                _ASSIGN_RE.fullmatch(tok) or (after_prefix and _PREFIX_ARG_RE.fullmatch(tok))
            ):
                break
            i += 1
        if i >= len(seg):
            continue
        args = seg[i + 1 :]
        yield _name(seg[i]), [a.lower() for a in args]
        if depth < _MAX_DEPTH:
            for flag, inner in zip(args, args[1:], strict=False):
                if _INLINE_FLAG_RE.fullmatch(flag):
                    yield from invocations(inner, depth + 1)


def _first_arg(args: list[str]) -> str:
    return next((a for a in args if not a.startswith(("-", "/"))), "")


def _injection_tool(name: str, args: list[str]) -> str | None:
    if name in _INJECTION_TOOLS:
        return name
    if _AUTOHOTKEY_RE.fullmatch(name):
        return "AutoHotkey"
    if name in _NIRCMD and _first_arg(args) in _NIRCMD_INPUT:
        return f"nircmd {_first_arg(args)}"
    return None


def _capture_tool(name: str, args: list[str]) -> str | None:
    if name in _SCREENSHOT_TOOLS:
        return name
    if name in _NIRCMD and _first_arg(args) in _NIRCMD_CAPTURE:
        return f"nircmd {_first_arg(args)}"
    if name == "import" and any(
        a == "-window" and b == "root" for a, b in zip(args, args[1:], strict=False)
    ):
        return "import -window root"
    if name in _CLIPBOARD_TOOLS:
        return "clipboard read" if name == "gcb" else name
    if name == "xclip" and any(a in ("-o", "-out") for a in args):
        return "xclip -o"
    if name == "xsel" and any(_XSEL_OUTPUT_RE.fullmatch(a) for a in args):
        return "xsel -o"
    return None


def _tool_match(command: str, low: str, check) -> str | None:
    if not any(hint in low for hint in _TOOL_HINTS):
        return None
    for name, args in invocations(command):
        technique = check(name, args)
        if technique:
            return technique
    return None


# ---------------------------------------------------------------------------
# PowerShell -EncodedCommand
# ---------------------------------------------------------------------------

MAX_DECODED = 64 * 1024
_MAX_TOKEN = (MAX_DECODED * 4) // 3 + 4
_POWERSHELL_RE = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", _I)
_FLAG_TOKEN_RE = re.compile(
    r"(?<!\S)[-/]{1,2}([A-Za-z]+)(?::|\s+)['\"]?(\$[\w:]+|[A-Za-z0-9+/=]{4,})"
)
# `$t = '<base64>'; powershell -enc $t`: the payload is a string literal elsewhere.
_QUOTED_B64_RE = re.compile(r"['\"]([A-Za-z0-9+/]{16,}={0,2})['\"]")


def _decode_utf16_b64(token: str) -> str | None:
    if len(token) > _MAX_TOKEN:
        return None
    try:
        raw = base64.b64decode(token, validate=True)
        if len(raw) > MAX_DECODED:
            return None
        return raw.decode("utf-16-le")
    except (binascii.Error, ValueError):
        return None


def _is_encoded_flag(flag: str) -> bool:
    flag = flag.lower()
    return flag in ("e", "ec") or (len(flag) >= 2 and "encodedcommand".startswith(flag))


def decode_ps_encoded(command: str) -> str | None:
    """Decoded text of every `powershell -EncodedCommand <base64>` in `command`, or `None`.

    Base64 of UTF-16LE, at most 64 KB decoded per token; anything undecodable is skipped.
    """
    low = command.lower()
    shell = _POWERSHELL_RE.search(command) if "powershell" in low or "pwsh" in low else None
    if shell is None:
        return None
    decoded: list[str] = []
    from_variable = False
    for match in _FLAG_TOKEN_RE.finditer(command, shell.end()):
        flag, token = match.groups()
        if not _is_encoded_flag(flag):
            continue
        if token.startswith("$"):
            from_variable = True
        elif (text := _decode_utf16_b64(token)) is not None:
            decoded.append(text)
    if from_variable:
        for match in _QUOTED_B64_RE.finditer(command):
            if (text := _decode_utf16_b64(match.group(1))) is not None:
                decoded.append(text)
    return "\n".join(decoded) if decoded else None


# ---------------------------------------------------------------------------
# Public detectors
# ---------------------------------------------------------------------------


def _python_runs_code(command: str, low: str) -> bool:
    """`python -c` / heredoc / pipe into python; flags with values (`-X utf8 -c`) included."""
    if _PY_INVOKE.search(command, low):
        return True
    return any(
        _PY_NAME_RE.fullmatch(name) and any(_PY_CODE_FLAG_RE.fullmatch(a) for a in args)
        for name, args in invocations(command)
    )


def _injection_plain(command: str) -> str | None:
    low = command.lower()
    technique = _api_match(command, low, INJECTION_API)
    if technique:
        return technique
    if _api_match(command, low, _PY_INJECTION) and _python_runs_code(command, low):
        return "Python input automation"
    if _OSASCRIPT.search(command, low) and _all(_AS_INJECTION, command, low):
        return "osascript System Events"
    return _tool_match(command, low, _injection_tool)


def injection(command: str) -> str | None:
    """The input-injection technique in a shell command (or its -EncodedCommand), or `None`."""
    technique = _injection_plain(command)
    if technique:
        return technique
    decoded = decode_ps_encoded(command)
    if decoded:
        technique = _injection_plain(decoded)
        return f"{technique}, base64-encoded" if technique else None
    return None


def capture(command: str) -> str | None:
    """The screen/clipboard capture technique in a shell command, or `None`."""
    low = command.lower()
    technique = _api_match(command, low, CAPTURE_API)
    if technique:
        return technique
    if _PY_CAPTURE.search(command, low) and _python_runs_code(command, low):
        return "Python screen/clipboard capture"
    return _tool_match(command, low, _capture_tool)


SCRIPT_EXTENSIONS = frozenset(
    {
        ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ahk", ".py", ".pyw", ".ipynb",
        ".sh", ".bash", ".zsh", ".bat", ".cmd", ".applescript", ".scpt",
    }
)  # fmt: skip
_SHELL_SCRIPT_EXTENSIONS = frozenset({".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd"})
# Tool names distinctive enough to count anywhere in a script (e.g. inside subprocess.run([...])).
_SCRIPT_TOOL = _gate(
    ("xdotool", "ydotool", "wtype", "nircmd"),
    r"\b(?:xdotool|ydotool|wtype)\b|\bnircmdc?(?:\.exe)?['\"]?[\s,]+['\"]?(?:sendkey|sendmouse"
    r"|setcursor|movecursor|savescreenshot)",
)


def script_technique(text: str, ext: str) -> str | None:
    """Input injection or capture in the content of a script file with extension `ext`."""
    low = text.lower()
    if ext == ".ahk" and _AHK_INPUT.search(text, low):
        return "AutoHotkey input"
    technique = _api_match(text, low, INJECTION_API) or _api_match(text, low, CAPTURE_API)
    if technique:
        return technique
    if _api_match(text, low, _PY_INJECTION) or _PY_IMPORT.search(text, low):
        return "Python input automation"
    if _PY_CAPTURE.search(text, low):
        return "Python screen/clipboard capture"
    if _all(_AS_INJECTION, text, low):
        return "AppleScript System Events"
    if _SCRIPT_TOOL.search(text, low):
        return "xdotool/nircmd"
    if ext in _SHELL_SCRIPT_EXTENSIONS:
        return injection(text) or capture(text)
    return None
