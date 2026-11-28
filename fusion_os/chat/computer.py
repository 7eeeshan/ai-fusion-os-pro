"""Using the person's own Windows computer from the chat, when they ask for it.

Off by default: the person turns on "Use my computer" for one chat. Then the assistant can
- look: take a screenshot (shown to the person in the chat), list the open windows, read a window's controls
  (names, kinds and positions through Windows UI Automation, so a text-only local model can still find buttons);
- act: open an app, bring a window to the front, click (a point, or a control by its name), type text, press keys,
  scroll. Every action asks the person first (`computer.control`), unless they turned on "without asking" for that
  chat (`computer.control.preapproved`). The emergency stop blocks all of it, like every other action.

Everything runs in Windows PowerShell 5.1 (always installed) with .NET and user32, as the signed-in user, no extra
programs. Arguments go to PowerShell as base64 JSON, never pasted into the script, so text can't turn into code.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Callable, Optional

OBSERVE = ("screenshot", "list_windows", "read_window")
CONTROL = ("open_app", "focus_window", "click", "click_element", "type_text", "press_keys", "scroll")
MAX_SHOTS = 60
SHOT_WIDTH = 1280
SHOT_NAME = re.compile(r"^[0-9a-f]{32}\.(png|jpg)$")

VK = {"ctrl": 0x11, "control": 0x11, "alt": 0x12, "shift": 0x10, "win": 0x5B, "windows": 0x5B, "enter": 0x0D,
      "return": 0x0D, "tab": 0x09, "esc": 0x1B, "escape": 0x1B, "backspace": 0x08, "delete": 0x2E, "del": 0x2E,
      "insert": 0x2D, "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27, "home": 0x24, "end": 0x23,
      "pageup": 0x21, "pagedown": 0x22, "space": 0x20, "printscreen": 0x2C, "capslock": 0x14, "menu": 0x5D,
      "volumeup": 0xAF, "volumedown": 0xAE, "mute": 0xAD, "playpause": 0xB3}
VK.update({f"f{i}": 0x6F + i for i in range(1, 13)})


class ComputerError(ValueError):
    pass


def keys_to_vk(combo: str) -> list[int]:
    """'ctrl+shift+s' -> virtual-key codes, pressed in order and released in reverse."""
    out = []
    for part in [p.strip().lower() for p in str(combo).replace(" ", "").split("+") if p.strip()]:
        if part in VK:
            out.append(VK[part])
        elif len(part) == 1 and part.isalnum():
            out.append(ord(part.upper()))
        else:
            raise ComputerError(f"unknown key {part!r}; use names like ctrl, alt, shift, win, enter, tab, esc, f5, a")
    if not out or len(out) > 5:
        raise ComputerError("give one key combination, e.g. ctrl+s or alt+tab")
    return out


PRELUDE = r"""
$ErrorActionPreference = 'Stop'
$A = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ARGS__')) | ConvertFrom-Json
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices; using System.Text;
public static class FU {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern int GetWindowTextLength(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr h, uint cmd);
  public static List<object[]> Windows() {
    var list = new List<object[]>();
    EnumWindows((h, l) => {
      if (!IsWindowVisible(h) || GetWindow(h, 4) != IntPtr.Zero) return true;  // visible, not owned (no dialogs' owners)
      int n = GetWindowTextLength(h); if (n == 0) return true;
      var sb = new StringBuilder(n + 1); GetWindowText(h, sb, sb.Capacity);
      uint pid; GetWindowThreadProcessId(h, out pid);
      list.Add(new object[] { h.ToInt64(), (int)pid, sb.ToString() });
      return true; }, IntPtr.Zero);
    return list;
  }
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, int d, UIntPtr e);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, UIntPtr e);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool IsIconic(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}
'@
[FU]::SetProcessDPIAware() | Out-Null
function Out-Json($o) { [Console]::Out.Write((ConvertTo-Json -InputObject $o -Depth 6 -Compress)) }
function Find-Window($t) {
  foreach ($w in [FU]::Windows()) { if ($w[2] -like ('*' + $t + '*')) { return [IntPtr][long]$w[0] } }
  return [IntPtr]::Zero }
function Window-Name($h) { foreach ($w in [FU]::Windows()) { if ([long]$w[0] -eq $h.ToInt64()) { return $w[2] } }; return '' }
"""

SCRIPTS = {
    "screenshot": r"""
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$b = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
$s = [Math]::Min(1.0, $A.max_w / $b.Width)
$w = [int]($b.Width * $s); $h = [int]($b.Height * $s)
$out = New-Object System.Drawing.Bitmap $w, $h
$g2 = [System.Drawing.Graphics]::FromImage($out)
$g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g2.DrawImage($bmp, 0, 0, $w, $h)
$codec = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.MimeType -eq 'image/jpeg' }
$ep = New-Object System.Drawing.Imaging.EncoderParameters 1
$ep.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality), 75L
$out.Save($A.path, $codec, $ep)
$t = Window-Name ([FU]::GetForegroundWindow())
Out-Json @{ left = $b.Left; top = $b.Top; width = $b.Width; height = $b.Height; scale = $s; w = $w; h = $h;
            foreground = $t }
""",
    "list_windows": r"""
$fg = [FU]::GetForegroundWindow().ToInt64()
$names = @{}; Get-Process | ForEach-Object { $names[$_.Id] = $_.ProcessName }
$ws = New-Object System.Collections.ArrayList
foreach ($w in [FU]::Windows()) {
  [void]$ws.Add(@{ pid = $w[1]; app = $names[[int]$w[1]]; title = $w[2]; active = ([long]$w[0] -eq $fg);
     minimized = [FU]::IsIconic([IntPtr][long]$w[0]) }) }
Out-Json @($ws)
""",
    "read_window": r"""
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$AE = [System.Windows.Automation.AutomationElement]
$win = $null
if ($A.title) { $h = Find-Window $A.title; if ($h -ne [IntPtr]::Zero) { $win = $AE::FromHandle($h) } }
else { $win = $AE::FromHandle([FU]::GetForegroundWindow()) }
if (-not $win) { throw ('no window matches ' + $A.title) }
$walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
$items = New-Object System.Collections.ArrayList
function Walk($e, $d) {
  if ($items.Count -ge $A.max -or $d -gt $A.depth) { return }
  $c = $e.Current
  $r = $c.BoundingRectangle
  if (-not $r.IsEmpty -and $r.Width -gt 0) {
    [void]$items.Add(@{ d = $d; kind = $c.ControlType.ProgrammaticName -replace 'ControlType\.', ''; name = $c.Name;
      id = $c.AutomationId; x = [int]($r.X + $r.Width / 2); y = [int]($r.Y + $r.Height / 2);
      w = [int]$r.Width; h = [int]$r.Height; enabled = $c.IsEnabled })
  }
  $ch = $walker.GetFirstChild($e)
  while ($ch -ne $null -and $items.Count -lt $A.max) { Walk $ch ($d + 1); $ch = $walker.GetNextSibling($ch) }
}
Walk $win 0
Out-Json @{ title = $win.Current.Name; items = @($items) }
""",
    "open_app": r"""
if ($A.args) { $p = Start-Process -FilePath $A.target -ArgumentList $A.args -PassThru }
else { $p = Start-Process -FilePath $A.target -PassThru }
Start-Sleep -Milliseconds 800
Out-Json @{ started = $A.target; pid = $(if ($p) { $p.Id } else { $null }) }
""",
    "focus_window": r"""
$h = Find-Window $A.title
if ($h -eq [IntPtr]::Zero) { throw ('no window matches ' + $A.title) }
if ([FU]::IsIconic($h)) { [FU]::ShowWindow($h, 9) | Out-Null }
[FU]::keybd_event(0x12, 0, 0, [UIntPtr]::Zero); [FU]::keybd_event(0x12, 0, 2, [UIntPtr]::Zero)
[FU]::SetForegroundWindow($h) | Out-Null
Out-Json @{ focused = (Window-Name $h) }
""",
    "click": r"""
[FU]::SetCursorPos($A.x, $A.y) | Out-Null
Start-Sleep -Milliseconds 60
$down = 2; $up = 4
if ($A.button -eq 'right') { $down = 8; $up = 16 } elseif ($A.button -eq 'middle') { $down = 32; $up = 64 }
for ($i = 0; $i -lt $A.times; $i++) {
  [FU]::mouse_event($down, 0, 0, 0, [UIntPtr]::Zero); [FU]::mouse_event($up, 0, 0, 0, [UIntPtr]::Zero)
  Start-Sleep -Milliseconds 70 }
Out-Json @{ clicked = @($A.x, $A.y); button = $A.button; count = $A.times }
""",
    "click_element": r"""
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$AE = [System.Windows.Automation.AutomationElement]
$win = $null
if ($A.title) { $h = Find-Window $A.title; if ($h -ne [IntPtr]::Zero) { $win = $AE::FromHandle($h) } }
else { $win = $AE::FromHandle([FU]::GetForegroundWindow()) }
if (-not $win) { throw 'no such window' }
$all = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, [System.Windows.Automation.Condition]::TrueCondition)
$hit = $null
foreach ($e in $all) { if ($e.Current.Name -eq $A.name) { $hit = $e; break } }
if (-not $hit) { foreach ($e in $all) { if ($e.Current.Name -like ('*' + $A.name + '*')) { $hit = $e; break } } }
if (-not $hit) { throw ('no control named ' + $A.name) }
$how = 'click'
$ip = $null
if ($hit.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$ip)) { $ip.Invoke(); $how = 'invoke' }
else {
  $r = $hit.Current.BoundingRectangle
  [FU]::SetCursorPos([int]($r.X + $r.Width / 2), [int]($r.Y + $r.Height / 2)) | Out-Null
  [FU]::mouse_event(2, 0, 0, 0, [UIntPtr]::Zero); [FU]::mouse_event(4, 0, 0, 0, [UIntPtr]::Zero) }
Out-Json @{ clicked = $hit.Current.Name; kind = $hit.Current.ControlType.ProgrammaticName; how = $how }
""",
    "type_text": r"""
Add-Type -AssemblyName System.Windows.Forms
$t = [string]$A.text
$esc = [regex]::Replace($t, '[+^%~(){}\[\]]', { param($m) '{' + $m.Value + '}' })
$esc = $esc -replace "`r`n", "`n" -replace "`n", '{ENTER}' -replace "`t", '{TAB}'
[System.Windows.Forms.SendKeys]::SendWait($esc)
Out-Json @{ typed = $t.Length }
""",
    "press_keys": r"""
foreach ($k in $A.vk) { [FU]::keybd_event([byte]$k, 0, 0, [UIntPtr]::Zero); Start-Sleep -Milliseconds 30 }
for ($i = $A.vk.Count - 1; $i -ge 0; $i--) { [FU]::keybd_event([byte]$A.vk[$i], 0, 2, [UIntPtr]::Zero) }
Out-Json @{ pressed = $A.combo }
""",
    "scroll": r"""
if ($A.x -ne $null) { [FU]::SetCursorPos($A.x, $A.y) | Out-Null }
[FU]::mouse_event(0x0800, 0, 0, [int](120 * $A.amount), [UIntPtr]::Zero)
Out-Json @{ scrolled = $A.amount }
""",
}


def _powershell(script: str, timeout: float) -> tuple[int, str, str]:
    exe = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    p = subprocess.run([str(exe), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"],
                       input=script, capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return p.returncode, p.stdout, p.stderr


class ComputerUse:
    def __init__(self, shots: Path, runner: Optional[Callable[[str, float], tuple[int, str, str]]] = None,
                 platform: Optional[str] = None):
        self.shots = shots
        self.runner = runner or _powershell
        self.platform = platform or os.name
        self.view: dict = {}  # how the last screenshot maps to the screen, so clicks can use its coordinates

    def available(self) -> bool:
        return self.platform == "nt"

    def _run(self, action: str, args: dict, timeout: float = 30) -> dict:
        if not self.available():
            raise ComputerError("using the computer works on Windows only")
        b64 = base64.b64encode(json.dumps(args).encode()).decode()
        rc, out, err = self.runner(PRELUDE.replace("__ARGS__", b64) + SCRIPTS[action], timeout)
        if rc != 0:
            msg = (err or out).strip().splitlines()
            raise ComputerError(f"{action} failed: " + " ".join(msg[-3:])[:600] if msg else f"{action} failed")
        try:
            return json.loads(out.strip() or "{}")
        except ValueError:
            raise ComputerError(f"{action}: unexpected output {out[:200]!r}")

    # ---------- coordinates ----------
    def to_screen(self, x, y) -> tuple[int, int]:
        """Coordinates in the latest screenshot -> real screen pixels."""
        x, y = float(x), float(y)
        v = self.view
        if not v:
            return int(x), int(y)
        if not (0 <= x <= v["w"] and 0 <= y <= v["h"]):
            raise ComputerError(f"({int(x)}, {int(y)}) is outside the screenshot ({v['w']}x{v['h']})")
        s = v["scale"] or 1
        return int(round(v["left"] + x / s)), int(round(v["top"] + y / s))

    def from_screen(self, x, y) -> tuple[int, int]:
        v = self.view
        if not v:
            return int(x), int(y)
        s = v["scale"] or 1
        return int(round((x - v["left"]) * s)), int(round((y - v["top"]) * s))

    # ---------- screenshots ----------
    def _prune(self) -> None:
        files = sorted(self.shots.glob("*.jpg"), key=lambda p: p.stat().st_mtime)
        for f in files[:-MAX_SHOTS]:
            try:
                f.unlink()
            except OSError:
                pass

    def shot_path(self, name: str) -> Path:
        if not SHOT_NAME.match(name):
            raise ComputerError("bad screenshot name")
        return self.shots / name

    def screenshot(self) -> dict:
        self.shots.mkdir(parents=True, exist_ok=True)
        name = uuid.uuid4().hex + ".jpg"
        r = self._run("screenshot", {"path": str(self.shots / name), "max_w": SHOT_WIDTH})
        self.view = {k: r.get(k) for k in ("left", "top", "width", "height", "scale", "w", "h")}
        self._prune()
        return {"image": name, "foreground": r.get("foreground") or "", **self.view}

    # ---------- the actions ----------
    def do(self, action: str, args: dict) -> dict:
        """Returns {text: for the model, summary, image?: screenshot name for the person}."""
        a = dict(args or {})
        if action == "screenshot":
            s = self.screenshot()
            return {"text": f"Screenshot taken ({s['w']}x{s['h']}; the screen is {s['width']}x{s['height']}). "
                            f"Active window: {s['foreground'] or 'none'}. Coordinates you give to click use this "
                            "screenshot's pixels. You may not be able to see the image; use read_window to get "
                            "the controls as text.", "summary": s["foreground"] or "screen", "image": s["image"]}
        if action == "list_windows":
            ws = self._run("list_windows", {})
            ws = ws if isinstance(ws, list) else [ws] if ws else []
            text = "\n".join(f"- {w.get('title')} ({w.get('app')}{', active' if w.get('active') else ''}"
                             f"{', minimized' if w.get('minimized') else ''})" for w in ws)
            return {"text": text or "no windows", "summary": f"{len(ws)} windows"}
        if action == "read_window":
            r = self._run("read_window", {"title": str(a.get("title") or ""), "max": 250,
                                          "depth": max(1, min(int(a.get("depth") or 8), 15))})
            lines = []
            for it in r.get("items") or []:
                x, y = self.from_screen(it["x"], it["y"])
                name = (it.get("name") or "").replace("\n", " ")[:80]
                lines.append(f"{'  ' * min(it['d'], 8)}{it['kind']} \"{name}\" at ({x}, {y})"
                             + ("" if it.get("enabled", True) else " disabled"))
            return {"text": f"Window: {r.get('title')}\n" + "\n".join(lines) +
                            ("\n(coordinates are in screenshot pixels)" if self.view else ""),
                    "summary": f"{r.get('title')}: {len(lines)} controls"}
        if action == "open_app":
            target = str(a.get("app") or a.get("target") or "").strip()
            if not target or len(target) > 400 or "\n" in target:
                raise ComputerError("give the app to open: a name like notepad or calc, a full path, or ms-settings:")
            extra = a.get("args")
            extra = [str(x)[:400] for x in extra][:20] if isinstance(extra, list) else None
            r = self._run("open_app", {"target": target, "args": extra})
            return self._after(f"opened {target}", f"Opened {target}")
        if action == "focus_window":
            r = self._run("focus_window", {"title": self._title(a)})
            return self._after(f"focused {r.get('focused')}", f"Brought {r.get('focused')} to the front")
        if action == "click":
            x, y = self.to_screen(a.get("x"), a.get("y"))
            button = a.get("button") if a.get("button") in ("left", "right", "middle") else "left"
            n = 2 if a.get("double") else 1
            self._run("click", {"x": x, "y": y, "button": button, "times": n})
            return self._after(f"{'double-' if n == 2 else ''}{button} click at ({a.get('x')}, {a.get('y')})",
                               f"Clicked at ({a.get('x')}, {a.get('y')})")
        if action == "click_element":
            name = str(a.get("name") or "").strip()
            if not name:
                raise ComputerError("give the name of the control to click (from read_window)")
            r = self._run("click_element", {"name": name[:200], "title": str(a.get("title") or "")})
            return self._after(f"clicked {r.get('clicked')!r}", f"Clicked {r.get('clicked')}")
        if action == "type_text":
            text = str(a.get("text") or "")
            if not text or len(text) > 5000:
                raise ComputerError("give the text to type (up to 5,000 characters)")
            self._run("type_text", {"text": text}, timeout=60)
            return self._after(f"typed {len(text)} characters", f"Typed {len(text)} characters")
        if action == "press_keys":
            combo = str(a.get("keys") or "")
            self._run("press_keys", {"vk": keys_to_vk(combo), "combo": combo})
            return self._after(f"pressed {combo}", f"Pressed {combo}")
        if action == "scroll":
            amount = max(-50, min(int(a.get("amount") or -3), 50))
            pos = {}
            if a.get("x") is not None and a.get("y") is not None:
                x, y = self.to_screen(a["x"], a["y"])
                pos = {"x": x, "y": y}
            self._run("scroll", {"amount": amount, "x": pos.get("x"), "y": pos.get("y")})
            return self._after(f"scrolled {amount}", f"Scrolled {'up' if amount > 0 else 'down'} {abs(amount)}")
        raise ComputerError(f"unknown computer action {action}")

    @staticmethod
    def _title(a: dict) -> str:
        t = str(a.get("title") or "").strip()
        if not t:
            raise ComputerError("give (part of) the window title, from list_windows")
        return t[:200]

    def _after(self, text: str, summary: str) -> dict:
        """After an action: a fresh screenshot for the person, and the active window for the model."""
        time.sleep(0.4)
        try:
            s = self.screenshot()
        except ComputerError:
            return {"text": text, "summary": summary}
        return {"text": f"Done: {text}. Active window now: {s['foreground'] or 'none'}. A new screenshot was "
                        "taken; use read_window to see the controls.", "summary": summary, "image": s["image"]}
