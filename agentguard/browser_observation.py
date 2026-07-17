from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable

from .detectors import PromptInjectionDetector, SensitiveDataDetector


_MAX_HTML_CHARS = 1_048_576
_MAX_DOM_CHARS = 2_097_152
_MAX_SEGMENTS = 2_000
_MAX_SEGMENT_CHARS = 8_192


class BrowserRuntimeError(RuntimeError):
    """A browser lifecycle error without page-controlled diagnostic text."""


@dataclass(frozen=True)
class ObservationSegment:
    channel: str
    text: str


@dataclass(frozen=True)
class BrowserCapture:
    renderer: str
    source_sha256: str
    dom_sha256: str
    segments: tuple[ObservationSegment, ...]


@dataclass(frozen=True)
class GuardedObservationSegment:
    channel: str
    content: str | None
    content_sha256: str
    quarantined: bool
    signal_messages: tuple[str, ...]
    redactions: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "content": self.content,
            "content_sha256": self.content_sha256,
            "quarantined": self.quarantined,
            "signal_messages": list(self.signal_messages),
            "redactions": dict(self.redactions),
        }


@dataclass(frozen=True)
class GuardedBrowserObservation:
    source_sha256: str
    renderer: str
    segments: tuple[GuardedObservationSegment, ...]

    @property
    def safe_text(self) -> str:
        return "\n".join(
            segment.content
            for segment in self.segments
            if not segment.quarantined and segment.content
        )

    @property
    def quarantined_count(self) -> int:
        return sum(segment.quarantined for segment in self.segments)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_sha256": self.source_sha256,
            "renderer": self.renderer,
            "safe_text": self.safe_text,
            "quarantined_count": self.quarantined_count,
            "segments": [segment.to_dict() for segment in self.segments],
        }


class BrowserObservationGuard:
    """Sanitize DOM, accessibility, and OCR channels segment by segment."""

    def __init__(
        self,
        *,
        prompt_detector: PromptInjectionDetector | None = None,
        sensitive_detector: SensitiveDataDetector | None = None,
    ) -> None:
        self.prompt_detector = prompt_detector or PromptInjectionDetector()
        self.sensitive_detector = sensitive_detector or SensitiveDataDetector()

    def sanitize(self, capture: BrowserCapture) -> GuardedBrowserObservation:
        guarded: list[GuardedObservationSegment] = []
        for segment in capture.segments[:_MAX_SEGMENTS]:
            bounded = segment.text[:_MAX_SEGMENT_CHARS]
            redacted, counts = self.sensitive_detector.redact(bounded)
            safe_content = str(redacted)
            signals = self.prompt_detector.detect(safe_content)
            quarantined = bool(signals)
            guarded.append(
                GuardedObservationSegment(
                    channel=segment.channel,
                    content=None if quarantined else safe_content,
                    content_sha256=hashlib.sha256(bounded.encode("utf-8")).hexdigest(),
                    quarantined=quarantined,
                    signal_messages=tuple(sorted({signal.message for signal in signals})),
                    redactions=counts,
                )
            )
        return GuardedBrowserObservation(
            source_sha256=capture.source_sha256,
            renderer=capture.renderer,
            segments=tuple(guarded),
        )


class OfflineChromiumRenderer:
    """Render bounded HTML in a real Chromium process with networking disabled."""

    def __init__(
        self,
        executable: str | Path | None = None,
        *,
        timeout_seconds: float = 20.0,
    ) -> None:
        resolved = Path(executable).resolve() if executable else find_chromium_executable()
        if resolved is None or not resolved.is_file():
            raise BrowserRuntimeError("No supported Chromium executable was found")
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("browser timeout_seconds must be between 1 and 120")
        self.executable = resolved
        self.timeout_seconds = float(timeout_seconds)

    def render_html(
        self,
        html: str,
        *,
        source_label: str,
        ocr_texts: Iterable[str] = (),
    ) -> BrowserCapture:
        if not isinstance(html, str) or not html.strip():
            raise ValueError("browser HTML must be a non-empty string")
        if len(html) > _MAX_HTML_CHARS:
            raise ValueError("browser HTML exceeded the size limit")
        source_sha256 = hashlib.sha256(source_label.encode("utf-8")).hexdigest()
        with tempfile.TemporaryDirectory(prefix="agentguard-browser-") as temp_dir:
            root = Path(temp_dir)
            page = root / "page.html"
            page.write_text(html, encoding="utf-8")
            profile = root / "profile"
            command = [
                str(self.executable),
                "--headless",
                "--disable-gpu",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-sync",
                "--metrics-recording-only",
                "--mute-audio",
                "--no-default-browser-check",
                "--no-first-run",
                "--host-resolver-rules=MAP * ~NOTFOUND",
                f"--user-data-dir={profile}",
                "--dump-dom",
                page.as_uri(),
            ]
            creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            try:
                completed = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=self.timeout_seconds,
                    check=False,
                    creationflags=creationflags,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise BrowserRuntimeError(
                    f"Chromium rendering failed: {type(exc).__name__}"
                ) from None
            if completed.returncode != 0:
                stderr_digest = hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest()
                raise BrowserRuntimeError(
                    "Chromium rendering returned status "
                    f"{completed.returncode} (stderr_sha256={stderr_digest})"
                )
            dom = completed.stdout
        if len(dom) > _MAX_DOM_CHARS:
            raise BrowserRuntimeError("Chromium DOM output exceeded the size limit")
        parser = _SegmentParser()
        try:
            parser.feed(dom)
            parser.close()
        except Exception as exc:
            raise BrowserRuntimeError(f"Rendered DOM parsing failed: {type(exc).__name__}") from None
        segments = list(parser.segments)
        for value in ocr_texts:
            if not isinstance(value, str):
                raise ValueError("OCR observations must be strings")
            if value.strip():
                segments.append(ObservationSegment("image_ocr", value.strip()))
        return BrowserCapture(
            renderer="chromium_offline",
            source_sha256=source_sha256,
            dom_sha256=hashlib.sha256(dom.encode("utf-8")).hexdigest(),
            segments=tuple(segments[:_MAX_SEGMENTS]),
        )


def find_chromium_executable() -> Path | None:
    configured = os.environ.get("AGENTGUARD_CHROMIUM_PATH")
    runner_chrome = os.environ.get("CHROME_BIN")
    candidates = [value for value in (configured, runner_chrome) if value]
    for name in (
        "google-chrome",
        "google-chrome-stable",
        "chrome",
        "microsoft-edge",
        "msedge",
        "chromium",
        "chromium-browser",
    ):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    if os.name == "nt":
        program_files = [
            os.environ.get("PROGRAMFILES"),
            os.environ.get("PROGRAMFILES(X86)"),
            os.environ.get("LOCALAPPDATA"),
        ]
        suffixes = [
            Path("Google/Chrome/Application/chrome.exe"),
            Path("Microsoft/Edge/Application/msedge.exe"),
        ]
        for root in program_files:
            if root:
                candidates.extend(str(Path(root) / suffix) for suffix in suffixes)
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    return None


class _SegmentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.segments: list[ObservationSegment] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() in {"script", "style", "noscript"}:
            self._ignored_depth += 1
        for name, value in attrs:
            if (
                value
                and name.casefold() in {"alt", "aria-label", "title", "placeholder"}
                and len(self.segments) < _MAX_SEGMENTS
            ):
                self.segments.append(
                    ObservationSegment("accessibility", value.strip()[:_MAX_SEGMENT_CHARS])
                )

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if self._ignored_depth or not text or len(self.segments) >= _MAX_SEGMENTS:
            return
        self.segments.append(ObservationSegment("dom_text", text[:_MAX_SEGMENT_CHARS]))
