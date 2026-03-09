#!/usr/bin/env python3
"""
Lightweight vulnerability scanning wrapper for Kali Linux tools.

Reads targets from targets.txt, runs multiple scanners sequentially,
parses structured outputs where possible, and builds a consolidated HTML report.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import ipaddress
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Any, Optional
from urllib import parse, request
from urllib.parse import urlparse


ZAP_PORT = 8090
ZAP_START_TIMEOUT_SECONDS = 90
ZAP_BINARIES = ("zap.sh", "zaproxy", "owasp-zap")
TESTSSL_BINARIES = ("testssl.sh", "testssl")
NUCLEI_JSON_FLAG_CACHE: Optional[str] = None


def setup_logging(results_dir: Path) -> None:
    """Configure console + file logging."""
    results_dir.mkdir(parents=True, exist_ok=True)
    log_file = results_dir / "scan.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file, mode="a", encoding="utf-8"),
        ],
    )


def load_targets(targets_file: Path) -> list[str]:
    """Load targets from a text file, ignoring blanks and comments."""
    if not targets_file.exists():
        raise FileNotFoundError(f"Targets file not found: {targets_file}")
    targets: list[str] = []
    with targets_file.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


def normalize_target_input(raw_target: str) -> str:
    """
    Normalize common malformed target inputs into a scanner-friendly format.
    Examples:
    - hxxp://example.com -> http://example.com
    - www.example.com/path -> http://www.example.com/path
    - example.com:8443 -> http://example.com:8443
    """
    target = raw_target.strip()
    if not target:
        return target

    # Common safe normalization for red-team notes/copy-paste inputs.
    target = re.sub(r"^hxxps://", "https://", target, flags=re.IGNORECASE)
    target = re.sub(r"^hxxp://", "http://", target, flags=re.IGNORECASE)
    target = target.replace("\\", "/")

    # If no scheme but looks URL-ish (path, host:port, www), assume HTTP.
    if "://" not in target:
        looks_like_url = (
            target.startswith("www.")
            or "/" in target
            or bool(re.match(r"^[A-Za-z0-9.-]+:\d+($|/)", target))
        )
        if looks_like_url:
            target = f"http://{target}"

    # Clean duplicate slashes in path but keep scheme delimiter intact.
    if "://" in target:
        scheme, rest = target.split("://", 1)
        rest = re.sub(r"/{2,}", "/", rest)
        target = f"{scheme.lower()}://{rest}"

    return target


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def is_domain(value: str) -> bool:
    # Simple, practical domain check for automation purposes.
    domain_re = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$"
    )
    return bool(domain_re.match(value))


def normalize_web_target(target: str) -> Optional[str]:
    """Return a URL for web scanners when possible, else None."""
    if is_url(target):
        return target
    if is_domain(target) or is_ip(target):
        return f"http://{target}"
    return None


def normalize_ssl_target(target: str) -> Optional[str]:
    """Return host:port suitable for SSL-oriented tools."""
    if is_url(target):
        parsed = urlparse(target)
        host = parsed.hostname
        if not host:
            return None
        if parsed.port:
            port = parsed.port
        else:
            port = 443 if parsed.scheme == "https" else 443
        return f"{host}:{port}"
    if is_domain(target) or is_ip(target):
        return f"{target}:443"
    return None


def _web_target_identity(target: str) -> tuple[Optional[str], Optional[str], bool]:
    """
    Return identity tuple: (exact_host_port, host_only, has_explicit_port).
    exact_host_port falls back to default scheme ports when not explicitly set.
    """
    value = target.strip()
    if not value:
        return None, None, False

    if "://" not in value:
        value = f"http://{value}"

    try:
        parsed = urlparse(value)
    except Exception:
        return None, None, False

    host = (parsed.hostname or "").strip().lower()
    if not host:
        return None, None, False

    has_explicit_port = parsed.port is not None
    if parsed.port is not None:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = 80

    return f"{host}:{port}", host, has_explicit_port


def _httpx_probe_input(target: str) -> Optional[str]:
    """
    Convert a web target URL into host-style input for httpx:
    - host when no explicit port (lets httpx test both HTTP/HTTPS)
    - host:port when explicit port is provided
    """
    exact_key, host_key, has_explicit_port = _web_target_identity(target)
    if not host_key:
        return None
    if not has_explicit_port:
        return host_key
    if not exact_key:
        return host_key
    _, port = exact_key.rsplit(":", 1)
    return f"{host_key}:{port}"


def sanitize_target(target: str) -> str:
    parsed = urlparse(target)
    base = parsed.netloc + parsed.path if parsed.netloc else target
    base = base.strip().strip("/")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    safe = safe.strip("._-") or "target"
    return safe[:100]


def target_for_nmap(target: str) -> str:
    """Nmap expects a host/IP, not a URL."""
    if is_url(target):
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


def tool_exists(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def resolve_tool(candidates: tuple[str, ...]) -> Optional[str]:
    for candidate in candidates:
        if tool_exists(candidate):
            return candidate
    return None


def resolve_nuclei_json_flag() -> str:
    global NUCLEI_JSON_FLAG_CACHE
    if NUCLEI_JSON_FLAG_CACHE:
        return NUCLEI_JSON_FLAG_CACHE

    proc = run_command(["nuclei", "-h"], "Nuclei help", timeout=20)
    help_text = ""
    if proc:
        help_text = f"{proc.stdout or ''}\n{proc.stderr or ''}".lower()

    if "-jsonl" in help_text or " -j," in help_text:
        NUCLEI_JSON_FLAG_CACHE = "-j"
    elif "-json " in help_text:
        NUCLEI_JSON_FLAG_CACHE = "-json"
    else:
        NUCLEI_JSON_FLAG_CACHE = "-j"
    return NUCLEI_JSON_FLAG_CACHE


def resolve_httpx_path(httpx_bin: str) -> Optional[str]:
    # Prefer the explicit binary if it is ProjectDiscovery httpx.
    candidate = shutil.which(httpx_bin) if os.sep not in httpx_bin else httpx_bin
    pd_httpx = str(Path("/root/go/bin/httpx"))
    if candidate:
        version_cmd = [candidate, "-version"]
        try:
            result = subprocess.run(
                version_cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            version_text = f"{result.stdout}\n{result.stderr}".lower()
            if "projectdiscovery" in version_text or "current version" in version_text:
                return candidate
        except Exception:
            pass

    # If PATH contains a conflicting httpx, use the common Go install location.
    if Path(pd_httpx).is_file():
        return pd_httpx
    return candidate


def filter_live_web_targets(
    web_targets: list[str],
    results_dir: Path,
    httpx_bin: str,
    live_check_timeout: int,
    threads: int,
    timeout: int,
    retries: int,
) -> set[str]:
    if not web_targets:
        return set()

    httpx_path = resolve_httpx_path(httpx_bin)
    if not httpx_path:
        logging.warning("httpx binary not found (%s). Skipping live precheck.", httpx_bin)
        return set(web_targets)

    input_file = results_dir / "httpx_live_input.txt"
    output_file = results_dir / "httpx_live_output.txt"
    target_identities: dict[str, tuple[Optional[str], Optional[str], bool]] = {
        target: _web_target_identity(target) for target in web_targets
    }
    probe_inputs = sorted({
        probe
        for target in web_targets
        for probe in [_httpx_probe_input(target)]
        if probe
    })
    if not probe_inputs:
        logging.warning("No valid web targets for httpx precheck. Falling back to all web targets.")
        return set(web_targets)

    input_file.write_text("\n".join(probe_inputs) + "\n", encoding="utf-8")

    cmd = [
        httpx_path,
        "-silent",
        "-l",
        str(input_file),
        "-o",
        str(output_file),
        "-threads",
        str(max(1, threads)),
        "-timeout",
        str(max(1, timeout)),
        "-retries",
        str(max(0, retries)),
    ]
    logging.info("[*] Filtering live web targets with httpx (%s input)", len(probe_inputs))
    proc = run_command(cmd, "httpx live filter", timeout=max(1, live_check_timeout))
    if not proc or proc.returncode != 0:
        details = ""
        if proc:
            details = (proc.stderr or "").strip() or (proc.stdout or "").strip()
        logging.warning(
            "httpx live precheck failed (rc=%s). Falling back to all web targets. %s",
            proc.returncode if proc else "n/a",
            details,
        )
        return set(web_targets)

    if not output_file.exists():
        logging.warning("httpx live precheck produced no output file. Falling back to all web targets.")
        return set(web_targets)

    live_exact_keys: set[str] = set()
    live_host_keys: set[str] = set()
    for line in output_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        exact_key, host_key, _ = _web_target_identity(line)
        if exact_key:
            live_exact_keys.add(exact_key)
        if host_key:
            live_host_keys.add(host_key)

    live_targets: set[str] = set()
    for target, (exact_key, host_key, has_explicit_port) in target_identities.items():
        if has_explicit_port:
            if exact_key and exact_key in live_exact_keys:
                live_targets.add(target)
        else:
            if (exact_key and exact_key in live_exact_keys) or (host_key and host_key in live_host_keys):
                live_targets.add(target)

    if not live_targets:
        logging.warning("httpx found no live web targets. Web scanners will be skipped.")
    else:
        logging.info("[*] Live web targets: %s/%s", len(live_targets), len(web_targets))
    return live_targets


def run_command(
    cmd: list[str],
    tool_name: str,
    timeout: int = 3600,
) -> Optional[subprocess.CompletedProcess[str]]:
    """Run command safely and return CompletedProcess, even on nonzero exit."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        logging.error("%s not found in PATH. Skipping.", tool_name)
    except subprocess.TimeoutExpired:
        logging.error("%s timed out after %s seconds.", tool_name, timeout)
    except Exception as exc:
        logging.error("Unexpected error running %s: %s", tool_name, exc)
    return None


def run_nmap(
    target: str,
    results_dir: Path,
    safe_target: str,
    nmap_timeout: int,
    nmap_host_timeout: str,
) -> Optional[Path]:
    logging.info("[+] Running Nmap")
    if not tool_exists("nmap"):
        logging.error("nmap is not installed.")
        return None
    out_file = results_dir / f"nmap_{safe_target}.xml"
    cmd = [
        "nmap",
        "-sV",
        "-Pn",
        "--script",
        "vuln",
        "--host-timeout",
        nmap_host_timeout,
        target,
        "-oX",
        str(out_file),
    ]
    proc = run_command(cmd, "Nmap", timeout=max(1, nmap_timeout))
    if not proc:
        return None
    if proc.returncode != 0:
        logging.warning("Nmap exited with code %s: %s", proc.returncode, proc.stderr.strip())
    return out_file if out_file.exists() else None


def run_nuclei(target: str, results_dir: Path, safe_target: str, args: argparse.Namespace) -> Optional[Path]:
    logging.info("[+] Running Nuclei")
    if not tool_exists("nuclei"):
        logging.error("nuclei is not installed.")
        return None
    out_file = results_dir / f"nuclei_{safe_target}.jsonl"
    json_flag = resolve_nuclei_json_flag()
    cmd = [
        "nuclei",
        "-u",
        target,
        json_flag,
        "-silent",
        "-stats",
        "-as",
        "-severity",
        args.nuclei_severity,
        "-retries",
        str(max(0, args.nuclei_retries)),
        "-timeout",
        str(max(1, args.nuclei_request_timeout)),
        "-c",
        str(max(1, args.nuclei_concurrency)),
        "-bulk-size",
        str(max(1, args.nuclei_bulk_size)),
        "-rl",
        str(max(1, args.nuclei_rate_limit)),
        "-o",
        str(out_file),
    ]
    if args.nuclei_resolvers:
        cmd.extend(["-r", str(Path(args.nuclei_resolvers).expanduser().resolve())])
    if args.nuclei_extra_args.strip():
        cmd.extend(shlex.split(args.nuclei_extra_args))
    proc = run_command(cmd, "Nuclei")
    if not proc:
        return None
    if proc.returncode != 0:
        details = (proc.stderr or "").strip() or (proc.stdout or "").strip() or "no output"
        logging.warning("Nuclei exited with code %s: %s", proc.returncode, details)
    return out_file if out_file.exists() else None


def run_nikto(target: str, results_dir: Path, safe_target: str) -> Optional[Path]:
    logging.info("[+] Running Nikto")
    if not tool_exists("nikto"):
        logging.error("nikto is not installed.")
        return None
    out_file = results_dir / f"nikto_{safe_target}.txt"
    cmd = ["nikto", "-h", target, "-output", str(out_file)]
    proc = run_command(cmd, "Nikto")
    if not proc:
        return None
    if proc.returncode != 0:
        logging.warning("Nikto exited with code %s: %s", proc.returncode, proc.stderr.strip())
    return out_file if out_file.exists() else None


def run_wapiti(target: str, results_dir: Path, safe_target: str) -> Optional[Path]:
    logging.info("[+] Running Wapiti")
    if not tool_exists("wapiti"):
        logging.error("wapiti is not installed.")
        return None
    out_dir = results_dir / f"wapiti_{safe_target}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "wapiti_report.json"
    cmd = ["wapiti", "-u", target, "-f", "json", "-o", str(out_file)]
    proc = run_command(cmd, "Wapiti")
    if not proc:
        return None
    if proc.returncode != 0:
        logging.warning("Wapiti exited with code %s: %s", proc.returncode, proc.stderr.strip())
    return out_file if out_file.exists() else None


def wait_for_zap() -> bool:
    deadline = time.time() + ZAP_START_TIMEOUT_SECONDS
    while time.time() < deadline:
        data = zap_api("core/view/version/", timeout=10)
        if isinstance(data, dict) and data.get("version"):
            return True
        time.sleep(3)
    return False


def zap_api(endpoint: str, params: Optional[dict[str, Any]] = None, timeout: int = 60) -> Optional[dict[str, Any]]:
    query = parse.urlencode({k: str(v) for k, v in (params or {}).items() if v is not None})
    url = f"http://127.0.0.1:{ZAP_PORT}/JSON/{endpoint}"
    if query:
        url = f"{url}?{query}"
    try:
        with request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except Exception as exc:
        logging.debug("ZAP API call failed (%s): %s", endpoint, exc)
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logging.debug("ZAP API returned non-JSON for %s", endpoint)
        return None
    if isinstance(data, dict):
        return data
    return None


def zap_wait_for_percent(endpoint: str, key: str, scan_id: str, timeout: int) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = zap_api(endpoint, {"scanId": scan_id}, timeout=20)
        if not isinstance(data, dict):
            time.sleep(2)
            continue
        try:
            progress = int(str(data.get(key, "0")))
        except ValueError:
            progress = 0
        if progress >= 100:
            return True
        time.sleep(2)
    return False


def ensure_zap_daemon() -> bool:
    zap_bin = resolve_tool(ZAP_BINARIES)
    if not zap_bin:
        logging.error("OWASP ZAP binary is not installed (tried: %s).", ", ".join(ZAP_BINARIES))
        return False

    # If already running, reuse it.
    if zap_api("core/view/version/", timeout=10):
        return True

    logging.info("[+] Starting OWASP ZAP daemon")
    try:
        subprocess.Popen(
            [
                zap_bin,
                "-daemon",
                "-port",
                str(ZAP_PORT),
                "-host",
                "127.0.0.1",
                "-config",
                "api.disablekey=true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        logging.error("Failed to start ZAP daemon: %s", exc)
        return False

    if not wait_for_zap():
        logging.error("ZAP daemon did not become ready in time.")
        return False
    return True


def run_zap(target: str, results_dir: Path, safe_target: str) -> Optional[Path]:
    logging.info("[+] Running OWASP ZAP Spider")
    if not ensure_zap_daemon():
        return None

    spider_start = zap_api(
        "spider/action/scan/",
        {"url": target, "maxChildren": 0, "recurse": "true"},
        timeout=30,
    )
    if not spider_start or "scan" not in spider_start:
        logging.error("Failed to start ZAP spider for %s", target)
        return None
    spider_id = str(spider_start["scan"])
    if not zap_wait_for_percent("spider/view/status/", "status", spider_id, timeout=1800):
        logging.warning("ZAP spider did not complete in time for %s", target)

    logging.info("[+] Running OWASP ZAP Active Scan")
    active_start = zap_api(
        "ascan/action/scan/",
        {"url": target, "recurse": "true", "inScopeOnly": "false"},
        timeout=30,
    )
    if not active_start or "scan" not in active_start:
        logging.error("Failed to start ZAP active scan for %s", target)
        return None
    active_id = str(active_start["scan"])
    if not zap_wait_for_percent("ascan/view/status/", "status", active_id, timeout=3600):
        logging.warning("ZAP active scan did not complete in time for %s", target)

    out_file = results_dir / f"zap_{safe_target}.json"

    alerts = zap_api("core/view/alerts/", {"baseurl": target, "start": 0, "count": 9999}, timeout=120)
    if not alerts:
        logging.error("Failed to fetch ZAP alerts for %s", target)
        return None
    out_file.write_text(json.dumps(alerts), encoding="utf-8")
    return out_file if out_file.exists() else None


def run_sslscan(target: str, results_dir: Path, safe_target: str) -> Optional[Path]:
    logging.info("[+] Running SSLScan")
    if not tool_exists("sslscan"):
        logging.error("sslscan is not installed.")
        return None
    out_file = results_dir / f"sslscan_{safe_target}.txt"
    proc = run_command(["sslscan", target], "SSLScan", timeout=1800)
    if not proc:
        return None
    out_file.write_text(proc.stdout or "", encoding="utf-8")
    if proc.returncode != 0:
        logging.warning("SSLScan exited with code %s: %s", proc.returncode, proc.stderr.strip())
    return out_file


def run_testssl(target: str, results_dir: Path, safe_target: str) -> Optional[Path]:
    logging.info("[+] Running testssl.sh")
    testssl_bin = resolve_tool(TESTSSL_BINARIES)
    if not testssl_bin:
        logging.error("testssl.sh is not installed (tried: %s).", ", ".join(TESTSSL_BINARIES))
        return None
    out_file = results_dir / f"testssl_{safe_target}.txt"
    proc = run_command([testssl_bin, target], "testssl.sh", timeout=3600)
    if not proc:
        return None
    out_file.write_text(proc.stdout or "", encoding="utf-8")
    if proc.returncode != 0:
        logging.warning("testssl.sh exited with code %s: %s", proc.returncode, proc.stderr.strip())
    return out_file


class StatusTracker:
    """Thread-safe progress tracker with periodic heartbeat logging."""

    def __init__(self, total_targets: int, total_tools: int, interval_seconds: int = 10) -> None:
        self.total_targets = total_targets
        self.total_tools = total_tools
        self.interval_seconds = interval_seconds
        self.completed_tools = 0
        self.active_tools: dict[str, tuple[str, float]] = {}
        self.current_target_idx = 0
        self.current_target = "-"
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._heartbeat_loop, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)

    def set_target(self, idx: int, target: str) -> None:
        with self.lock:
            self.current_target_idx = idx
            self.current_target = target

    def mark_start(self, target: str, tool: str) -> None:
        with self.lock:
            self.active_tools[f"{target}|{tool}"] = (f"{tool}@{target}", time.time())
        logging.info("[+] Running %s for %s", tool, target)

    def mark_end(self, target: str, tool: str) -> None:
        with self.lock:
            self.active_tools.pop(f"{target}|{tool}", None)
            self.completed_tools += 1

    def _heartbeat_loop(self) -> None:
        while not self.stop_event.wait(self.interval_seconds):
            with self.lock:
                active = list(self.active_tools.values())
                completed = self.completed_tools
                cur_idx = self.current_target_idx
                cur_target = self.current_target
            active_labels: list[str] = []
            now = time.time()
            for label, started_at in active:
                elapsed_s = max(0, int(now - started_at))
                elapsed_min, elapsed_sec = divmod(elapsed_s, 60)
                active_labels.append(f"{label}({elapsed_min}m{elapsed_sec:02d}s)")
            active_str = ", ".join(active_labels[:6]) if active_labels else "none"
            if len(active) > 6:
                active_str += f", +{len(active) - 6} more"
            logging.info(
                "[*] Status: target %s/%s (%s), tools %s/%s complete, active: %s",
                cur_idx,
                self.total_targets,
                cur_target,
                completed,
                self.total_tools,
                active_str,
            )


def run_tool_task(
    tool_key: str,
    target: str,
    tracker: StatusTracker,
    func: Any,
    *args: Any,
) -> Optional[Path]:
    tracker.mark_start(target, tool_key)
    try:
        return func(*args)
    finally:
        tracker.mark_end(target, tool_key)


def build_tool_plan(target: str) -> tuple[str, Optional[str], Optional[str], list[str]]:
    """
    Return (safe_target, web_target, ssl_target, tools_to_run) for a target.
    Tools list contains keys used in scan_artifacts.
    """
    safe_target = sanitize_target(target)
    web_target = normalize_web_target(target)
    ssl_target = normalize_ssl_target(target)
    tools = ["nmap", "nuclei"]
    if web_target:
        tools.extend(["nikto", "wapiti", "zap", "sslscan", "testssl"])
    return safe_target, web_target, ssl_target, tools


def severity_normalize(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "Info"
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
        "informational": "Info",
    }
    for key, out in mapping.items():
        if key in text:
            return out
    return text.capitalize()


def text_or_empty(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip()


def first_nonempty(*values: Any) -> str:
    for value in values:
        text = text_or_empty(value)
        if text:
            return text
    return ""


def parse_nuclei(path: Path, target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not path.exists():
        return findings
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {}) or {}
            findings.append(
                {
                    "target": target,
                    "tool": "Nuclei",
                    "vulnerability": str(info.get("name") or obj.get("template-id") or "Unknown"),
                    "severity": severity_normalize(info.get("severity")),
                    "description": str(
                        info.get("description")
                        or obj.get("matched-at")
                        or obj.get("matcher-name")
                        or "No description"
                    ),
                    "endpoint": first_nonempty(obj.get("matched-at"), obj.get("host"), obj.get("url"), target),
                    "payload": first_nonempty(obj.get("curl-command"), obj.get("extracted-results")),
                    "evidence": first_nonempty(obj.get("matcher-name"), obj.get("extracted-results")),
                    "request_raw": text_or_empty(obj.get("request")),
                    "response_raw": text_or_empty(obj.get("response")),
                    "source": "Nuclei",
                }
            )
    return findings


def parse_nmap(path: Path, target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not path.exists():
        return findings
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError:
        return findings

    # Pull vulnerability scripts from hostscript and per-port scripts.
    script_nodes = root.findall(".//hostscript/script") + root.findall(".//port/script")
    for script in script_nodes:
        vuln_name = script.attrib.get("id", "nmap-script")
        output = script.attrib.get("output", "No output")
        sev_match = re.search(r"\b(critical|high|medium|low|info)\b", output, re.IGNORECASE)
        severity = severity_normalize(sev_match.group(1) if sev_match else "Info")
        findings.append(
            {
                "target": target,
                "tool": "Nmap",
                "vulnerability": vuln_name,
                "severity": severity,
                "description": output,
                "endpoint": target,
                "payload": "",
                "evidence": "",
                "request_raw": "",
                "response_raw": "",
                "source": "Nmap",
            }
        )
    return findings


def parse_wapiti(path: Path, target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not path.exists():
        return findings
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return findings

    vulns = data.get("vulnerabilities", {})
    if isinstance(vulns, dict):
        for category, entries in vulns.items():
            if not isinstance(entries, list):
                continue
            for item in entries:
                if not isinstance(item, dict):
                    continue
                details = item.get("info") or item.get("parameter") or item.get("module") or "No description"
                endpoint = first_nonempty(item.get("path"), item.get("url"), item.get("request"), target)
                payload = first_nonempty(item.get("payload"), item.get("evil_request"), item.get("parameter"))
                evidence = first_nonempty(item.get("info"), item.get("module"), item.get("http_request"))
                findings.append(
                    {
                        "target": target,
                        "tool": "Wapiti",
                        "vulnerability": str(category),
                        "severity": severity_normalize(item.get("level") or item.get("severity") or "Medium"),
                        "description": str(details),
                        "endpoint": endpoint,
                        "payload": payload,
                        "evidence": evidence,
                        "request_raw": text_or_empty(item.get("http_request") or item.get("request")),
                        "response_raw": text_or_empty(item.get("http_response") or item.get("response")),
                        "source": "Wapiti",
                    }
                )
    return findings


def parse_zap(path: Path, target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not path.exists():
        return findings

    raw = path.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return findings

    alert_items: list[dict[str, Any]] = []
    if isinstance(data, list):
        alert_items = [x for x in data if isinstance(x, dict)]
    elif isinstance(data, dict):
        if isinstance(data.get("alerts"), list):
            alert_items = [x for x in data["alerts"] if isinstance(x, dict)]
        elif isinstance(data.get("site"), list):
            for site in data["site"]:
                if isinstance(site, dict) and isinstance(site.get("alerts"), list):
                    alert_items.extend([x for x in site["alerts"] if isinstance(x, dict)])

    for alert in alert_items:
        endpoint = first_nonempty(alert.get("url"), target)
        payload = first_nonempty(alert.get("attack"))
        evidence = first_nonempty(alert.get("evidence"), alert.get("param"), alert.get("other"))
        request_raw = ""
        response_raw = ""
        instances = alert.get("instances")
        if isinstance(instances, list) and instances:
            first_instance = instances[0] if isinstance(instances[0], dict) else {}
            endpoint = first_nonempty(first_instance.get("uri"), endpoint)
            payload = first_nonempty(first_instance.get("attack"), payload)
            evidence = first_nonempty(first_instance.get("evidence"), evidence)
            request_raw = text_or_empty(first_instance.get("request"))
            response_raw = text_or_empty(first_instance.get("response"))
        findings.append(
            {
                "target": target,
                "tool": "OWASP ZAP",
                "vulnerability": str(alert.get("alert") or alert.get("name") or "Unknown Alert"),
                "severity": severity_normalize(alert.get("risk") or alert.get("riskdesc") or "Info"),
                "description": str(alert.get("description") or alert.get("url") or "No description"),
                "endpoint": endpoint,
                "payload": payload,
                "evidence": evidence,
                "request_raw": request_raw,
                "response_raw": response_raw,
                "source": "OWASP ZAP",
            }
        )
    return findings


def parse_results(scan_artifacts: dict[str, dict[str, Optional[Path]]]) -> list[dict[str, Any]]:
    all_findings: list[dict[str, Any]] = []
    for target, artifacts in scan_artifacts.items():
        nmap_path = artifacts.get("nmap")
        nuclei_path = artifacts.get("nuclei")
        wapiti_path = artifacts.get("wapiti")
        zap_path = artifacts.get("zap")

        if nmap_path:
            all_findings.extend(parse_nmap(nmap_path, target))
        if nuclei_path:
            all_findings.extend(parse_nuclei(nuclei_path, target))
        if wapiti_path:
            all_findings.extend(parse_wapiti(wapiti_path, target))
        if zap_path:
            all_findings.extend(parse_zap(zap_path, target))

    return all_findings


def generate_report(
    findings: list[dict[str, Any]],
    targets: list[str],
    report_path: Path,
) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)

    sev_counter = Counter(item["severity"] for item in findings)
    target_counter = Counter(item["target"] for item in findings)
    for t in targets:
        target_counter.setdefault(t, 0)

    rows = []
    for item in findings:
        endpoint = html.escape(str(item.get("endpoint") or ""))
        payload = html.escape(str(item.get("payload") or ""))
        evidence = html.escape(str(item.get("evidence") or ""))
        request_raw = str(item.get("request_raw") or "").strip()
        response_raw = str(item.get("response_raw") or "").strip()
        extra = ""
        if request_raw or response_raw:
            req_html = html.escape(request_raw) if request_raw else "N/A"
            resp_html = html.escape(response_raw) if response_raw else "N/A"
            extra = (
                "<details><summary>Raw Request/Response</summary>"
                f"<div><strong>Request</strong><pre>{req_html}</pre></div>"
                f"<div><strong>Response</strong><pre>{resp_html}</pre></div>"
                "</details>"
            )
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['target'])}</td>"
            f"<td>{html.escape(item['tool'])}</td>"
            f"<td>{html.escape(item['vulnerability'])}</td>"
            f"<td>{html.escape(item['severity'])}</td>"
            f"<td>{html.escape(item['description'])}</td>"
            f"<td>{endpoint}</td>"
            f"<td>{payload}</td>"
            f"<td>{evidence}{extra}</td>"
            f"<td>{html.escape(item['source'])}</td>"
            "</tr>"
        )

    sev_list = "".join(
        f"<li>{html.escape(sev)}: {count}</li>"
        for sev, count in sorted(sev_counter.items(), key=lambda x: x[0])
    )
    target_list = "".join(
        f"<li>{html.escape(t)}: {count}</li>"
        for t, count in sorted(target_counter.items(), key=lambda x: x[0])
    )
    table_rows = "".join(rows) or (
        "<tr><td colspan='9'>No parsed vulnerabilities found (or structured outputs unavailable).</td></tr>"
    )

    generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vulnerability Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #1f2937; }}
    h1, h2 {{ margin-bottom: 0.4rem; }}
    .meta {{ color: #4b5563; margin-bottom: 16px; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .filters {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-bottom: 14px; }}
    .filters label {{ display: flex; flex-direction: column; font-size: 13px; color: #374151; gap: 4px; }}
    .filters input, .filters select {{ padding: 6px 8px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 14px; }}
    .card {{ border: 1px solid #d1d5db; border-radius: 8px; padding: 12px 16px; background: #f9fafb; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border: 1px solid #d1d5db; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    tr:nth-child(even) {{ background: #fafafa; }}
    code {{ background: #f3f4f6; padding: 2px 4px; border-radius: 4px; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #f9fafb; padding: 8px; border: 1px solid #e5e7eb; border-radius: 6px; }}
    details {{ margin-top: 8px; }}
  </style>
</head>
<body>
  <h1>Consolidated Vulnerability Report</h1>
  <p class="meta">Generated at: {generated_at}</p>

  <div class="summary">
    <div class="card">
      <h2>Total Vulnerabilities</h2>
      <p><strong>{len(findings)}</strong></p>
    </div>
    <div class="card">
      <h2>By Severity</h2>
      <ul>{sev_list or "<li>None</li>"}</ul>
    </div>
    <div class="card">
      <h2>By Target</h2>
      <ul>{target_list or "<li>None</li>"}</ul>
    </div>
  </div>

  <h2>Detailed Findings</h2>
  <div class="filters">
    <label>Target
      <input id="filter-target" type="text" placeholder="e.g. testphp.vulnweb.com">
    </label>
    <label>Tool Used
      <input id="filter-tool" type="text" placeholder="e.g. Nuclei">
    </label>
    <label>Vulnerability Name
      <input id="filter-vuln" type="text" placeholder="name contains...">
    </label>
    <label>Severity
      <select id="filter-severity">
        <option value="">All</option>
        <option>Critical</option>
        <option>High</option>
        <option>Medium</option>
        <option>Low</option>
        <option>Info</option>
      </select>
    </label>
    <label>Description
      <input id="filter-desc" type="text" placeholder="description contains...">
    </label>
    <label>Source Tool
      <input id="filter-source" type="text" placeholder="e.g. OWASP ZAP">
    </label>
  </div>
  <table>
    <thead>
      <tr>
        <th>Target</th>
        <th>Tool Used</th>
        <th>Vulnerability Name</th>
        <th>Severity</th>
        <th>Description</th>
        <th>Endpoint</th>
        <th>Payload</th>
        <th>Evidence</th>
        <th>Source Tool</th>
      </tr>
    </thead>
    <tbody>
      {table_rows}
    </tbody>
  </table>
  <script>
    (function() {{
      const table = document.querySelector("table");
      if (!table) return;
      const rows = Array.from(table.querySelectorAll("tbody tr"));
      const targetEl = document.getElementById("filter-target");
      const toolEl = document.getElementById("filter-tool");
      const vulnEl = document.getElementById("filter-vuln");
      const sevEl = document.getElementById("filter-severity");
      const descEl = document.getElementById("filter-desc");
      const sourceEl = document.getElementById("filter-source");

      function normalize(v) {{
        return (v || "").toLowerCase().trim();
      }}

      function applyFilters() {{
        const fTarget = normalize(targetEl.value);
        const fTool = normalize(toolEl.value);
        const fVuln = normalize(vulnEl.value);
        const fSev = normalize(sevEl.value);
        const fDesc = normalize(descEl.value);
        const fSource = normalize(sourceEl.value);

        for (const row of rows) {{
          const cells = row.querySelectorAll("td");
          if (cells.length < 9) continue;
          const target = normalize(cells[0].innerText);
          const tool = normalize(cells[1].innerText);
          const vuln = normalize(cells[2].innerText);
          const sev = normalize(cells[3].innerText);
          const desc = normalize(cells[4].innerText);
          const source = normalize(cells[8].innerText);

          const visible =
            (!fTarget || target.includes(fTarget)) &&
            (!fTool || tool.includes(fTool)) &&
            (!fVuln || vuln.includes(fVuln)) &&
            (!fSev || sev === fSev) &&
            (!fDesc || desc.includes(fDesc)) &&
            (!fSource || source.includes(fSource));
          row.style.display = visible ? "" : "none";
        }}
      }}

      [targetEl, toolEl, vulnEl, sevEl, descEl, sourceEl].forEach((el) => {{
        el.addEventListener("input", applyFilters);
        el.addEventListener("change", applyFilters);
      }});
    }})();
  </script>
</body>
</html>"""
    report_path.write_text(html_doc, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automate vulnerability scanning for multiple targets with Kali tools."
    )
    parser.add_argument("--targets-file", default="targets.txt", help="Path to targets file")
    parser.add_argument("--results-dir", default="results", help="Directory for raw scanner outputs")
    parser.add_argument("--reports-dir", default="reports", help="Directory for generated reports")
    parser.add_argument(
        "--max-parallel-tools",
        type=int,
        default=4,
        help="Max number of scanner tools to run in parallel per target",
    )
    parser.add_argument(
        "--status-interval",
        type=int,
        default=10,
        help="Heartbeat status interval in seconds",
    )
    parser.add_argument(
        "--nmap-timeout",
        type=int,
        default=1800,
        help="Hard timeout (seconds) for each nmap process",
    )
    parser.add_argument(
        "--nmap-host-timeout",
        default="15m",
        help='nmap --host-timeout value (e.g. "10m", "1800s")',
    )
    parser.add_argument("--httpx-bin", default="httpx", help="Path or name of httpx binary")
    parser.add_argument(
        "--live-check-timeout",
        type=int,
        default=900,
        help="Hard timeout (seconds) for httpx live web-target precheck",
    )
    parser.add_argument(
        "--httpx-threads",
        type=int,
        default=200,
        help="httpx threads for live target precheck",
    )
    parser.add_argument(
        "--httpx-timeout",
        type=int,
        default=5,
        help="httpx per-request timeout in seconds",
    )
    parser.add_argument(
        "--httpx-retries",
        type=int,
        default=1,
        help="httpx retries per target",
    )
    parser.add_argument(
        "--nuclei-severity",
        default="info,low,medium,high,critical",
        help="Nuclei template severity filter (comma-separated)",
    )
    parser.add_argument(
        "--nuclei-concurrency",
        type=int,
        default=100,
        help="Nuclei -c value",
    )
    parser.add_argument(
        "--nuclei-bulk-size",
        type=int,
        default=50,
        help="Nuclei -bulk-size value",
    )
    parser.add_argument(
        "--nuclei-rate-limit",
        type=int,
        default=400,
        help="Nuclei -rl value",
    )
    parser.add_argument(
        "--nuclei-request-timeout",
        type=int,
        default=5,
        help="Nuclei -timeout value",
    )
    parser.add_argument(
        "--nuclei-retries",
        type=int,
        default=1,
        help="Nuclei -retries value",
    )
    parser.add_argument(
        "--nuclei-resolvers",
        default="",
        help="Optional resolvers file passed to nuclei (-r)",
    )
    parser.add_argument(
        "--nuclei-extra-args",
        default="",
        help='Extra raw nuclei args, e.g. "--nuclei-extra-args \'-headless -duc\'"',
    )
    args = parser.parse_args()

    targets_file = Path(args.targets_file)
    results_dir = Path(args.results_dir)
    reports_dir = Path(args.reports_dir)

    results_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(results_dir)

    try:
        targets = load_targets(targets_file)
    except Exception as exc:
        logging.error("Failed to load targets: %s", exc)
        return

    if not targets:
        logging.error("No targets found in %s", targets_file)
        return

    scan_artifacts: dict[str, dict[str, Optional[Path]]] = defaultdict(dict)
    target_plans: dict[str, tuple[str, Optional[str], Optional[str], list[str]]] = {}
    valid_targets: list[str] = []

    for target in targets:
        normalized_target = normalize_target_input(target)
        if normalized_target != target:
            logging.info("[*] Normalized target: %s -> %s", target, normalized_target)

        if not (is_url(normalized_target) or is_domain(normalized_target) or is_ip(normalized_target)):
            logging.warning("Target %s is not a valid domain/IP/URL after normalization. Skipping.", target)
            continue
        plan = build_tool_plan(normalized_target)
        target_plans[normalized_target] = plan
        valid_targets.append(normalized_target)

    if not valid_targets:
        logging.error("No valid targets to scan.")
        return

    all_web_targets = [
        plan[1]
        for plan in target_plans.values()
        if plan[1]
    ]
    live_web_targets = filter_live_web_targets(
        sorted(set(all_web_targets)),
        results_dir=results_dir,
        httpx_bin=args.httpx_bin,
        live_check_timeout=args.live_check_timeout,
        threads=args.httpx_threads,
        timeout=args.httpx_timeout,
        retries=args.httpx_retries,
    )

    total_tools = 0
    for target in valid_targets:
        _, web_target, ssl_target, _ = target_plans[target]
        # nmap always runs.
        per_target = 1
        if web_target and web_target in live_web_targets:
            # nuclei, nikto, wapiti, zap
            per_target += 4
            if ssl_target:
                # sslscan, testssl
                per_target += 2
        total_tools += per_target

    tracker = StatusTracker(
        total_targets=len(valid_targets),
        total_tools=total_tools,
        interval_seconds=max(3, args.status_interval),
    )
    tracker.start()

    try:
        # Targets remain sequential; tools inside each target run in parallel when independent.
        for idx, target in enumerate(valid_targets, start=1):
            logging.info("[+] Starting scan for %s", target)
            tracker.set_target(idx, target)
            safe_target, web_target, ssl_target, _ = target_plans[target]

            jobs: dict[str, Any] = {
                "nmap": partial(
                    run_nmap,
                    target_for_nmap(target),
                    results_dir,
                    safe_target,
                    args.nmap_timeout,
                    args.nmap_host_timeout,
                ),
            }
            if web_target and web_target in live_web_targets:
                jobs["nuclei"] = partial(run_nuclei, web_target, results_dir, safe_target, args)
                jobs.update(
                    {
                        "nikto": partial(run_nikto, web_target, results_dir, safe_target),
                        "wapiti": partial(run_wapiti, web_target, results_dir, safe_target),
                        # ZAP spider + active-scan + alerts remain ordered inside run_zap.
                        "zap": partial(run_zap, web_target, results_dir, safe_target),
                    }
                )
            else:
                if web_target and web_target not in live_web_targets:
                    logging.info("[-] Skipping web scanners for non-live target: %s", web_target)
                else:
                    logging.info("[-] Skipping web scanners for non-web target: %s", target)

            if web_target and ssl_target and web_target in live_web_targets:
                jobs.update(
                    {
                        "sslscan": partial(run_sslscan, ssl_target, results_dir, safe_target),
                        "testssl": partial(run_testssl, ssl_target, results_dir, safe_target),
                    }
                )
            else:
                if web_target and web_target not in live_web_targets:
                    logging.info("[-] Skipping SSL scanners for non-live target: %s", web_target)
                else:
                    logging.info("[-] Skipping SSLScan/testssl for non-web target: %s", target)

            logging.info(
                "[*] Planned tools for %s: %s",
                target,
                ", ".join(jobs.keys()),
            )

            max_workers = max(1, min(args.max_parallel_tools, len(jobs)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(run_tool_task, key, target, tracker, job): key
                    for key, job in jobs.items()
                }
                for future in concurrent.futures.as_completed(futures):
                    key = futures[future]
                    try:
                        scan_artifacts[target][key] = future.result()
                    except Exception as exc:
                        logging.error("Unhandled error in %s for %s: %s", key, target, exc)
                        scan_artifacts[target][key] = None
    finally:
        tracker.stop()

    findings = parse_results(scan_artifacts)
    report_path = reports_dir / "vulnerability_report.html"
    generate_report(findings, targets, report_path)

    logging.info("[+] Scan completed.")
    logging.info("[+] Report generated: %s", report_path)


if __name__ == "__main__":
    main()
