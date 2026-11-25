#!/usr/bin/env python3
"""AI Threat Detection: single-file, offline-capable network security dashboard.

The built-in lab produces labeled simulated telemetry only; it never sends
attack traffic. Live capture and PCAP analysis are passive.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import ipaddress
import json
import math
import os
import secrets
import socket
import sqlite3
import statistics
import string
import sys
import tempfile
import threading
import time
import unittest
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

import numpy as np
from flask import (
    Flask, Response, abort, jsonify, redirect, render_template_string, request,
    session, url_for,
)
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

try:
    from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, AsyncSniffer, get_if_addr, get_if_list, sniff
except Exception:
    ARP = DNS = DNSQR = IP = TCP = UDP = AsyncSniffer = None
    get_if_addr = get_if_list = sniff = None


APP_NAME = "AI Threat Detection"
VERSION = "1.0"
FEATURES = [
    "packets_per_second", "unique_dst_ports", "syn_ratio", "failed_auth",
    "payload_indicators", "dns_label_entropy", "arp_binding_change",
    "unique_dst_ips", "bytes_per_packet", "connection_failures",
]
LABEL_NAMES = ["benign", "network_flood", "port_scan", "auth_abuse", "web_injection", "dns_tunnel", "arp_change"]
WINDOW_SECONDS = 60
MAX_EVIDENCE_BYTES = 4000
MAX_PCAP_BYTES = 24 * 1024 * 1024
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
APP_DIR = Path(os.environ.get("AITHREAT_HOME", Path.home() / ".aithreat"))
APP_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("AITHREAT_DB", APP_DIR / "events.sqlite3"))
MODEL_PATH = Path(os.environ.get("AITHREAT_MODEL", APP_DIR / "models.joblib"))
DB_LOCK = threading.RLock()
STATE_LOCK = threading.RLock()
CAPTURE_LOCK = threading.RLock()
SETTINGS_CACHE_LOCK = threading.RLock()
MODEL_LOCK = threading.RLock()
SETTINGS_CACHE: dict[str, Any] | None = None
WINDOWS: dict[str, deque] = defaultdict(deque)
ARP_BINDINGS: dict[str, str] = {}
DNS_COUNTS: dict[tuple[str, str], deque] = defaultdict(deque)
AUTH_FAILURES: dict[tuple[str, str], deque] = defaultdict(deque)
CONNECTIONS: dict[str, deque] = defaultdict(deque)
CAPTURE: dict[str, Any] = {"sniffer": None, "running": False, "interface": None, "error": None, "started": None}
MODEL: dict[str, Any] = {"iforest": None, "forest": None, "metrics": {}, "trained_at": None, "source": "not trained"}
SETTINGS_DEFAULTS = {
    "scan_ports": 12, "syn_flood_packets": 80, "dos_packets": 180,
    "bruteforce_failures": 6, "dns_queries": 80, "anomaly_threshold": 0.72,
    "window_seconds": WINDOW_SECONDS, "capture_interface": "",
}
MITRE = {
    "Port Scanning": "T1046", "SYN Flood": "T1498.001", "DoS/DDoS Indicators": "T1498",
    "Brute-Force Login Attempts": "T1110", "Unauthorized Access": "T1078",
    "ARP Spoofing": "T1557.002", "Suspicious DNS Activity": "T1071.004",
    "Possible DNS Tunneling": "T1071.004", "SQL Injection Attempts": "T1190",
    "Cross-Site Scripting Attempts": "T1189", "Abnormal Network Behavior": "T1565",
    "Suspicious Connection Patterns": "T1046",
}
MITIGATIONS = {
    "Port Scanning": "Validate exposure and restrict unnecessary services; investigate source attribution before blocking.",
    "SYN Flood": "Check service health and upstream telemetry; apply rate controls at an authorized network edge.",
    "DoS/DDoS Indicators": "Validate impact with service metrics and coordinate mitigation with the network operator.",
    "Brute-Force Login Attempts": "Review authentication logs, enforce MFA and rate limits, and rotate exposed credentials.",
    "Unauthorized Access": "Verify the access-control event, contain the account or session, and preserve audit records.",
    "ARP Spoofing": "Verify the mapping through trusted switch/router state; inspect the local segment and enable protections.",
    "Suspicious DNS Activity": "Review resolver logs and query context; enforce approved resolvers if policy permits.",
    "Possible DNS Tunneling": "Inspect the full resolver telemetry and endpoint; restrict unusual DNS egress after validation.",
    "SQL Injection Attempts": "Review the request and application logs; use parameterized queries and an approved WAF policy.",
    "Cross-Site Scripting Attempts": "Review the request and output handling; apply contextual encoding and input validation.",
    "Abnormal Network Behavior": "Compare with host and application baselines; corroborate before taking containment action.",
    "Suspicious Connection Patterns": "Review connection outcomes and destination context; confirm against expected service behavior.",
}

app = Flask(__name__)
app.secret_key = os.environ.get("AITHREAT_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=MAX_PCAP_BYTES + 1024 * 1024,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def initialize_db() -> None:
    with DB_LOCK, db_connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT NOT NULL UNIQUE,
                attack TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL,
                score INTEGER NOT NULL, src_ip TEXT, dst_ip TEXT, src_port INTEGER,
                dst_port INTEGER, protocol TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                occurrences INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'open',
                source TEXT NOT NULL, evidence TEXT NOT NULL, explanation TEXT NOT NULL,
                anomaly_score REAL, rules TEXT NOT NULL, timeline TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS incident_time ON incidents(last_seen DESC);
            CREATE INDEX IF NOT EXISTS incident_source ON incidents(src_ip);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        for key, value in SETTINGS_DEFAULTS.items():
            db.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (key, json.dumps(value)))


def read_settings() -> dict[str, Any]:
    global SETTINGS_CACHE
    with SETTINGS_CACHE_LOCK:
        if SETTINGS_CACHE is not None:
            return dict(SETTINGS_CACHE)
    with DB_LOCK, db_connect() as db:
        rows = db.execute("SELECT key,value FROM settings").fetchall()
    result = dict(SETTINGS_DEFAULTS)
    for row in rows:
        try:
            result[row["key"]] = json.loads(row["value"])
        except (ValueError, TypeError):
            continue
    with SETTINGS_CACHE_LOCK:
        if SETTINGS_CACHE is None:
            SETTINGS_CACHE = result
        return dict(SETTINGS_CACHE)


def save_settings(values: dict[str, Any]) -> dict[str, Any]:
    global SETTINGS_CACHE
    current = read_settings()
    numeric = {
        "scan_ports": (4, 500), "syn_flood_packets": (20, 100000),
        "dos_packets": (30, 200000), "bruteforce_failures": (3, 100),
        "dns_queries": (20, 100000), "anomaly_threshold": (0.50, 0.99),
    }
    for key, (low, high) in numeric.items():
        if key in values:
            try:
                v = float(values[key])
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be numeric")
            if not low <= v <= high:
                raise ValueError(f"{key} must be between {low} and {high}")
            current[key] = v if key == "anomaly_threshold" else int(v)
    if "capture_interface" in values:
        interface = values["capture_interface"]
        if not isinstance(interface, str) or len(interface) > 160:
            raise ValueError("Invalid capture interface")
        current["capture_interface"] = interface
    with DB_LOCK, db_connect() as db:
        for key, value in current.items():
            db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, json.dumps(value)))
    with SETTINGS_CACHE_LOCK:
        SETTINGS_CACHE = dict(current)
    return current


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = [text.count(ch) / len(text) for ch in set(text)]
    return -sum(p * math.log2(p) for p in counts)


def feature_vector(values: dict[str, Any]) -> np.ndarray:
    """Convert measured event/flow features into the fixed model feature layout."""
    row = []
    for feature in FEATURES:
        try:
            value = float(values.get(feature, 0) or 0)
        except (ValueError, TypeError):
            value = 0.0
        row.append(max(0.0, min(value, 1_000_000.0)))
    return np.asarray(row, dtype=np.float64)


def synthetic_dataset(seed: int = 17041, size: int = 2400) -> tuple[np.ndarray, np.ndarray]:
    """Build deterministic, explicitly synthetic model-development examples."""
    rng = np.random.default_rng(seed)
    x = np.zeros((size, len(FEATURES)), dtype=np.float64)
    y = np.zeros(size, dtype=np.int64)
    for i in range(size):
        label = int(rng.choice(len(LABEL_NAMES), p=[.68, .07, .06, .06, .05, .04, .04]))
        row = np.array([
            rng.gamma(2.0, 2.0), rng.poisson(2.0), rng.beta(1.0, 8.0), 0,
            0, rng.uniform(1, 3.2), 0, rng.poisson(2.0), rng.gamma(2.2, 180),
            rng.poisson(0.5),
        ], dtype=float)
        if label == 1:
            row[0], row[2], row[9] = rng.uniform(80, 650), rng.uniform(.72, 1), rng.uniform(25, 300)
        elif label == 2:
            row[1], row[0], row[9] = rng.uniform(15, 150), rng.uniform(8, 70), rng.uniform(8, 80)
        elif label == 3:
            row[3], row[9] = rng.uniform(4, 30), rng.uniform(4, 30)
        elif label == 4:
            row[4], row[8] = rng.uniform(1, 12), rng.uniform(200, 4000)
        elif label == 5:
            row[5], row[8] = rng.uniform(3.5, 6), rng.uniform(50, 1000)
        elif label == 6:
            row[6], row[9] = rng.uniform(1, 4), rng.uniform(2, 20)
        x[i], y[i] = row, label
    return x, y


def _train_model(force: bool = False) -> dict[str, Any]:
    if MODEL_PATH.exists() and not force:
        try:
            import joblib
            saved = joblib.load(MODEL_PATH)
            if saved.get("features") == FEATURES and saved.get("version") == VERSION:
                MODEL.update(saved["model"])
                MODEL["source"] = "locally saved; synthetic training data"
                return model_summary()
        except Exception:
            # A corrupt or incompatible local model is retrained from known data.
            pass
    x, y = synthetic_dataset()
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=.25, random_state=91, stratify=y
    )
    forest = RandomForestClassifier(
        n_estimators=90, max_depth=12, min_samples_leaf=2,
        class_weight="balanced_subsample", random_state=91, n_jobs=1,
    )
    forest.fit(x_train, y_train)
    predicted = forest.predict(x_test)
    # Independent deterministic normal reference set is not used to fit either model.
    reference, _ = synthetic_dataset(seed=9182, size=640)
    reference = reference[np.all(reference[:, [1, 3, 4, 6]] < 1, axis=1)]
    if len(reference) < 100:
        reference = x_train[y_train == 0]
    iforest = IsolationForest(
        n_estimators=100, contamination="auto", random_state=41, n_jobs=1,
    ).fit(reference)
    # Threshold based on an independent synthetic normal calibration partition.
    normal_test = x_test[y_test == 0]
    calibration = -iforest.score_samples(normal_test)
    anomaly_cut = float(np.quantile(calibration, .985)) if len(calibration) else 0.6
    cm = confusion_matrix(y_test, predicted, labels=np.arange(len(LABEL_NAMES)))
    false_positive_rate = float(cm[0, 1:].sum() / max(1, cm[0].sum()))
    metrics = {
        "test_source": "independent synthetic labeled holdout (25%); not live traffic",
        "samples": int(len(y_test)), "confusion_matrix": cm.tolist(),
        "labels": LABEL_NAMES, "precision_macro": float(precision_score(y_test, predicted, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_test, predicted, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_test, predicted, average="macro", zero_division=0)),
        "false_positive_rate_benign": false_positive_rate,
        "class_distribution": {LABEL_NAMES[i]: int((y_test == i).sum()) for i in range(len(LABEL_NAMES))},
        "anomaly_threshold_raw": anomaly_cut,
    }
    trained = {"iforest": iforest, "forest": forest, "metrics": metrics,
               "trained_at": utc_now(), "source": "synthetic training data"}
    MODEL.update(trained)
    try:
        import joblib
        joblib.dump({"version": VERSION, "features": FEATURES, "model": trained}, MODEL_PATH)
    except Exception as exc:
        MODEL["source"] = f"in-memory synthetic model; persistence failed: {type(exc).__name__}"
    return model_summary()


def train_model(force: bool = False) -> dict[str, Any]:
    with MODEL_LOCK:
        return _train_model(force)


def _model_inference(features: dict[str, Any], anomaly_threshold: float | None = None) -> dict[str, Any]:
    if MODEL["iforest"] is None:
        train_model()
    row = feature_vector(features).reshape(1, -1)
    raw = float(-MODEL["iforest"].score_samples(row)[0])
    threshold = float(MODEL["metrics"].get("anomaly_threshold_raw", 1.0))
    # Bounded relative anomaly measure; not an attack probability.
    anomaly = max(0.0, min(1.0, (raw - threshold) / max(threshold, .05) + .5))
    anomaly_cutoff = float(anomaly_threshold if anomaly_threshold is not None else read_settings()["anomaly_threshold"])
    label = int(MODEL["forest"].predict(row)[0])
    return {
        "raw_iforest_score": raw, "anomaly_score": round(anomaly, 3),
        "anomaly": anomaly >= anomaly_cutoff, "anomaly_score_threshold": anomaly_cutoff,
        "classification": LABEL_NAMES[label],
        "classification_note": "Random Forest label from synthetic training profiles; advisory only",
    }


def model_inference(features: dict[str, Any], anomaly_threshold: float | None = None) -> dict[str, Any]:
    with MODEL_LOCK:
        return _model_inference(features, anomaly_threshold)


def model_summary() -> dict[str, Any]:
    metrics = MODEL.get("metrics", {})
    return {
        "status": "trained" if MODEL.get("forest") is not None else "not trained",
        "trained_at": MODEL.get("trained_at"), "data_source": MODEL.get("source"),
        "features": FEATURES, "classes": LABEL_NAMES, "metrics": metrics,
        "feature_importance": (
            {name: round(float(score), 5) for name, score in
             zip(FEATURES, MODEL["forest"].feature_importances_)}
            if MODEL.get("forest") is not None else {}
        ),
    }


def valid_ip(value: Any) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


def score_event(severity: int, occurrences: int, persistence_seconds: float, anomaly: float) -> tuple[int, dict[str, int]]:
    """Transparent evidence-weighted risk score; score is not a probability."""
    parts = {
        "rule_severity": max(0, min(45, int(severity))),
        "frequency": min(20, max(0, (occurrences - 1) * 4)),
        "persistence": min(15, max(0, int(persistence_seconds // 15) * 3)),
        "model_anomaly": min(20, max(0, int(anomaly * 20))),
    }
    return min(100, sum(parts.values())), parts


def score_level(score: int) -> str:
    return "critical" if score >= 75 else "high" if score >= 50 else "medium" if score >= 25 else "low"


def safe_evidence(event: dict[str, Any]) -> dict[str, Any]:
    output = {}
    for key, value in event.items():
        key = str(key)[:64]
        if isinstance(value, (str, int, float, bool)) or value is None:
            output[key] = str(value)[:MAX_EVIDENCE_BYTES] if isinstance(value, str) else value
        elif isinstance(value, (list, tuple)):
            output[key] = [str(x)[:256] for x in value[:32]]
        elif isinstance(value, dict):
            output[key] = {str(k)[:64]: str(v)[:512] for k, v in list(value.items())[:32]}
    return output


def make_fingerprint(attack: str, src: str | None, dst: str | None, src_port: Any, dst_port: Any, source: str) -> str:
    material = "|".join((attack, src or "-", dst or "-", str(src_port or "-"), str(dst_port or "-"), source))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def record_incident(
    attack: str, category: str, src: str | None, dst: str | None,
    src_port: int | None, dst_port: int | None, protocol: str,
    evidence: dict[str, Any], features: dict[str, Any], rule: str,
    source: str = "live", severity: int = 30, confirmed: bool = False,
) -> dict[str, Any]:
    now = utc_now()
    inference = model_inference(features)
    fingerprint = make_fingerprint(attack, src, dst, src_port, dst_port, source)
    timeline_event = {
        "time": now, "event": "observed", "source": source,
        "rule": rule, "confirmed": confirmed,
    }
    with DB_LOCK, db_connect() as db:
        existing = db.execute("SELECT * FROM incidents WHERE fingerprint=?", (fingerprint,)).fetchone()
        count = (existing["occurrences"] + 1) if existing else 1
        first = existing["first_seen"] if existing else now
        try:
            persistence = max(0, (datetime.fromisoformat(now) - datetime.fromisoformat(first)).total_seconds())
        except ValueError:
            persistence = 0
        score, score_parts = score_event(severity, count, persistence, inference["anomaly_score"])
        level = score_level(score)
        ev = safe_evidence(evidence)
        ev["observation_status"] = (
            "simulated test event" if source == "simulated"
            else "confirmed observation" if confirmed else "suspected"
        )
        ev["score_components"] = score_parts
        ev["risk_score_note"] = "Evidence-weighted risk score; not an attack probability."
        ev["model"] = inference
        ev["mitre"] = MITRE.get(attack)
        ev["mitigation"] = MITIGATIONS.get(attack, "Corroborate the telemetry before response.")
        rules = [rule]
        explanation = (
            f"{attack} ({category}) was raised by rule '{rule}'. "
            f"Observed source={src or 'not supplied'}, destination={dst or 'not supplied'}, "
            f"protocol={protocol}, source port={src_port or 'not supplied'}, destination port={dst_port or 'not supplied'}. "
            f"Evidence: {json.dumps(ev, ensure_ascii=True)[:3500]} "
            f"Risk score {score}/100 = " + " + ".join(f"{k} {v}" for k, v in score_parts.items()) + "."
        )
        timeline = json.loads(existing["timeline"]) if existing else []
        timeline.append(timeline_event)
        if len(timeline) > 200:
            timeline = timeline[-200:]
        if existing:
            db.execute("""UPDATE incidents SET last_seen=?,occurrences=?,score=?,severity=?,
                evidence=?,explanation=?,anomaly_score=?,rules=?,timeline=? WHERE id=?""",
                (now, count, score, level, json.dumps(ev), explanation,
                 inference["anomaly_score"], json.dumps(rules), json.dumps(timeline), existing["id"]))
            incident_id = existing["id"]
        else:
            cur = db.execute("""INSERT INTO incidents(fingerprint,attack,category,severity,score,src_ip,dst_ip,
                src_port,dst_port,protocol,first_seen,last_seen,occurrences,source,evidence,explanation,
                anomaly_score,rules,timeline) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fingerprint, attack, category, level, score, src, dst, src_port, dst_port,
                 protocol, now, now, 1, source, json.dumps(ev), explanation,
                 inference["anomaly_score"], json.dumps(rules), json.dumps(timeline)))
            incident_id = cur.lastrowid
    return {"id": incident_id, "attack": attack, "severity": level, "score": score, "source": source, "occurrences": count}


def emit_rule(name: str, src: str | None, dst: str | None, src_port: int | None, dst_port: int | None,
              protocol: str, evidence: dict[str, Any], features: dict[str, Any],
              rule: str, severity: int, category: str = "Network", confirmed: bool = False,
              source: str = "live") -> dict[str, Any]:
    return record_incident(name, category, src, dst, src_port, dst_port, protocol,
                           evidence, features, rule, source, severity, confirmed)


def _trim(q: deque, now: float, seconds: int) -> None:
    while q and now - q[0][0] > seconds:
        q.popleft()


def _tracked_queue(mapping: dict, key: Any, max_keys: int = 4096, max_entries: int = 4096) -> deque:
    if key not in mapping:
        if len(mapping) >= max_keys:
            mapping.pop(next(iter(mapping)))
        mapping[key] = deque(maxlen=max_entries)
    return mapping[key]


SQLI_PATTERNS = ("union select", " or 1=1", "'--", "drop table", "sleep(", "information_schema")
XSS_PATTERNS = ("<script", "javascript:", "onerror=", "onload=", "document.cookie")


def inspect_http_payload(payload: bytes, src: str | None, dst: str | None,
                         src_port: int | None, dst_port: int | None,
                         source: str = "live") -> list[dict[str, Any]]:
    if not payload:
        return []
    text = payload[:8192].decode("utf-8", "ignore").lower()
    if not text.startswith(("get ", "post ", "put ", "patch ", "delete ", "head ", "options ", "http/")):
        return []
    decoded_text = unquote_plus(text)
    found = []
    for attack, patterns, severity, mitre_category in (
        ("SQL Injection Attempts", SQLI_PATTERNS, 44, "Application"),
        ("Cross-Site Scripting Attempts", XSS_PATTERNS, 38, "Application"),
    ):
        matches = [p for p in patterns if p in text or p in decoded_text]
        if matches:
            found.append(emit_rule(
                attack, src, dst, src_port, dst_port, "TCP",
                {"matched_indicators": matches, "payload_excerpt": text[:240]},
                {"payload_indicators": len(matches), "bytes_per_packet": len(payload)},
                f"HTTP payload contains {len(matches)} configured {attack.lower()} signature(s)",
                severity, mitre_category, source=source,
            ))
    return found


def inspect_packet(packet: Any, source: str = "live") -> list[dict[str, Any]]:
    """Passive packet inspection; counters are bounded by rolling time windows."""
    if IP is None:
        return []
    found: list[dict[str, Any]] = []
    now_mono = time.monotonic()
    settings = read_settings()
    src = dst = None
    sport = dport = None
    protocol = "OTHER"
    payload = b""
    with STATE_LOCK:
        if ARP and packet.haslayer(ARP):
            arp = packet[ARP]
            if int(arp.op) == 2:
                ip, mac = str(arp.psrc), str(arp.hwsrc).lower()
                old = ARP_BINDINGS.get(ip)
                if old is None and len(ARP_BINDINGS) >= 4096:
                    ARP_BINDINGS.pop(next(iter(ARP_BINDINGS)))
                ARP_BINDINGS[ip] = mac
                if old and old != mac:
                    found.append(emit_rule(
                        "ARP Spoofing", ip, None, None, None, "ARP",
                        {"claimed_ip": ip, "previous_mac": old, "new_mac": mac},
                        {"arp_binding_change": 1, "connection_failures": 1},
                        "Observed an ARP reply mapping an existing IPv4 address to a different MAC",
                        42, "Network", confirmed=True, source=source,
                    ))
            return found
        if not packet.haslayer(IP):
            return found
        ip = packet[IP]
        src, dst = valid_ip(ip.src), valid_ip(ip.dst)
        if TCP and packet.haslayer(TCP):
            tcp = packet[TCP]
            sport, dport = int(tcp.sport), int(tcp.dport)
            protocol = "TCP"
            payload = bytes(tcp.payload) if tcp.payload else b""
        elif UDP and packet.haslayer(UDP):
            udp = packet[UDP]
            sport, dport = int(udp.sport), int(udp.dport)
            protocol = "UDP"
            payload = bytes(udp.payload) if udp.payload else b""

        flow = _tracked_queue(WINDOWS, src or "unknown")
        flow.append((now_mono, dst, dport, protocol, bool(TCP and packet.haslayer(TCP) and int(packet[TCP].flags) & 0x02 and not int(packet[TCP].flags) & 0x10), len(bytes(packet))))
        _trim(flow, now_mono, int(settings["window_seconds"]))
        count = len(flow)
        ports = {entry[2] for entry in flow if entry[2] is not None}
        dsts = {entry[1] for entry in flow if entry[1]}
        syns = sum(1 for entry in flow if entry[4])
        syn_ratio = syns / count if count else 0
        pps = count / max(1, min(int(read_settings()["window_seconds"]), int(now_mono - flow[0][0]) + 1)) if flow else 0
        feat = {
            "packets_per_second": pps, "unique_dst_ports": len(ports),
            "syn_ratio": syn_ratio, "unique_dst_ips": len(dsts),
            "bytes_per_packet": statistics.mean(e[5] for e in flow) if flow else 0,
            "connection_failures": syns,
        }
        # A scan requires breadth across destination ports, not a single request.
        if len(ports) >= settings["scan_ports"]:
            found.append(emit_rule(
                "Port Scanning", src, dst, sport, dport, protocol,
                {"unique_destination_ports_in_window": len(ports), "window_seconds": settings["window_seconds"],
                 "destination_ports_sample": sorted(ports)[:40]},
                feat, f"Source contacted at least {settings['scan_ports']} distinct destination ports in the rolling window",
                40, "Network", source=source,
            ))
        if syns >= settings["syn_flood_packets"] and syn_ratio >= .75:
            found.append(emit_rule(
                "SYN Flood", src, dst, sport, dport, protocol,
                {"syn_packets_in_window": syns, "packet_count": count, "syn_ratio": round(syn_ratio, 3)},
                feat, f"At least {settings['syn_flood_packets']} SYN packets with >=75% SYN-only ratio",
                48, "Availability", source=source,
            ))
        # Destination-wide count groups traffic from different sources as DDoS indicators.
        target = dst or "unknown"
        connections = _tracked_queue(CONNECTIONS, target, max_entries=10000)
        connections.append((now_mono, src))
        _trim(connections, now_mono, int(settings["window_seconds"]))
        unique_sources = {item[1] for item in connections}
        distributed_load = len(connections) >= settings["dos_packets"] and len(unique_sources) >= 3
        concentrated_load = len(connections) >= settings["dos_packets"] * 5 and len(unique_sources) == 1
        if distributed_load or concentrated_load:
            found.append(emit_rule(
                "DoS/DDoS Indicators", src, dst, sport, dport, protocol,
                {"destination_packet_count": len(connections), "distinct_sources": len(unique_sources),
                 "window_seconds": settings["window_seconds"],
                 "traffic_pattern": "distributed" if distributed_load else "single-source high volume"},
                {**feat, "packets_per_second": len(connections) / settings["window_seconds"]},
                (f"Destination received at least {settings['dos_packets']} packets from >=3 sources in window"
                 if distributed_load else
                 f"Destination received at least {settings['dos_packets'] * 5} packets from one source in window"),
                50 if distributed_load else 44, "Availability", source=source,
            ))

        # Domain indicators are based on DNS query lengths, label entropy, and repetition.
        if DNS and packet.haslayer(DNS) and packet[DNS].qd and DNSQR and packet.haslayer(DNSQR):
            try:
                qname = bytes(packet[DNSQR].qname).decode("ascii", "ignore").rstrip(".").lower()
            except Exception:
                qname = ""
            labels = qname.split(".")
            longest = max((len(label) for label in labels), default=0)
            label_entropy = max((entropy(label) for label in labels), default=0)
            q = _tracked_queue(DNS_COUNTS, (src or "unknown", qname), max_entries=1000)
            q.append((now_mono, 1))
            _trim(q, now_mono, int(settings["window_seconds"]))
            dns_features = {**feat, "dns_label_entropy": label_entropy}
            if longest >= 45 and label_entropy >= 3.4:
                found.append(emit_rule(
                    "Possible DNS Tunneling", src, dst, sport, dport, protocol,
                    {"query_name": qname[:220], "longest_label_length": longest,
                     "maximum_label_entropy_bits": round(label_entropy, 2)},
                    dns_features, "DNS query has a long, high-entropy label", 39, "DNS", source=source,
                ))
            elif len(q) >= settings["dns_queries"] or longest >= 30:
                found.append(emit_rule(
                    "Suspicious DNS Activity", src, dst, sport, dport, protocol,
                    {"query_name": qname[:220], "repeated_query_count": len(q), "longest_label_length": longest},
                    dns_features, "DNS query volume or label length exceeded configured heuristic", 30, "DNS", source=source,
                ))
        if payload and (dport in (80, 8080, 8000, 8888) or sport in (80, 8080, 8000, 8888)):
            found.extend(inspect_http_payload(payload, src, dst, sport, dport, source))
        # Only report model anomalies if the score exceeds a calibrated threshold and no specific rule fired.
        inference = model_inference(feat, settings["anomaly_threshold"])
        if inference["anomaly"] and not found:
            found.append(emit_rule(
                "Abnormal Network Behavior", src, dst, sport, dport, protocol,
                {"flow_packets": count, "distinct_destination_ports": len(ports),
                 "distinct_destination_ips": len(dsts), "model": inference},
                feat, "Isolation Forest score exceeded synthetic-normal calibration threshold",
                25, "Anomaly", source=source,
            ))
        # Connection pattern rule is deliberately conservative: repeated endpoints plus failed SYNs.
        if syns >= 20 and len(dsts) <= 2 and syn_ratio >= .65 and not any(x["attack"] == "SYN Flood" for x in found):
            found.append(emit_rule(
                "Suspicious Connection Patterns", src, dst, sport, dport, protocol,
                {"connection_attempts": syns, "destination_count": len(dsts), "syn_ratio": round(syn_ratio, 3)},
                feat, "Repeated SYN attempts concentrated on <=2 destinations", 30, "Network", source=source,
            ))
    return found


def ingest_log_event(data: dict[str, Any], source: str = "live") -> list[dict[str, Any]]:
    """Ingest normalized authentication/application audit events; no login guessing."""
    if not isinstance(data, dict):
        raise ValueError("event must be a JSON object")
    kind = str(data.get("type", "")).lower()
    src = valid_ip(data.get("src_ip"))
    dst = valid_ip(data.get("dst_ip"))
    if data.get("src_ip") and not src or data.get("dst_ip") and not dst:
        raise ValueError("invalid source or destination IPv4/IPv6 address")
    service = str(data.get("service", "application"))[:80]
    username = str(data.get("username", "unknown"))[:80]
    outcome = str(data.get("outcome", "")).lower()
    now = time.monotonic()
    found = []
    if kind in ("auth", "authentication") and outcome in ("failure", "failed", "denied"):
        key = (src or "unknown", service)
        with STATE_LOCK:
            q = _tracked_queue(AUTH_FAILURES, key, max_entries=2000)
            q.append((now, username))
            _trim(q, now, WINDOW_SECONDS)
            failures = len(q)
        threshold = read_settings()["bruteforce_failures"]
        if failures >= threshold:
            found.append(emit_rule(
                "Brute-Force Login Attempts", src, dst, None, None, "AUTH",
                {"service": service, "failure_count_in_window": failures, "window_seconds": WINDOW_SECONDS,
                 "distinct_usernames": len({u for _, u in q})},
                {"failed_auth": failures, "connection_failures": failures},
                f"Observed {failures} failed authentication audit records; threshold={threshold}",
                42, "Identity", source=source,
            ))
    elif kind in ("auth", "authentication") and outcome in ("success", "allowed", "accepted") and data.get("unauthorized") is True:
        found.append(emit_rule(
            "Unauthorized Access", src, dst, None, None, "AUTH",
            {"service": service, "username": username, "outcome": outcome,
             "audit_marker": "unauthorized=true"},
            {"failed_auth": 1, "connection_failures": 1},
            "Ingested authentication audit record explicitly marked unauthorized",
            50, "Identity", confirmed=True, source=source,
        ))
    elif kind in ("http", "web", "application"):
        payload = str(data.get("request", data.get("message", "")))[:8192].encode("utf-8")
        try:
            sport = int(data.get("src_port")) if data.get("src_port") is not None else None
            dport = int(data.get("dst_port")) if data.get("dst_port") is not None else None
        except (ValueError, TypeError):
            raise ValueError("ports must be integers")
        if any(p is not None and not 1 <= p <= 65535 for p in (sport, dport)):
            raise ValueError("ports must be between 1 and 65535")
        found.extend(inspect_http_payload(payload, src, dst, sport, dport, source))
    else:
        raise ValueError("type must be auth, authentication, http, web, or application")
    return found


def primary_ipv4() -> str | None:
    """Find source address selected by OS routing without requiring internet reachability."""
    candidates = []
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/net/route", encoding="ascii") as route_file:
                next(route_file)
                rows = [line.split() for line in route_file if len(line.split()) >= 8]
            default = [row for row in rows if row[1] == "00000000" and int(row[3], 16) & 1]
            default.sort(key=lambda row: int(row[6]))
            if default:
                iface = default[0][0]
                virtual_prefixes = ("lo", "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "tun", "tap")
                if get_if_list and get_if_addr and not iface.lower().startswith(virtual_prefixes):
                    for name in get_if_list():
                        if name == iface:
                            candidates.append(get_if_addr(name))
        except (OSError, ValueError, StopIteration):
            pass
    if not candidates:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("192.0.2.1", 9))
            candidates.append(sock.getsockname()[0])
        except OSError:
            pass
        finally:
            sock.close()
    for candidate in candidates:
        ip = valid_ip(candidate)
        address = ipaddress.ip_address(ip) if ip else None
        if address and address.version == 4 and not (
            address.is_loopback or address.is_link_local or address.is_unspecified
            or address.is_multicast or address.is_reserved
        ):
            return ip
    return None


def adapter_list() -> list[dict[str, Any]]:
    if not get_if_list or not get_if_addr:
        return []
    primary = primary_ipv4()
    result = []
    try:
        for name in get_if_list():
            try:
                address = valid_ip(get_if_addr(name))
            except Exception:
                address = None
            if address:
                result.append({"name": str(name)[:160], "ipv4": address, "primary": address == primary})
    except Exception:
        return []
    return result


def private_client(remote: str | None) -> bool:
    ip = valid_ip(remote)
    if not ip:
        return False
    address = ipaddress.ip_address(ip)
    return address.is_loopback or (address.version == 4 and any(address in net for net in PRIVATE_NETWORKS))


def login_password() -> str:
    configured = os.environ.get("AITHREAT_PASSWORD")
    if configured:
        return configured
    password_file = APP_DIR / "initial-password.txt"
    try:
        if password_file.exists():
            return password_file.read_text(encoding="utf-8").strip()
        password = secrets.token_urlsafe(18)
        password_file.write_text(password + "\n", encoding="utf-8")
        try:
            password_file.chmod(0o600)
        except OSError:
            pass
        print(f"[AI Threat Detection] First-run dashboard password: {password}", file=sys.stderr)
        print(f"[AI Threat Detection] Stored in {password_file}; set AITHREAT_PASSWORD to override.", file=sys.stderr)
        return password
    except OSError as exc:
        raise RuntimeError("Cannot securely initialize login password; set AITHREAT_PASSWORD") from exc


def csrf_valid() -> bool:
    return bool(session.get("csrf") and secrets.compare_digest(
        str(request.headers.get("X-CSRF-Token", "")), str(session["csrf"])
    ))


LOGIN_HTML = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Sign in | AI Threat Detection</title><style>
*{box-sizing:border-box}body{margin:0;background:#101722;color:#e8eef5;font:15px system-ui,Segoe UI,sans-serif;min-height:100vh;display:grid;place-items:center}
form{width:min(390px,92vw);background:#192331;border:1px solid #354354;padding:30px;border-radius:8px}h1{font-size:21px;margin:0 0 7px}p{color:#aab8c7;line-height:1.55}label{display:block;margin:20px 0 7px}input{width:100%;padding:11px;background:#0f1721;color:white;border:1px solid #405064;border-radius:4px}button{margin-top:18px;width:100%;padding:11px;background:#2674c8;border:0;color:white;border-radius:4px;font-weight:650}small{color:#97a9bb} .error{color:#ff9797}
</style><form method="post"><h1>AI Threat Detection</h1><p>Sign in to the local security operations dashboard.</p>{% if error %}<p class="error">{{error}}</p>{% endif %}<label for="password">Dashboard password</label><input id="password" name="password" type="password" required autofocus autocomplete="current-password"><button>Sign in</button><p><small>LAN access is restricted to private networks and authenticated users.</small></p></form></html>"""


@app.before_request
def enforce_local_auth() -> Any:
    remote = request.remote_addr
    if not private_client(remote):
        abort(403)
    if request.endpoint in ("login", "static") or session.get("authenticated"):
        return None
    if request.path.startswith("/api/"):
        return jsonify({"error": "authentication required"}), 401
    return redirect(url_for("login", next=request.path))


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    error = None
    if request.method == "POST":
        supplied = request.form.get("password", "")
        if secrets.compare_digest(supplied, login_password()):
            session.clear()
            session["authenticated"] = True
            session["csrf"] = secrets.token_urlsafe(24)
            next_path = request.args.get("next", "/")
            if not next_path.startswith("/") or next_path.startswith("//"):
                next_path = "/"
            return redirect(next_path)
        error = "Incorrect password."
    return render_template_string(LOGIN_HTML, error=error)


@app.post("/logout")
def logout() -> Any:
    if not csrf_valid():
        abort(400, "Invalid CSRF token")
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def dashboard() -> Any:
    return render_template_string(DASHBOARD_HTML, csrf=session["csrf"], app_name=APP_NAME, version=VERSION)


@app.get("/api/overview")
def api_overview() -> Any:
    with DB_LOCK, db_connect() as db:
        total = db.execute("SELECT COUNT(*) FROM incidents WHERE status!='false_positive'").fetchone()[0]
        critical = db.execute("SELECT COUNT(*) FROM incidents WHERE severity='critical' AND status!='false_positive'").fetchone()[0]
        recent = db.execute("SELECT attack,COUNT(*) n FROM incidents WHERE last_seen>=datetime('now','-24 hours') AND status!='false_positive' GROUP BY attack ORDER BY n DESC LIMIT 8").fetchall()
        latest = db.execute("SELECT id,attack,severity,score,src_ip,dst_ip,protocol,last_seen,occurrences,source,status FROM incidents ORDER BY last_seen DESC LIMIT 8").fetchall()
        trend = db.execute("SELECT substr(last_seen,1,13) hour,COUNT(*) n FROM incidents WHERE last_seen>=datetime('now','-24 hours') GROUP BY hour ORDER BY hour").fetchall()
    return jsonify({
        "total_active": total, "critical_active": critical,
        "open_incidents": _count_status("open"), "capture": capture_status(),
        "primary_ipv4": primary_ipv4(), "engine": "healthy" if MODEL.get("forest") else "model unavailable",
        "attacks_24h": [dict(row) for row in recent], "latest": [dict(row) for row in latest],
        "hourly": [dict(row) for row in trend],
    })


def _count_status(status: str) -> int:
    with DB_LOCK, db_connect() as db:
        return int(db.execute("SELECT COUNT(*) FROM incidents WHERE status=?", (status,)).fetchone()[0])


def capture_status() -> dict[str, Any]:
    with CAPTURE_LOCK:
        sniffer = CAPTURE.get("sniffer")
        if CAPTURE["running"] and sniffer and not getattr(sniffer, "running", True):
            CAPTURE.update(
                running=False, sniffer=None, interface=None,
                error=CAPTURE.get("error") or "Capture stopped unexpectedly; check interface permissions and driver.",
            )
        return {key: CAPTURE[key] for key in ("running", "interface", "error", "started")}


@app.get("/api/health")
def api_health() -> Any:
    return jsonify({
        "status": "degraded" if CAPTURE.get("error") else "healthy",
        "database": DB_PATH.exists(), "model": MODEL.get("forest") is not None,
        "scapy": sniff is not None, "capture": capture_status(),
        "primary_ipv4": primary_ipv4(), "time_utc": utc_now(),
    })


@app.get("/api/incidents")
def api_incidents() -> Any:
    search = request.args.get("q", "")[:120]
    severity = request.args.get("severity", "")[:16]
    status = request.args.get("status", "")[:32]
    attack = request.args.get("attack", "")[:100]
    limit = min(250, max(1, request.args.get("limit", default=100, type=int) or 100))
    where, params = [], []
    if search:
        like = f"%{search}%"
        where.append("(attack LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR explanation LIKE ?)")
        params.extend([like] * 4)
    if severity in ("low", "medium", "high", "critical"):
        where.append("severity=?"); params.append(severity)
    if status in ("open", "investigating", "resolved", "false_positive"):
        where.append("status=?"); params.append(status)
    if attack:
        where.append("attack=?"); params.append(attack)
    sql = "SELECT * FROM incidents" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY last_seen DESC LIMIT ?"
    params.append(limit)
    with DB_LOCK, db_connect() as db:
        rows = db.execute(sql, params).fetchall()
    return jsonify([_incident_dict(row) for row in rows])


def _incident_dict(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    for key in ("evidence", "rules", "timeline"):
        try:
            result[key] = json.loads(result[key])
        except (ValueError, TypeError):
            result[key] = [] if key != "evidence" else {}
    result["mitre"] = result["evidence"].get("mitre")
    result["mitigation"] = result["evidence"].get("mitigation")
    return result


@app.get("/api/incidents/<int:incident_id>")
def api_incident(incident_id: int) -> Any:
    with DB_LOCK, db_connect() as db:
        row = db.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        abort(404)
    return jsonify(_incident_dict(row))


@app.post("/api/incidents/<int:incident_id>/status")
def api_incident_status(incident_id: int) -> Any:
    if not csrf_valid():
        abort(400, "Invalid CSRF token")
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in ("open", "investigating", "resolved", "false_positive"):
        return jsonify(error="invalid status"), 400
    with DB_LOCK, db_connect() as db:
        cur = db.execute("UPDATE incidents SET status=? WHERE id=?", (status, incident_id))
        if not cur.rowcount:
            abort(404)
        row = db.execute("SELECT timeline FROM incidents WHERE id=?", (incident_id,)).fetchone()
        timeline = json.loads(row["timeline"])
        timeline.append({"time": utc_now(), "event": f"status changed to {status}", "source": "analyst"})
        db.execute("UPDATE incidents SET timeline=? WHERE id=?", (json.dumps(timeline[-200:]), incident_id))
    return jsonify(ok=True, status=status)


@app.get("/api/ip-profiles")
def api_ip_profiles() -> Any:
    with DB_LOCK, db_connect() as db:
        rows = db.execute("""SELECT src_ip,COUNT(*) incidents,MAX(last_seen) last_seen,
            SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) critical,
            GROUP_CONCAT(DISTINCT attack) attacks FROM incidents
            WHERE src_ip IS NOT NULL AND status!='false_positive'
            GROUP BY src_ip ORDER BY incidents DESC LIMIT 200""").fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/api/model")
def api_model() -> Any:
    return jsonify(model_summary())


@app.post("/api/model/train")
def api_model_train() -> Any:
    if not csrf_valid():
        abort(400, "Invalid CSRF token")
    return jsonify(train_model(force=True))


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings() -> Any:
    if request.method == "GET":
        return jsonify({"settings": read_settings(), "adapters": adapter_list()})
    if not csrf_valid():
        abort(400, "Invalid CSRF token")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON object required"), 400
    try:
        updated = save_settings(data)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(settings=updated)


@app.post("/api/logs")
def api_logs() -> Any:
    if not csrf_valid():
        abort(400, "Invalid CSRF token")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON object required"), 400
    try:
        return jsonify(observations=ingest_log_event(data))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/lab/<scenario>")
def api_lab(scenario: str) -> Any:
    """Offline scenarios feed evidence fixtures to the same detector rules."""
    if not csrf_valid():
        abort(400, "Invalid CSRF token")
    source = "simulated"
    sample_private = "192.0.2.10"  # Documentation-only address, never presented as local host.
    target_private = "198.51.100.20"  # Documentation-only address.
    emitted = []
    try:
        if scenario == "port-scan":
            emitted.append(emit_rule("Port Scanning", sample_private, target_private, 45000, 443, "TCP",
                {"unique_destination_ports_in_window": 24, "destination_ports_sample": list(range(20, 44)),
                 "window_seconds": 60, "test_fixture": True},
                {"unique_dst_ports": 24, "packets_per_second": 2, "connection_failures": 24},
                "Offline lab fixture: 24 unique destination ports", 40, "Network", source=source))
        elif scenario == "syn-flood":
            emitted.append(emit_rule("SYN Flood", sample_private, target_private, 45000, 443, "TCP",
                {"syn_packets_in_window": 120, "packet_count": 125, "syn_ratio": .96, "test_fixture": True},
                {"packets_per_second": 120, "syn_ratio": .96, "connection_failures": 120},
                "Offline lab fixture: SYN rate threshold exceeded", 48, "Availability", source=source))
        elif scenario == "dos":
            emitted.append(emit_rule("DoS/DDoS Indicators", sample_private, target_private, 45000, 443, "TCP",
                {"destination_packet_count": 240, "distinct_sources": 8, "window_seconds": 60, "test_fixture": True},
                {"packets_per_second": 4, "unique_dst_ips": 1, "connection_failures": 240},
                "Offline lab fixture: high destination rate from multiple source addresses", 50, "Availability", source=source))
        elif scenario == "bruteforce":
            for _ in range(read_settings()["bruteforce_failures"]):
                emitted.extend(ingest_log_event({
                    "type": "auth", "src_ip": sample_private, "dst_ip": target_private,
                    "service": "demo-ssh-audit", "username": "demo-user", "outcome": "failure",
                }, source=source))
        elif scenario == "unauthorized":
            emitted.extend(ingest_log_event({"type": "auth", "src_ip": sample_private, "dst_ip": target_private,
                "service": "demo-app-audit", "username": "demo-user", "outcome": "success", "unauthorized": True}, source=source))
        elif scenario == "arp-spoof":
            emitted.append(emit_rule("ARP Spoofing", sample_private, None, None, None, "ARP",
                {"claimed_ip": sample_private, "previous_mac": "02:00:00:00:00:01",
                 "new_mac": "02:00:00:00:00:02", "test_fixture": True},
                {"arp_binding_change": 1}, "Offline lab fixture: conflicting ARP binding", 42, "Network",
                confirmed=True, source=source))
        elif scenario in ("dns", "dns-tunnel"):
            name = "Possible DNS Tunneling" if scenario == "dns-tunnel" else "Suspicious DNS Activity"
            query_name = "a9f3c7d2e8b1f5a0c4d6e9a1b3c5d7e9a1b2c3d4e5f6a7b8c9d0.payload.example"
            dns_label = query_name.split(".", 1)[0]
            evidence = ({
                "query_name": query_name, "longest_label_length": len(dns_label),
                "maximum_label_entropy_bits": round(entropy(dns_label), 2), "test_fixture": True,
            } if scenario == "dns-tunnel" else {
                "query_name": "repeated.demo.example", "repeated_query_count": 100, "test_fixture": True,
            })
            emitted.append(emit_rule(name, sample_private, target_private, 53000, 53, "UDP", evidence,
                {"dns_label_entropy": entropy(dns_label) if scenario == "dns-tunnel" else 1.2, "packets_per_second": 4},
                "Offline lab fixture: suspicious DNS query heuristic", 39 if scenario == "dns-tunnel" else 30,
                "DNS", source=source))
        elif scenario in ("sqli", "xss"):
            text = "GET /search?q=1' UNION SELECT password FROM users-- HTTP/1.1" if scenario == "sqli" else \
                   "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1"
            # These are inert request strings passed to the signature matcher, not sent anywhere.
            emitted.extend(inspect_http_payload(text.encode(), sample_private, target_private, 51000, 8080, source))
        elif scenario == "abnormal":
            emitted.append(emit_rule("Abnormal Network Behavior", sample_private, target_private, 51000, 9001, "TCP",
                {"flow_packets": 500, "distinct_destination_ports": 4, "test_fixture": True},
                {"packets_per_second": 500, "unique_dst_ports": 4, "bytes_per_packet": 9000},
                "Offline lab fixture: anomalous synthetic flow features", 25, "Anomaly", source=source))
        elif scenario == "connections":
            emitted.append(emit_rule("Suspicious Connection Patterns", sample_private, target_private, 51000, 443, "TCP",
                {"connection_attempts": 28, "destination_count": 1, "syn_ratio": .82, "test_fixture": True},
                {"connection_failures": 28, "syn_ratio": .82, "unique_dst_ips": 1},
                "Offline lab fixture: repeated connection attempts to one destination", 30, "Network", source=source))
        else:
            return jsonify(error="unknown scenario"), 404
    except (ValueError, OSError) as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(source=source, simulated=True, observations=emitted,
                   message="Fixture only: no packets were sent and no external host was contacted.")


@app.post("/api/pcap")
def api_pcap() -> Any:
    if not csrf_valid():
        abort(400, "Invalid CSRF token")
    upload = request.files.get("file")
    if not upload or not upload.filename or not upload.filename.lower().endswith((".pcap", ".pcapng")):
        return jsonify(error="Select a .pcap or .pcapng file"), 400
    data = upload.stream.read(MAX_PCAP_BYTES + 1)
    if len(data) > MAX_PCAP_BYTES:
        return jsonify(error=f"PCAP exceeds {MAX_PCAP_BYTES} byte limit"), 413
    if not data:
        return jsonify(error="PCAP file is empty"), 400
    if not sniff:
        return jsonify(error="Scapy is unavailable; install dependencies to inspect PCAP files"), 503
    try:
        from scapy.utils import RawPcapReader
        processed, detections = 0, []
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=True) as tmp:
            tmp.write(data); tmp.flush()
            # Stream through reader to keep memory bounded.
            for packet_data, metadata in RawPcapReader(tmp.name):
                if processed >= 100000:
                    break
                from scapy.layers.l2 import Ether
                packet = Ether(packet_data)
                processed += 1
                detections.extend(inspect_packet(packet, source="pcap"))
        return jsonify(source="pcap", packets_processed=processed, observations=detections[:500],
                       message="Offline PCAP investigation; file was not replayed onto a network.")
    except Exception as exc:
        return jsonify(error=f"PCAP parse failed: {type(exc).__name__}: {str(exc)[:180]}"), 400


def _capture_packet(packet: Any) -> None:
    try:
        inspect_packet(packet, source="live")
    except Exception as exc:
        with CAPTURE_LOCK:
            CAPTURE["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"


@app.post("/api/capture")
def api_capture() -> Any:
    if not csrf_valid():
        abort(400, "Invalid CSRF token")
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action == "stop":
        with CAPTURE_LOCK:
            sniffer = CAPTURE["sniffer"]
            CAPTURE["sniffer"] = None
            CAPTURE["running"] = False
            CAPTURE["interface"] = None
        if sniffer:
            try:
                sniffer.stop()
            except Exception as exc:
                with CAPTURE_LOCK:
                    CAPTURE["error"] = f"Capture stop: {type(exc).__name__}: {str(exc)[:140]}"
        return jsonify(capture_status())
    with CAPTURE_LOCK:
        if action != "start":
            return jsonify(error="action must be start or stop"), 400
        if CAPTURE["running"]:
            return jsonify(error="capture is already running", capture=capture_status()), 409
        if not AsyncSniffer:
            CAPTURE["error"] = "Scapy is unavailable"
            return jsonify(error=CAPTURE["error"]), 503
        interface = str(data.get("interface") or read_settings().get("capture_interface") or "").strip()
        available = {item["name"] for item in adapter_list()}
        if interface and interface not in available:
            return jsonify(error="interface is not in the detected adapter list"), 400
        try:
            sniffer = AsyncSniffer(iface=interface or None, prn=_capture_packet, store=False)
            sniffer.start()
            CAPTURE.update(sniffer=sniffer, running=True, interface=interface or "system default",
                           error=None, started=utc_now())
            return jsonify(capture_status())
        except Exception as exc:
            CAPTURE.update(sniffer=None, running=False, interface=None,
                           error=f"{type(exc).__name__}: {str(exc)[:180]}")
            return jsonify(error=CAPTURE["error"]), 503


@app.get("/report.csv")
def report_csv() -> Any:
    incidents = api_incidents().get_json()
    output = io.StringIO()
    fields = ["id", "attack", "category", "severity", "score", "src_ip", "dst_ip", "src_port",
              "dst_port", "protocol", "first_seen", "last_seen", "occurrences", "status", "source", "explanation"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for incident in incidents:
        writer.writerow(incident)
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=ai-threat-incidents.csv"})


@app.get("/report.html")
def report_html() -> Any:
    incidents = api_incidents().get_json()
    rows = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(item.get(key, '') or ''))}</td>" for key in
            ("id", "attack", "severity", "score", "src_ip", "dst_ip", "protocol", "last_seen", "source", "status")) + "</tr>"
        for item in incidents
    )
    document = f"""<!doctype html><meta charset="utf-8"><title>AI Threat Detection report</title>
<style>body{{font:14px Arial,sans-serif;color:#17212c;margin:32px}}h1{{font-size:24px}}p{{color:#46586a}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #cbd4dd;padding:7px;text-align:left}}th{{background:#e8edf2}}small{{color:#526273}}</style>
<h1>AI Threat Detection — Incident Report</h1><p>Generated {html.escape(utc_now())}. Records are local observations; simulated events are explicitly labeled.</p>
<table><thead><tr>{''.join(f'<th>{html.escape(k.replace("_"," ").title())}</th>' for k in ("id","attack","severity","score","src_ip","dst_ip","protocol","last_seen","source","status"))}</tr></thead><tbody>{rows}</tbody></table>
<p><small>Risk scores are evidence-weighted operational scores, not calibrated attack probabilities.</small></p>"""
    return Response(document, mimetype="text/html",
                    headers={"Content-Disposition": "attachment; filename=ai-threat-report.html"})


@app.errorhandler(413)
def request_too_large(_: Exception) -> Any:
    return jsonify(error="upload exceeds configured size limit"), 413


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{app_name}} | SOC</title><style>
:root{color-scheme:dark;--bg:#101720;--panel:#192431;--panel2:#202e3d;--line:#334253;--muted:#a3b2c1;--text:#e9eff5;--blue:#4b9bea;--red:#f16e70;--orange:#f2ad52;--green:#55c49a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 "Segoe UI",Roboto,Arial,sans-serif;min-height:100vh}button,input,select{font:inherit}button{cursor:pointer}
.app{min-height:100vh;display:grid;grid-template-columns:226px minmax(0,1fr);grid-template-rows:58px 1fr}.top{grid-column:1/3;background:#151f2a;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 20px;gap:14px;position:sticky;top:0;z-index:5}
.brand{font-weight:700;font-size:15px;letter-spacing:.2px}.top .context{color:var(--muted);font-size:12px;border-left:1px solid var(--line);padding-left:14px}.topright{margin-left:auto;display:flex;align-items:center;gap:14px;color:var(--muted);font-size:12px}
.sidebar{background:#141e28;border-right:1px solid var(--line);padding:16px 10px;display:flex;flex-direction:column;gap:4px;min-height:calc(100vh - 58px)}.navtitle{font-size:10px;color:#8596a7;font-weight:700;letter-spacing:1px;padding:8px 11px 5px;text-transform:uppercase}
.nav{border:0;background:transparent;color:#becbd7;text-align:left;padding:10px 11px;border-radius:4px;display:flex;gap:11px;align-items:center}.nav:hover,.nav.active{background:#26384a;color:#fff}.nav .ico{width:18px;color:#91a9bf;text-align:center;font-size:13px}.sidefoot{margin-top:auto;border-top:1px solid var(--line);padding:13px 10px;color:var(--muted);font-size:11px}
main{min-width:0;padding:20px 22px 40px;max-width:1800px;width:100%;margin:auto}.page{display:none}.page.active{display:block}.heading{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:17px;gap:14px}.heading h1{font-size:21px;margin:0 0 3px;font-weight:650}.sub{color:var(--muted);font-size:12px}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.btn{background:#26384a;border:1px solid #40546a;border-radius:4px;color:#e8f1f8;padding:8px 11px;font-size:12px}.btn:hover{background:#314b63}.btn.primary{background:#2169ae;border-color:#3284ce}.btn.danger{background:#622e35;border-color:#925058}.btn.small{padding:5px 8px}
.cards{display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:12px;margin-bottom:14px}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:5px}.card{padding:13px 15px;min-height:86px}.cardlabel{color:var(--muted);font-size:11px}.cardvalue{font-size:24px;font-weight:650;margin-top:3px}.cardnote{font-size:10px;color:#9eafbf}
.grid2{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(260px,.7fr);gap:13px;margin-bottom:14px}.panel{padding:15px;min-width:0}.panelhead{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:11px}.panel h2{margin:0;font-size:14px;font-weight:650}.panelnote{color:var(--muted);font-size:11px}.canvaswrap{height:210px;position:relative}.canvaswrap canvas{width:100%;height:100%}.health{display:inline-flex;align-items:center;gap:6px;color:var(--green);font-size:11px}.dot{width:7px;height:7px;background:currentColor;border-radius:50%}.health.degraded{color:var(--orange)}
.tablewrap{overflow:auto;max-width:100%}table{width:100%;border-collapse:collapse;font-size:12px;white-space:nowrap}th{text-align:left;color:#9fafbe;font-weight:600;background:#1c2936;position:sticky;top:0}td,th{padding:9px 10px;border-bottom:1px solid #2d3b49}tbody tr:hover{background:#202e3b}td.wrap{white-space:normal;min-width:220px}.pill{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:650;text-transform:uppercase;background:#314252;color:#c4d2df}.pill.critical{background:#67333a;color:#ffc2c4}.pill.high{background:#61422d;color:#ffce96}.pill.medium{background:#594c2c;color:#f5dc8c}.pill.low{background:#264b40;color:#a8e8d0}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px}.control{padding:8px 9px;border:1px solid #3c4d5e;background:#111a24;color:var(--text);border-radius:4px}.control::placeholder{color:#8798a8}.toolbar .control{min-width:125px}.toolbar input[type=search]{min-width:220px}.split{display:grid;grid-template-columns:1fr 1fr;gap:13px}.metricgrid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.metric{background:#131d27;padding:10px;border-radius:4px}.metric strong{display:block;font-size:17px}.metric span{color:var(--muted);font-size:10px}.mono{font-family:Consolas,monospace;font-size:11px;color:#c1ceda}.muted{color:var(--muted)}.empty{text-align:center;padding:28px;color:var(--muted)}.notice{border-left:3px solid var(--blue);background:#1b2a38;padding:10px 12px;color:#b9c9d8;font-size:12px;margin:10px 0}.notice.warn{border-color:var(--orange)}.notice.error{border-color:var(--red)}.field{display:grid;grid-template-columns:210px minmax(100px,300px);align-items:center;gap:12px;margin:12px 0}.field label{color:#c6d2de}.field input,.field select{width:100%}.modal{position:fixed;inset:0;background:#05090dcc;z-index:10;display:none;place-items:center;padding:20px}.modal.show{display:grid}.modalbox{max-width:850px;max-height:88vh;overflow:auto;background:#182431;border:1px solid #405267;border-radius:6px;padding:20px;width:min(850px,100%)}.modalclose{float:right}.modal pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#c4d4e2;background:#101820;padding:12px;border-radius:4px;font-size:11px}.labgrid{display:grid;grid-template-columns:repeat(3,minmax(160px,1fr));gap:8px}.labcard{background:#131d27;border:1px solid #324456;border-radius:4px;padding:11px}.labcard b{font-size:12px}.labcard p{color:var(--muted);font-size:11px;min-height:34px}.toast{position:fixed;right:20px;bottom:20px;z-index:20;background:#223447;border:1px solid #466079;padding:11px 16px;border-radius:4px;display:none;max-width:400px}.toast.show{display:block}.criticalToast{border-color:var(--red)}
@media(max-width:900px){.app{grid-template-columns:65px minmax(0,1fr)}.sidebar{padding:12px 6px}.nav{justify-content:center;padding:11px 4px}.nav .label,.navtitle,.sidefoot{display:none}.nav .ico{font-size:15px}.grid2{grid-template-columns:1fr}.cards{grid-template-columns:repeat(2,1fr)}main{padding:15px}.top{padding:0 12px}}
@media(max-width:560px){.app{grid-template-columns:1fr;grid-template-rows:54px auto 1fr}.top{grid-column:1}.sidebar{grid-row:2;min-height:auto;position:sticky;top:54px;z-index:4;flex-direction:row;overflow-x:auto;border-right:0;border-bottom:1px solid var(--line);padding:5px}.nav{min-width:52px}.top .context{display:none}main{grid-row:3;padding:13px 10px}.cards{gap:7px}.card{padding:10px;min-height:74px}.cardvalue{font-size:20px}.labgrid{grid-template-columns:1fr 1fr}.field{grid-template-columns:1fr;gap:4px}.heading h1{font-size:19px}}
</style></head><body>
<div class="app"><header class="top"><div class="brand">◈ {{app_name}}</div><div class="context">NETWORK SECURITY OPERATIONS</div><div class="topright"><span id="topip">IPv4: —</span><span id="tophealth" class="health"><i class="dot"></i><span>Checking</span></span><button class="btn small" onclick="logout()">Sign out</button></div></header>
<aside class="sidebar"><div class="navtitle">Workspace</div>
<button class="nav active" data-page="overview"><span class="ico">▦</span><span class="label">Overview</span></button>
<button class="nav" data-page="intelligence"><span class="ico">◉</span><span class="label">Threat intelligence</span></button>
<button class="nav" data-page="incidents"><span class="ico">▤</span><span class="label">Investigations</span></button>
<button class="nav" data-page="model"><span class="ico">⌁</span><span class="label">AI model</span></button>
<button class="nav" data-page="testing"><span class="ico">▷</span><span class="label">Detection lab</span></button>
<button class="nav" data-page="settings"><span class="ico">⚙</span><span class="label">Settings</span></button>
<div class="sidefoot">Local-first · Offline capable<br>Build {{version}}</div></aside><main>
<section id="page-overview" class="page active"><div class="heading"><div><h1>Security overview</h1><div class="sub">Local observations, live capture health, and recent investigations.</div></div><div class="actions"><button class="btn" onclick="refreshAll()">Refresh data</button><a class="btn" href="/report.csv">Export CSV</a><a class="btn" href="/report.html">HTML report</a></div></div>
<div class="cards"><div class="card"><div class="cardlabel">Active incidents</div><div class="cardvalue" id="stat-total">—</div><div class="cardnote">Excludes false positives</div></div><div class="card"><div class="cardlabel">Critical incidents</div><div class="cardvalue" id="stat-critical">—</div><div class="cardnote">Require prompt validation</div></div><div class="card"><div class="cardlabel">Open investigations</div><div class="cardvalue" id="stat-open">—</div><div class="cardnote">Local persisted records</div></div><div class="card"><div class="cardlabel">Capture engine</div><div class="cardvalue" style="font-size:17px" id="stat-capture">—</div><div class="cardnote" id="capture-note">Passive packet capture</div></div></div>
<div class="grid2"><div class="panel"><div class="panelhead"><h2>Incident activity</h2><span class="panelnote">Hourly counts · last 24h</span></div><div class="canvaswrap"><canvas id="trend"></canvas></div></div><div class="panel"><div class="panelhead"><h2>Observed detections</h2><span class="panelnote">Grouped by rule · 24h</span></div><div class="tablewrap"><table><thead><tr><th>Detection</th><th>Count</th></tr></thead><tbody id="attack-summary"></tbody></table></div></div></div>
<div class="panel"><div class="panelhead"><h2>Latest incidents</h2><button class="btn small" onclick="go('incidents')">Investigate all</button></div><div class="tablewrap"><table><thead><tr><th>Detection</th><th>Severity</th><th>Score</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Last seen</th><th>Origin</th></tr></thead><tbody id="latest"></tbody></table></div></div></section>
<section id="page-intelligence" class="page"><div class="heading"><div><h1>Threat intelligence</h1><div class="sub">Local source profiles based only on retained incident observations; no external reputation lookups.</div></div><button class="btn" onclick="loadProfiles()">Refresh</button></div><div class="panel"><div class="panelhead"><h2>Observed source IP profiles</h2><span class="panelnote">Select a row to filter investigations</span></div><div class="tablewrap"><table><thead><tr><th>Source IP</th><th>Incidents</th><th>Critical</th><th>Observed rules</th><th>Last observed</th></tr></thead><tbody id="profiles"></tbody></table></div></div><div class="notice">IP activity is not a reputation verdict. Confirm asset ownership, NAT, and expected behavior before containment.</div></section>
<section id="page-incidents" class="page"><div class="heading"><div><h1>Incident investigation</h1><div class="sub">Search, filter, inspect evidence and timeline, and manage analyst status.</div></div><div class="actions"><a class="btn" href="/report.csv">CSV</a><a class="btn" href="/report.html">HTML</a></div></div><div class="panel"><div class="toolbar"><input id="search" class="control" type="search" placeholder="Search detection, IP, evidence"><select id="severity-filter" class="control"><option value="">All severity</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select><select id="status-filter" class="control"><option value="">All status</option><option>open</option><option>investigating</option><option>resolved</option><option>false_positive</option></select><button class="btn" onclick="loadIncidents()">Apply filters</button><button class="btn" onclick="clearFilters()">Clear</button></div><div class="tablewrap"><table><thead><tr><th>ID</th><th>Detection</th><th>Severity</th><th>Score</th><th>Source</th><th>Destination</th><th>Count</th><th>Status</th><th>Origin</th><th>Last seen</th><th></th></tr></thead><tbody id="incidents"></tbody></table></div></div></section>
<section id="page-model" class="page"><div class="heading"><div><h1>Local AI model</h1><div class="sub">Isolation Forest anomaly scoring plus Random Forest advisory classification.</div></div><button class="btn primary" onclick="trainModel()">Train / retrain locally</button></div><div id="model-overview" class="notice">Loading model details…</div><div class="split"><div class="panel"><div class="panelhead"><h2>Independent holdout evaluation</h2><span class="panelnote">Synthetic labeled data; not real-world performance</span></div><div id="metrics"></div></div><div class="panel"><div class="panelhead"><h2>Feature importance</h2><span class="panelnote">Random Forest split-importance</span></div><div class="tablewrap"><table><thead><tr><th>Feature</th><th>Importance</th></tr></thead><tbody id="feature-importance"></tbody></table></div></div></div><div class="panel" style="margin-top:13px"><div class="panelhead"><h2>Confusion matrix</h2><span class="panelnote">Rows = true class, columns = predicted class</span></div><div class="tablewrap" id="confusion"></div></div><div class="notice warn">Training and test distributions are generated synthetic telemetry for a reproducible project baseline. They are not labeled packet captures; model results do not establish production accuracy. A model label is advisory and does not alone trigger alerts.</div></section>
<section id="page-testing" class="page"><div class="heading"><div><h1>Offline detection lab</h1><div class="sub">Run deterministic, labeled fixtures through the production rule path. No network traffic is generated.</div></div></div><div class="notice">Every resulting record is marked <b>simulated</b>. Documentation-only source/destination addresses and inert request strings are used in examples.</div><div class="labgrid" id="labgrid"></div><div class="panel" style="margin-top:14px"><div class="panelhead"><h2>PCAP investigation and offline replay</h2><span class="panelnote">Local upload only · maximum 24 MiB · packets feed the detector, never the network</span></div><form id="pcap-form"><input class="control" name="file" type="file" accept=".pcap,.pcapng" required><button class="btn primary">Inspect PCAP</button></form><pre id="pcap-result" style="display:none"></pre></div><div class="panel" style="margin-top:14px"><div class="panelhead"><h2>Authentication / application audit event</h2><span class="panelnote">For authorized local logs and monitored test services</span></div><div class="toolbar"><select id="log-type" class="control"><option value="auth">Failed authentication</option><option value="unauthorized">Explicit unauthorized access</option><option value="sqli">SQL injection indicator in HTTP log</option><option value="xss">XSS indicator in HTTP log</option></select><input id="log-src" class="control" placeholder="Source IP (optional)"><button class="btn" onclick="submitLogEvent()">Submit one audit record</button></div><div class="sub">Repeated failed authentication records trigger the brute-force rule at its configured threshold.</div></div></section>
<section id="page-settings" class="page"><div class="heading"><div><h1>Settings and engine health</h1><div class="sub">Local thresholds, adapter selection, and passive live capture controls.</div></div><button class="btn" onclick="loadSettings()">Refresh</button></div><div class="grid2"><div class="panel"><div class="panelhead"><h2>Detection thresholds</h2><span class="panelnote">Bounded values; persisted locally</span></div><form id="settings-form"><div id="settings-fields"></div><button class="btn primary">Save thresholds</button></form></div><div class="panel"><div class="panelhead"><h2>Capture adapter</h2><span class="panelnote">Only current primary IPv4 is displayed in header</span></div><div class="field"><label>Selected packet adapter</label><select class="control" id="interface-select"><option value="">System default</option></select></div><div class="actions"><button class="btn primary" id="capture-toggle" onclick="toggleCapture()">Start passive capture</button><span id="capture-state" class="muted">Stopped</span></div><div class="notice">Capture may require administrator/root privileges and a supported driver. If unavailable, offline PCAP inspection and the labeled lab remain available.</div><div class="panelhead" style="margin-top:16px"><h2>Engine health</h2><button class="btn small" onclick="loadHealth()">Check</button></div><pre id="health-result"></pre></div></div><div class="panel"><div class="panelhead"><h2>Access and storage</h2></div><div class="sub">Dashboard listens on localhost by default. LAN binding is opt-in via <code>--host lan</code> and accepts only loopback or RFC1918 private clients, with authenticated sessions. Database and model live under <code>~/.aithreat</code> by default.</div></div></section>
</main></div><div id="modal" class="modal" onclick="if(event.target===this)closeModal()"><div class="modalbox"><button class="btn small modalclose" onclick="closeModal()">Close</button><div id="modalbody"></div></div></div><div id="toast" class="toast"></div>
<script>
const CSRF={{csrf|tojson}};
const scenarios=[
['port-scan','Port scanning','Multiple destination ports touched in a time window.'],
['syn-flood','SYN flood','High SYN-only rate on a source flow.'],
['dos','DoS / DDoS indicators','High destination volume across source addresses.'],
['bruteforce','Brute-force login','Repeated failed authentication audit records.'],
['unauthorized','Unauthorized access','Explicit unauthorized marker in an audit record.'],
['arp-spoof','ARP mapping change','Conflicting observed address-to-MAC mapping.'],
['dns','Suspicious DNS','Repeated DNS query heuristic.'],
['dns-tunnel','Possible DNS tunneling','Long, high-entropy DNS label heuristic.'],
['sqli','SQL injection signature','Inert HTTP request string matches configured SQLi markers.'],
['xss','Cross-site scripting signature','Inert HTTP request string matches configured XSS markers.'],
['abnormal','Abnormal behavior','High-feature flow passed to local anomaly model.'],
['connections','Suspicious connection pattern','Repeated connection attempts concentrated on one target.']];
let activePage='overview', overviewState=null, seenIncidentIds=new Set();
function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function toast(msg,critical=false){const t=document.getElementById('toast');t.textContent=msg;t.className='toast show'+(critical?' criticalToast':'');setTimeout(()=>t.classList.remove('show'),4500);}
async function api(url,options={}){options.headers={...(options.headers||{}),'X-CSRF-Token':CSRF};if(options.body&&!(options.body instanceof FormData))options.headers['Content-Type']='application/json';const r=await fetch(url,options);if(r.status===401){location.href='/login';throw Error('Authentication required');}const d=await r.json().catch(()=>({error:'Invalid server response'}));if(!r.ok)throw Error(d.error||`Request failed (${r.status})`);return d;}
function go(page){activePage=page;document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id==='page-'+page));document.querySelectorAll('.nav').forEach(n=>n.classList.toggle('active',n.dataset.page===page));if(page==='overview')loadOverview();if(page==='intelligence')loadProfiles();if(page==='incidents')loadIncidents();if(page==='model')loadModel();if(page==='settings'){loadSettings();loadHealth();}}
document.querySelectorAll('.nav').forEach(n=>n.addEventListener('click',()=>go(n.dataset.page)));
function rowIncident(x,compact=false){return `<tr><td>${compact?'':esc(x.id)}</td><td><button class="btn small" onclick="showIncident(${x.id})">${esc(x.attack)}</button></td><td><span class="pill ${esc(x.severity)}">${esc(x.severity)}</span></td><td>${esc(x.score)}</td><td class="mono">${esc(x.src_ip||'—')}</td><td class="mono">${esc(x.dst_ip||'—')}</td>${compact?`<td>${esc(x.protocol||'—')}</td><td>${esc(x.last_seen)}</td><td>${esc(x.source)}</td>`:`<td>${esc(x.occurrences)}</td><td>${esc(x.status)}</td><td>${esc(x.source)}</td><td>${esc(x.last_seen)}</td><td><button class="btn small" onclick="showIncident(${x.id})">Evidence</button></td>`}</tr>`}
function drawTrend(items){const c=document.getElementById('trend'),ctx=c.getContext('2d'),rect=c.getBoundingClientRect(),dpr=window.devicePixelRatio||1;c.width=rect.width*dpr;c.height=rect.height*dpr;ctx.scale(dpr,dpr);const w=rect.width,h=rect.height,pad=30;ctx.clearRect(0,0,w,h);ctx.strokeStyle='#344452';ctx.fillStyle='#9eafbd';ctx.font='10px Segoe UI';for(let i=0;i<4;i++){let y=pad+(h-pad*1.5)*i/3;ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(w-8,y);ctx.stroke();ctx.fillText(String(i),5,y+3);}const max=Math.max(1,...items.map(x=>x.n));if(!items.length){ctx.fillText('No retained observations in this period',pad+8,h/2);return;}ctx.strokeStyle='#56a9ef';ctx.lineWidth=2;ctx.beginPath();items.forEach((v,i)=>{const x=pad+(w-pad-10)*(items.length<2?.5:i/(items.length-1)),y=h-pad-(h-pad*1.5)*v.n/max;if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);});ctx.stroke();items.forEach((v,i)=>{const x=pad+(w-pad-10)*(items.length<2?.5:i/(items.length-1)),y=h-pad-(h-pad*1.5)*v.n/max;ctx.fillStyle='#56a9ef';ctx.fillRect(x-2,y-2,4,4);});}
async function loadOverview(){try{const d=await api('/api/overview');for(const item of d.latest){if(!seenIncidentIds.has(item.id)&&item.severity==='critical'&&seenIncidentIds.size)toast(`Critical observation: ${item.attack} · incident #${item.id}`,true);seenIncidentIds.add(item.id);}if(seenIncidentIds.size>1000)seenIncidentIds=new Set(d.latest.map(x=>x.id));overviewState=d;document.getElementById('stat-total').textContent=d.total_active;document.getElementById('stat-critical').textContent=d.critical_active;document.getElementById('stat-open').textContent=d.open_incidents;document.getElementById('stat-capture').textContent=d.capture.running?'Running':'Stopped';document.getElementById('capture-note').textContent=d.capture.error||d.capture.interface||'Passive packet capture';document.getElementById('topip').textContent='IPv4: '+(d.primary_ipv4||'unavailable');document.getElementById('latest').innerHTML=d.latest.length?d.latest.map(x=>rowIncident(x,true)).join(''):'<tr><td class="empty" colspan="9">No incident observations retained yet.</td></tr>';document.getElementById('attack-summary').innerHTML=d.attacks_24h.length?d.attacks_24h.map(x=>`<tr><td>${esc(x.attack)}</td><td>${esc(x.n)}</td></tr>`).join(''):'<tr><td colspan="2" class="empty">No detections in this period.</td></tr>';drawTrend(d.hourly);const h=document.getElementById('tophealth');h.classList.toggle('degraded',d.engine!=='healthy');h.lastElementChild.textContent=d.engine;}catch(e){toast(e.message);}}
async function refreshAll(){await loadOverview();if(activePage==='incidents')loadIncidents();}
async function loadIncidents(){try{const p=new URLSearchParams();for(const [id,key] of [['search','q'],['severity-filter','severity'],['status-filter','status']]){const v=document.getElementById(id).value;if(v)p.set(key,v);}const rows=await api('/api/incidents?'+p);document.getElementById('incidents').innerHTML=rows.length?rows.map(x=>rowIncident(x)).join(''):'<tr><td colspan="11" class="empty">No incidents match the selected filters.</td></tr>';}catch(e){toast(e.message);}}
function clearFilters(){['search','severity-filter','status-filter'].forEach(id=>document.getElementById(id).value='');loadIncidents();}
async function showIncident(id){try{const x=await api('/api/incidents/'+id);document.getElementById('modalbody').innerHTML=`<h2>${esc(x.attack)} <span class="pill ${esc(x.severity)}">${esc(x.severity)} · ${esc(x.score)}/100</span></h2><p class="sub">${esc(x.category)} · ${esc(x.protocol)} · ${esc(x.first_seen)} → ${esc(x.last_seen)}</p><p><b>Source</b> <span class="mono">${esc(x.src_ip||'not supplied')}:${esc(x.src_port||'—')}</span> &nbsp; <b>Destination</b> <span class="mono">${esc(x.dst_ip||'not supplied')}:${esc(x.dst_port||'—')}</span></p><p><b>Origin:</b> ${esc(x.source)} · <b>Occurrences:</b> ${esc(x.occurrences)} · <b>MITRE:</b> ${esc(x.mitre||'not mapped')}</p><h3>Evidence and model contribution</h3><pre>${esc(JSON.stringify(x.evidence,null,2))}</pre><h3>Explanation</h3><p>${esc(x.explanation)}</p><h3>Response guidance</h3><p>${esc(x.mitigation||'Corroborate telemetry before response.')}</p><h3>Investigation timeline</h3><pre>${esc(JSON.stringify(x.timeline,null,2))}</pre><div class="actions"><select id="incident-status" class="control"><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select><button class="btn primary" onclick="setIncidentStatus(${x.id})">Save status</button></div>`;document.getElementById('incident-status').value=x.status;document.getElementById('modal').classList.add('show');}catch(e){toast(e.message);}}
function closeModal(){document.getElementById('modal').classList.remove('show');}
async function setIncidentStatus(id){try{const status=document.getElementById('incident-status').value;await api(`/api/incidents/${id}/status`,{method:'POST',body:JSON.stringify({status})});toast('Incident status updated');closeModal();loadIncidents();loadOverview();}catch(e){toast(e.message);}}
async function loadProfiles(){try{const rows=await api('/api/ip-profiles');document.getElementById('profiles').innerHTML=rows.length?rows.map(x=>`<tr onclick="go('incidents');document.getElementById('search').value='${esc(x.src_ip)}';loadIncidents()" style="cursor:pointer"><td class="mono">${esc(x.src_ip)}</td><td>${esc(x.incidents)}</td><td>${esc(x.critical)}</td><td>${esc(x.attacks||'')}</td><td>${esc(x.last_seen)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No source profiles yet.</td></tr>';}catch(e){toast(e.message);}}
async function loadModel(){try{const d=await api('/api/model'),m=d.metrics||{};document.getElementById('model-overview').innerHTML=`<b>Status:</b> ${esc(d.status)} &nbsp; <b>Training:</b> ${esc(d.trained_at||'not run')} &nbsp; <b>Source:</b> ${esc(d.data_source||'unavailable')}<br><b>Features:</b> ${d.features.map(esc).join(', ')}<br><span class="sub">Inference anomaly score is not a calibrated probability. Forest classification is advisory only.</span>`;document.getElementById('metrics').innerHTML=`<p class="sub">${esc(m.test_source||'No evaluation available')}</p><div class="metricgrid"><div class="metric"><strong>${Number(m.precision_macro||0).toFixed(3)}</strong><span>Macro precision</span></div><div class="metric"><strong>${Number(m.recall_macro||0).toFixed(3)}</strong><span>Macro recall</span></div><div class="metric"><strong>${Number(m.f1_macro||0).toFixed(3)}</strong><span>Macro F1</span></div><div class="metric"><strong>${Number(m.false_positive_rate_benign||0).toFixed(3)}</strong><span>Benign false-positive rate</span></div><div class="metric"><strong>${esc(m.samples||0)}</strong><span>Holdout samples</span></div><div class="metric"><strong>${esc(d.classes?.length||0)}</strong><span>Labels</span></div></div>`;document.getElementById('feature-importance').innerHTML=Object.entries(d.feature_importance||{}).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`<tr><td>${esc(k)}</td><td>${Number(v).toFixed(5)}</td></tr>`).join('');const labels=m.labels||[],cm=m.confusion_matrix||[];document.getElementById('confusion').innerHTML=labels.length?`<table><thead><tr><th>True \\ Pred.</th>${labels.map(l=>`<th>${esc(l)}</th>`).join('')}</tr></thead><tbody>${labels.map((l,i)=>`<tr><th>${esc(l)}</th>${(cm[i]||[]).map(v=>`<td>${esc(v)}</td>`).join('')}</tr>`).join('')}</tbody></table>`:'No evaluation matrix';}catch(e){toast(e.message);}}
async function trainModel(){try{toast('Training local model…');await api('/api/model/train',{method:'POST',body:'{}'});await loadModel();toast('Model trained and saved locally.');}catch(e){toast(e.message);}}
async function runScenario(scenario){try{const d=await api('/api/lab/'+scenario,{method:'POST',body:'{}'});const n=d.observations.length;toast(`${n} simulated observation(s); no traffic sent.`,d.observations.some(x=>x.severity==='critical'));loadOverview();}catch(e){toast(e.message);}}
document.getElementById('labgrid').innerHTML=scenarios.map(([id,name,desc])=>`<div class="labcard"><b>${esc(name)}</b><p>${esc(desc)}</p><button class="btn small" onclick="runScenario('${esc(id)}')">Run simulated check</button></div>`).join('');
async function loadSettings(){try{const d=await api('/api/settings'),s=d.settings;const defs=[['scan_ports','Distinct ports for scan'],['syn_flood_packets','SYN packets threshold'],['dos_packets','DoS destination packets threshold'],['bruteforce_failures','Authentication failures threshold'],['dns_queries','Repeated DNS query threshold'],['anomaly_threshold','Model anomaly score threshold (0–1)']];document.getElementById('settings-fields').innerHTML=defs.map(([k,label])=>`<div class="field"><label for="set-${k}">${label}</label><input class="control" id="set-${k}" name="${k}" type="number" step="${k==='anomaly_threshold'?.01:1}" value="${esc(s[k])}"></div>`).join('');const sel=document.getElementById('interface-select');sel.innerHTML='<option value="">System default</option>'+d.adapters.map(a=>`<option value="${esc(a.name)}">${esc(a.name)}${a.primary?' · current primary':''}</option>`).join('');sel.value=s.capture_interface||'';const c=await api('/api/health');document.getElementById('capture-state').textContent=c.capture.running?`Running on ${c.capture.interface}`:'Stopped';document.getElementById('capture-toggle').textContent=c.capture.running?'Stop passive capture':'Start passive capture';}catch(e){toast(e.message);}}
document.getElementById('settings-form').addEventListener('submit',async e=>{e.preventDefault();const data={};new FormData(e.target).forEach((v,k)=>data[k]=v);data.capture_interface=document.getElementById('interface-select').value;try{await api('/api/settings',{method:'POST',body:JSON.stringify(data)});toast('Settings saved');}catch(err){toast(err.message);}});
async function toggleCapture(){try{const running=document.getElementById('capture-toggle').textContent.startsWith('Stop');const d=await api('/api/capture',{method:'POST',body:JSON.stringify({action:running?'stop':'start',interface:document.getElementById('interface-select').value})});document.getElementById('capture-state').textContent=d.running?`Running on ${d.interface}`:'Stopped';document.getElementById('capture-toggle').textContent=d.running?'Stop passive capture':'Start passive capture';toast(d.running?'Passive capture started':'Capture stopped');loadOverview();}catch(e){toast(e.message);}}
async function loadHealth(){try{document.getElementById('health-result').textContent=JSON.stringify(await api('/api/health'),null,2);}catch(e){toast(e.message);}}
async function submitLogEvent(){const type=document.getElementById('log-type').value,src=document.getElementById('log-src').value;let event;if(type==='auth')event={type:'auth',outcome:'failure',service:'demo-auth-log',username:'demo-user',src_ip:src||null};else if(type==='unauthorized')event={type:'auth',outcome:'success',unauthorized:true,service:'demo-app-log',username:'demo-user',src_ip:src||null};else event={type:'http',request:type==='sqli'?"GET /?q=1' UNION SELECT password--":"GET /?q=%3Cscript%3E",src_ip:src||null,dst_port:8080};try{const d=await api('/api/logs',{method:'POST',body:JSON.stringify(event)});toast(d.observations.length?`${d.observations.length} detection(s) emitted`:'Audit event recorded; rule threshold not yet reached');loadOverview();}catch(e){toast(e.message);}}
document.getElementById('pcap-form').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.target);try{const d=await api('/api/pcap',{method:'POST',body:f});const p=document.getElementById('pcap-result');p.style.display='block';p.textContent=JSON.stringify(d,null,2);toast(`Inspected ${d.packets_processed} packets offline`);loadOverview();}catch(err){toast(err.message);}});
async function logout(){try{await api('/logout',{method:'POST'});location.href='/login';}catch(e){toast(e.message);}}
document.getElementById('search').addEventListener('keydown',e=>{if(e.key==='Enter')loadIncidents();});window.addEventListener('resize',()=>{if(overviewState)drawTrend(overviewState.hourly);});loadOverview();setInterval(()=>{loadOverview();if(activePage==='incidents')loadIncidents();},5000);
</script></body></html>"""


def stop_capture() -> None:
    with CAPTURE_LOCK:
        sniffer = CAPTURE.get("sniffer")
        CAPTURE.update(sniffer=None, running=False, interface=None)
    if sniffer:
        try:
            sniffer.stop()
        except Exception:
            pass


def run_self_tests() -> bool:
    class DetectionTests(unittest.TestCase):
        def setUp(self) -> None:
            self.client = app.test_client()
            self.client.post("/login", data={"password": login_password()})
            with self.client.session_transaction() as sess:
                self.csrf = sess["csrf"]

        def post(self, url: str, data: dict[str, Any]) -> Any:
            return self.client.post(url, json=data, headers={"X-CSRF-Token": self.csrf})

        def test_model_training_and_inference(self) -> None:
            self.assertEqual(MODEL["forest"].n_features_in_, len(FEATURES))
            original_threshold = read_settings()["anomaly_threshold"]
            save_settings({"anomaly_threshold": 0.61})
            try:
                result = model_inference({"packets_per_second": 200, "syn_ratio": .99})
                self.assertIn("anomaly_score", result)
                self.assertIn("classification", result)
                self.assertEqual(result["anomaly_score_threshold"], 0.61)
                self.assertIn("confusion_matrix", MODEL["metrics"])
            finally:
                save_settings({"anomaly_threshold": original_threshold})

        def test_sqli_and_xss_distinct_rules(self) -> None:
            a = inspect_http_payload(b"GET /?id=1 UNION SELECT user--", "192.0.2.1", "198.51.100.2", 50000, 8080, "test")
            b = inspect_http_payload(b"GET /?q=<script>alert(1)</script>", "192.0.2.1", "198.51.100.2", 50000, 8080, "test")
            self.assertEqual(a[0]["attack"], "SQL Injection Attempts")
            self.assertEqual(b[0]["attack"], "Cross-Site Scripting Attempts")

        def test_packet_rules_and_benign_baseline(self) -> None:
            if IP is None:
                self.skipTest("Scapy is unavailable")
            from scapy.all import ARP as ScapyARP, DNS as ScapyDNS, DNSQR as ScapyDNSQR
            from scapy.all import Ether, IP as ScapyIP, TCP as ScapyTCP, UDP as ScapyUDP
            ordinary = Ether() / ScapyIP(src="192.0.2.181", dst="198.51.100.181") / ScapyUDP(sport=43000, dport=12345)
            self.assertEqual(inspect_packet(ordinary, source="test"), [])

            scanner, target = "192.0.2.182", "198.51.100.182"
            for port in range(12000, 12000 + int(read_settings()["scan_ports"])):
                scan_packet = Ether() / ScapyIP(src=scanner, dst=target) / ScapyTCP(sport=42000, dport=port, flags="S")
                detections = inspect_packet(scan_packet, source="test")
            self.assertIn("Port Scanning", [item["attack"] for item in detections])

            flood_src, flood_dst = "192.0.2.183", "198.51.100.183"
            detections = []
            for _ in range(int(read_settings()["syn_flood_packets"])):
                syn = Ether() / ScapyIP(src=flood_src, dst=flood_dst) / ScapyTCP(sport=42100, dport=443, flags="S")
                detections.extend(inspect_packet(syn, source="test"))
            self.assertIn("SYN Flood", [item["attack"] for item in detections])

            old_dos = read_settings()["dos_packets"]
            save_settings({"dos_packets": 30})
            try:
                dos_dst = "198.51.100.184"
                detections = []
                for source_ip in ("192.0.2.184", "192.0.2.185", "192.0.2.186"):
                    for _ in range(10):
                        packet = Ether() / ScapyIP(src=source_ip, dst=dos_dst) / ScapyUDP(sport=43001, dport=9000)
                        detections.extend(inspect_packet(packet, source="test"))
                self.assertIn("DoS/DDoS Indicators", [item["attack"] for item in detections])
            finally:
                save_settings({"dos_packets": old_dos})

            query = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno.payload.example"
            dns_packet = Ether() / ScapyIP(src="192.0.2.187", dst="198.51.100.187") / ScapyUDP(sport=53001, dport=53) / ScapyDNS(
                rd=1, qd=ScapyDNSQR(qname=query)
            )
            dns_results = inspect_packet(dns_packet, source="test")
            self.assertIn("Possible DNS Tunneling", [item["attack"] for item in dns_results])

            arp_ip = "192.0.2.188"
            with STATE_LOCK:
                ARP_BINDINGS[arp_ip] = "02:00:00:00:00:01"
            arp_packet = Ether() / ScapyARP(op=2, psrc=arp_ip, hwsrc="02:00:00:00:00:02")
            arp_results = inspect_packet(arp_packet, source="test")
            self.assertIn("ARP Spoofing", [item["attack"] for item in arp_results])

        def test_auth_threshold_and_unauthorized(self) -> None:
            records = [ingest_log_event({"type": "auth", "src_ip": "192.0.2.3", "service": "test-auth",
                "outcome": "failure"}, source="test") for _ in range(read_settings()["bruteforce_failures"])]
            self.assertTrue(any(x["attack"] == "Brute-Force Login Attempts" for group in records for x in group))
            out = ingest_log_event({"type": "auth", "src_ip": "192.0.2.4", "outcome": "success",
                "unauthorized": True}, source="test")
            self.assertEqual(out[0]["attack"], "Unauthorized Access")

        def test_incident_persistence_and_duplicate_correlation(self) -> None:
            args = ("Port Scanning", "Network", "192.0.2.5", "198.51.100.5", None, 443, "TCP",
                    {"unique_destination_ports_in_window": 18}, {"unique_dst_ports": 18},
                    "unit test scan evidence")
            first = record_incident(*args, source="test")
            second = record_incident(*args, source="test")
            self.assertEqual(first["id"], second["id"])
            self.assertGreaterEqual(second["occurrences"], 2)
            response = self.client.get(f"/api/incidents/{first['id']}")
            self.assertEqual(response.status_code, 200)
            self.assertIn("timeline", response.get_json())

        def test_dashboard_endpoints_and_settings_validation(self) -> None:
            self.assertEqual(self.client.get("/").status_code, 200)
            self.assertEqual(self.client.get("/api/overview").status_code, 200)
            self.assertEqual(self.client.get("/api/health").status_code, 200)
            bad = self.post("/api/settings", {"scan_ports": 1})
            self.assertEqual(bad.status_code, 400)
            lab = self.post("/api/lab/xss", {})
            self.assertEqual(lab.status_code, 200)
            self.assertTrue(lab.get_json()["simulated"])
            self.assertEqual(self.client.get("/report.csv").status_code, 200)
            self.assertEqual(self.client.get("/report.html").status_code, 200)

        def test_every_lab_scenario_emits_its_expected_detection(self) -> None:
            expected = {
                "port-scan": "Port Scanning", "syn-flood": "SYN Flood",
                "dos": "DoS/DDoS Indicators", "bruteforce": "Brute-Force Login Attempts",
                "unauthorized": "Unauthorized Access", "arp-spoof": "ARP Spoofing",
                "dns": "Suspicious DNS Activity", "dns-tunnel": "Possible DNS Tunneling",
                "sqli": "SQL Injection Attempts", "xss": "Cross-Site Scripting Attempts",
                "abnormal": "Abnormal Network Behavior",
                "connections": "Suspicious Connection Patterns",
            }
            for scenario, attack in expected.items():
                with self.subTest(scenario=scenario):
                    response = self.post(f"/api/lab/{scenario}", {})
                    self.assertEqual(response.status_code, 200, response.get_json())
                    data = response.get_json()
                    self.assertTrue(data["simulated"])
                    self.assertIn(attack, [x["attack"] for x in data["observations"]])
                    self.assertTrue(all(x["source"] == "simulated" for x in data["observations"]))
                    if scenario == "arp-spoof":
                        evidence = self.client.get(f"/api/incidents/{data['observations'][0]['id']}").get_json()["evidence"]
                        self.assertEqual(evidence["observation_status"], "simulated test event")

        def test_passive_pcap_upload(self) -> None:
            if sniff is None:
                self.skipTest("Scapy is unavailable")
            from scapy.all import Ether, IP as ScapyIP, UDP as ScapyUDP, wrpcap
            with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
                wrpcap(tmp.name, [Ether() / ScapyIP(src="192.0.2.21", dst="198.51.100.22") / ScapyUDP(sport=53000, dport=53)])
                tmp.seek(0)
                response = self.client.post(
                    "/api/pcap", data={"file": (io.BytesIO(tmp.read()), "ordinary.pcap")},
                    headers={"X-CSRF-Token": self.csrf}, content_type="multipart/form-data",
                )
            self.assertEqual(response.status_code, 200, response.get_json())
            self.assertEqual(response.get_json()["packets_processed"], 1)
            self.assertEqual(response.get_json()["source"], "pcap")

        def test_filter_and_false_positive_workflow(self) -> None:
            response = self.client.get("/api/incidents?severity=critical&limit=2")
            self.assertEqual(response.status_code, 200)
            rows = self.client.get("/api/incidents?limit=1").get_json()
            if rows:
                update = self.post(f"/api/incidents/{rows[0]['id']}/status", {"status": "false_positive"})
                self.assertEqual(update.status_code, 200)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DetectionTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return result.wasSuccessful()


def main() -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--host", choices=("localhost", "lan", "auto"), default=os.environ.get("AITHREAT_BIND", "localhost"),
                        help="localhost (default), lan (all interfaces), or auto (primary private IPv4)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("AITHREAT_PORT", "5000")))
    parser.add_argument("--self-test", action="store_true", help="Run offline backend tests and exit")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    initialize_db()
    train_model()
    if args.self_test:
        return 0 if run_self_tests() else 1
    if args.host == "localhost":
        host = "127.0.0.1"
    elif args.host == "lan":
        host = "0.0.0.0"
    else:
        host = primary_ipv4()
        if not host or not ipaddress.ip_address(host).is_private:
            parser.error("could not identify an active private IPv4 address for --host auto")
    password = login_password()
    print(f"{APP_NAME} is listening at http://{host}:{args.port}/")
    if not os.environ.get("AITHREAT_PASSWORD"):
        print(f"Dashboard password: {password}")
    try:
        app.run(host=host, port=args.port, threaded=True, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        pass
    finally:
        stop_capture()
    return 0


initialize_db()
train_model()

if __name__ == "__main__":
    raise SystemExit(main())
