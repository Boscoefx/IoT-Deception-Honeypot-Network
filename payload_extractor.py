"""
Payload Extractor — Healthcare IoT Honeypot Network
====================================================
Processes files dropped by attackers onto the honeypot.
Hashes each file, identifies file type, and extracts
indicators of compromise (IOCs) for threat reporting.

Usage:
    python scripts/payload_extractor.py --downloads-dir logs/downloads/
    python scripts/payload_extractor.py --file suspicious_binary
"""

import os
import hashlib
import json
import subprocess
import argparse
import sqlite3
import re
from pathlib import Path
from datetime import datetime


# ── Hashing ───────────────────────────────────────────────────

def hash_file(file_path: str) -> dict:
    """Compute MD5, SHA1, and SHA256 hashes of a file."""
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}


# ── File Type Detection ────────────────────────────────────────

MAGIC_BYTES = {
    b"\x7fELF": "ELF executable (Linux binary)",
    b"MZ": "PE executable (Windows binary)",
    b"\xca\xfe\xba\xbe": "Mach-O binary (macOS)",
    b"#!/": "Shell script",
    b"#!": "Script",
    b"PK\x03\x04": "ZIP archive",
    b"\x1f\x8b": "Gzip archive",
    b"BZh": "Bzip2 archive",
    b"\xfd7zXZ": "XZ archive",
}

def detect_file_type(file_path: str) -> str:
    """Detect file type by magic bytes."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
        for magic, description in MAGIC_BYTES.items():
            if header.startswith(magic):
                return description
        # Check if it's text
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                f.read(512)
            return "Text file"
        except UnicodeDecodeError:
            return "Unknown binary"
    except Exception:
        return "Unreadable"


# ── String Extraction ──────────────────────────────────────────

def extract_strings(file_path: str, min_length: int = 6) -> list[str]:
    """Extract printable ASCII strings from binary — classic malware analysis."""
    strings = []
    current = ""
    try:
        with open(file_path, "rb") as f:
            for byte in f.read():
                char = chr(byte)
                if char.isprintable() and char != "\n":
                    current += char
                else:
                    if len(current) >= min_length:
                        strings.append(current)
                    current = ""
    except Exception:
        pass
    return strings[:500]  # Cap at 500 strings


# ── IOC Extraction ─────────────────────────────────────────────

IP_PATTERN = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
URL_PATTERN = re.compile(r"https?://[^\s\"']+")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|ru|cn|xyz|top|cc)\b")
BITCOIN_PATTERN = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")

def extract_iocs(strings: list[str]) -> dict:
    """Extract Indicators of Compromise from string list."""
    all_text = " ".join(strings)
    return {
        "ips": list(set(IP_PATTERN.findall(all_text))),
        "urls": list(set(URL_PATTERN.findall(all_text))),
        "domains": list(set(DOMAIN_PATTERN.findall(all_text))),
        "bitcoin_addresses": list(set(BITCOIN_PATTERN.findall(all_text))),
    }


# ── Ransomware Indicator Detection ────────────────────────────

RANSOMWARE_KEYWORDS = [
    "encrypt", "ransom", "bitcoin", "decrypt", "locked", "your files",
    "pay", "recovery key", "aes", "rsa", "onion", ".tor", "tor browser",
    "wallet", "deadline", "payment", "restore", "shadow", "vssadmin"
]

BOTNET_KEYWORDS = [
    "mirai", "qbot", "gafgyt", "tsunami", "xorddos", "bill.gates",
    "/bin/busybox", "wget http", "curl http", "chmod 777", "/tmp/",
    "telnet", "scanner", "brute", "spray"
]

def classify_malware(strings: list[str], file_type: str) -> dict:
    """Heuristic classification of dropped malware."""
    all_text = " ".join(strings).lower()

    ransomware_score = sum(1 for kw in RANSOMWARE_KEYWORDS if kw in all_text)
    botnet_score = sum(1 for kw in BOTNET_KEYWORDS if kw in all_text)

    classification = "Unknown"
    confidence = "Low"

    if ransomware_score >= 3:
        classification = "Ransomware"
        confidence = "High" if ransomware_score >= 5 else "Medium"
    elif botnet_score >= 3:
        classification = "IoT Botnet / DDoS"
        confidence = "High" if botnet_score >= 5 else "Medium"
    elif "ELF" in file_type:
        classification = "Linux ELF Binary (unknown purpose)"
        confidence = "Low"

    return {
        "classification": classification,
        "confidence": confidence,
        "ransomware_indicators": ransomware_score,
        "botnet_indicators": botnet_score,
    }


# ── Full Analysis ──────────────────────────────────────────────

def analyze_payload(file_path: str) -> dict:
    """Run full analysis pipeline on a single file."""
    print(f"[+] Analyzing: {file_path}")
    size = os.path.getsize(file_path)
    hashes = hash_file(file_path)
    file_type = detect_file_type(file_path)
    strings = extract_strings(file_path)
    iocs = extract_iocs(strings)
    classification = classify_malware(strings, file_type)

    report = {
        "file": os.path.basename(file_path),
        "size_bytes": size,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "hashes": hashes,
        "file_type": file_type,
        "classification": classification,
        "iocs": iocs,
        "strings_sample": strings[:30],  # First 30 strings for report
    }

    print(f"  Type: {file_type}")
    print(f"  SHA256: {hashes['sha256']}")
    print(f"  Classification: {classification['classification']} ({classification['confidence']} confidence)")
    print(f"  IOCs: {len(iocs['ips'])} IPs, {len(iocs['urls'])} URLs, {len(iocs['domains'])} domains")

    return report


def process_downloads_directory(downloads_dir: str, db_path: str = "honeypot.db"):
    """Analyze all files in Cowrie's downloads directory."""
    downloads_dir = Path(downloads_dir)
    reports = []

    for file_path in downloads_dir.rglob("*"):
        if file_path.is_file():
            report = analyze_payload(str(file_path))
            reports.append(report)

            # Update database
            conn = sqlite3.connect(db_path)
            conn.execute("""
                UPDATE payloads SET sha256 = ? WHERE file_path LIKE ?
            """, (report["hashes"]["sha256"], f"%{report['file']}%"))
            conn.commit()
            conn.close()

            # Save individual report
            report_path = file_path.parent / f"{file_path.name}_analysis.json"
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"  Report: {report_path}")

    print(f"\n[+] Analyzed {len(reports)} payloads")
    return reports


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Payload Extractor & Analyzer")
    parser.add_argument("--downloads-dir", help="Cowrie downloads directory")
    parser.add_argument("--file", help="Analyze a single file")
    parser.add_argument("--db", default="honeypot.db", help="SQLite database path")
    args = parser.parse_args()

    if args.file:
        report = analyze_payload(args.file)
        print(json.dumps(report, indent=2))
    elif args.downloads_dir:
        process_downloads_directory(args.downloads_dir, args.db)
    else:
        parser.print_help()
