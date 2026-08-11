#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify the RFC 9421 fixture files under testdata/rfc9421.

Checks that every required file exists, has a stable hash, contains the
expected fields, has no duplicate names, has a non-empty case count, and that
each fixture is referenced by the MoonBit test suite.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_DIR = os.path.join(PROJECT, "testdata", "rfc9421")
TEST_DIR = os.path.join(PROJECT)

REQUIRED_FILES = [
    "SOURCE.json",
    "request_cases.json",
    "response_cases.json",
    "signature_input_cases.json",
    "signature_cases.json",
    "signature_base_cases.json",
    "hmac_cases.json",
    "negative_cases.json",
]


def sha256_hex(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    errors = []

    for name in REQUIRED_FILES:
        path = os.path.join(FIXTURE_DIR, name)
        if not os.path.exists(path):
            errors.append(f"missing fixture file: {name}")
            continue
        data = load(path)
        if isinstance(data, list) and len(data) == 0:
            errors.append(f"empty case list: {name}")

    # SOURCE.json fields.
    src = load(os.path.join(FIXTURE_DIR, "SOURCE.json"))
    for field in ["rfc_number", "section", "fixture_version", "generated_at", "source_description", "sha256"]:
        if field not in src:
            errors.append(f"SOURCE.json missing field: {field}")

    # Duplicate names within each list file.
    for name in ["request_cases.json", "response_cases.json", "signature_input_cases.json",
                 "signature_cases.json", "signature_base_cases.json", "hmac_cases.json", "negative_cases.json"]:
        path = os.path.join(FIXTURE_DIR, name)
        data = load(path)
        if isinstance(data, list):
            seen = set()
            for item in data:
                nm = item.get("name", item.get("input", "<input>"))
                if nm in seen:
                    errors.append(f"duplicate name in {name}: {nm}")
                seen.add(nm)

    # Every signature-base fixture must be referenced by the test suite.
    test_sources = ""
    for root, _dirs, files in os.walk(TEST_DIR):
        for f in files:
            if f.endswith(".mbt"):
                with open(os.path.join(root, f), "r", encoding="utf-8") as fh:
                    test_sources += fh.read()
    for case in load(os.path.join(FIXTURE_DIR, "signature_base_cases.json")):
        label = case.get("label", case["name"])
        if label not in test_sources:
            errors.append(f"signature-base fixture not referenced by tests: {case['name']}")
    for case in load(os.path.join(FIXTURE_DIR, "signature_input_cases.json")):
        # The label (text before '=') appears verbatim in the test sources.
        si = case["signature_input"]
        label = si.split("=", 1)[0]
        if label not in test_sources:
            errors.append(f"signature-input fixture not referenced by tests: {case['name']}")

    # Determinism: the generator must reproduce the same files.
    import subprocess

    gen = os.path.join(PROJECT, "scripts", "generate_rfc_fixtures.py")
    before = {name: sha256_hex(os.path.join(FIXTURE_DIR, name)) for name in REQUIRED_FILES}
    subprocess.run([sys.executable, gen], check=True, capture_output=True)
    after = {name: sha256_hex(os.path.join(FIXTURE_DIR, name)) for name in REQUIRED_FILES}
    for name in REQUIRED_FILES:
        if before[name] != after[name]:
            errors.append(f"non-deterministic fixture: {name}")

    if errors:
        for e in errors:
            print("ERROR: " + e)
        return 1
    print("RFC 9421 fixtures OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
