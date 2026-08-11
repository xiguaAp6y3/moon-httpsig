#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate deterministic RFC 9421 test fixtures under testdata/rfc9421.

The fixture data is embedded here (derived from RFC 9421 Appendix B examples)
so the generator is fully deterministic: running it twice produces byte
identical files, no network access, and no wall-clock timestamps.
"""

from __future__ import annotations

import hashlib
import json
import os

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(PROJECT, "testdata", "rfc9421")

# The RFC 9421 test-request / test-response messages and the shared secret
# (RFC 9421 Appendix B).
SECRET = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="

REQUEST_LINES = [
    "POST /foo?param=Value&Pet=dog HTTP/1.1",
    "Host: example.com",
    "Date: Tue, 20 Apr 2021 02:07:55 GMT",
    "Content-Type: application/json",
    "Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
    "Content-Length: 18",
    "",
    '{"hello": "world"}',
]

RESPONSE_LINES = [
    "HTTP/1.1 200 OK",
    "Date: Tue, 20 Apr 2021 02:07:56 GMT",
    "Content-Type: application/json",
    "Content-Digest: sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
    "Content-Length: 23",
    "",
    '{"message": "good dog"}',
]

# Signature bases from RFC 9421 Appendix B (exact bytes).
SIGNATURE_BASES = {
    "b2.1": {
        "section": "B.2.1",
        "message": "test-request",
        "algorithm": "rsa-pss-sha512",
        "signature_input": 'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
        "signature_base": '@signature-params: ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
    },
    "b2.2": {
        "section": "B.2.2",
        "message": "test-request",
        "algorithm": "rsa-pss-sha512",
        "signature_input": 'sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
        "signature_base": '"@authority": example.com\n"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n"@query-param";name="Pet": dog\n"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
    },
    "b2.3": {
        "section": "B.2.3",
        "message": "test-request",
        "algorithm": "rsa-pss-sha512",
        "signature_input": 'sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
        "signature_base": '"date": Tue, 20 Apr 2021 02:07:55 GMT\n"@method": POST\n"@path": /foo\n"@query": ?param=Value&Pet=dog\n"@authority": example.com\n"content-type": application/json\n"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:\n"content-length": 18\n"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
    },
    "b2.4": {
        "section": "B.2.4",
        "message": "test-response",
        "algorithm": "ecdsa-p256-sha256",
        "signature_input": 'sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
        "signature_base": '"@status": 200\n"content-type": application/json\n"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:\n"content-length": 23\n"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
    },
    "b2.5": {
        "section": "B.2.5",
        "message": "test-request",
        "algorithm": "hmac-sha256",
        "keyid": "test-shared-secret",
        "signature_input": 'sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
        "signature_base": '"date": Tue, 20 Apr 2021 02:07:55 GMT\n"@authority": example.com\n"content-type": application/json\n"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"',
        "signature": "sig-b25=:pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=:",
        "hmac_expected": "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=",
    },
    "b2.6": {
        "section": "B.2.6",
        "message": "test-request",
        "algorithm": "ed25519",
        "signature_input": 'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
        "signature_base": '"date": Tue, 20 Apr 2021 02:07:55 GMT\n"@method": POST\n"@path": /foo\n"@authority": example.com\n"content-type": application/json\n"content-length": 18\n"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"',
    },
}

# HMAC-SHA256 vectors (RFC 2104 style).
HMAC_CASES = [
    {
        "name": "rfc2104_case1",
        "key_hex": "0b" * 20,
        "data_hex": "4869205468657265",  # "Hi There"
        "expected": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    },
    {
        "name": "empty_key_empty_message",
        "key_hex": "",
        "data_hex": "",
        "expected": "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
    },
    {
        "name": "rfc9421_b25",
        "key_b64": SECRET,
        "data_b64": None,
        "expected": "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=",
    },
]

# Negative parse cases (RFC 9651 grammar violations).
NEGATIVE_CASES = [
    {"input": "a b", "kind": "InvalidStructuredField"},
    {"input": "A=1", "kind": "InvalidStructuredField"},
    {"input": 'a="unterminated', "kind": "UnexpectedEnd"},
    {"input": "a=:badbase$:", "kind": "InvalidBase64"},
    {"input": "a=1;b=1;b=2", "kind": "InvalidStructuredField"},
    {"input": "a=99999999999999999999", "kind": "InvalidInteger"},
    {"input": "a=?2", "kind": "InvalidStructuredField"},
    {"input": "(unterminated", "kind": "UnexpectedEnd"},
    {"input": "a=1,", "kind": "InvalidStructuredField"},
    {"input": 'a=("@method");created="x"', "kind": "InvalidSignatureInput"},
]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(name: str, payload) -> None:
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)

    # SOURCE.json: provenance metadata for the fixtures.
    source = {
        "rfc_number": 9421,
        "rfc_title": "HTTP Message Signatures",
        "section": "Appendix B",
        "fixture_version": "1.0",
        "generated_at": "fixed:2026-01-01T00:00:00Z",
        "source_description": (
            "Embedded fixture data derived from RFC 9421 Appendix B "
            "examples (public test vectors and the public test shared secret)."
        ),
        "sha256": sha256_hex("\n".join(REQUEST_LINES).encode("utf-8")),
        "notes": [
            "No network content is fetched.",
            "Output is deterministic across runs.",
            "The HMAC example (B.2.5) is byte-verifiable by this library.",
        ],
    }
    write_json("SOURCE.json", source)

    # Request / response cases.
    write_json(
        "request_cases.json",
        {
            "name": "test-request",
            "message_lines": REQUEST_LINES,
            "method": "POST",
            "scheme": "https",
            "authority": "example.com",
            "path": "/foo",
            "query": "param=Value&Pet=dog",
            "sha256": sha256_hex("\n".join(REQUEST_LINES).encode("utf-8")),
        },
    )
    write_json(
        "response_cases.json",
        {
            "name": "test-response",
            "message_lines": RESPONSE_LINES,
            "status": 200,
            "sha256": sha256_hex("\n".join(RESPONSE_LINES).encode("utf-8")),
        },
    )

    # Signature-Input, Signature, and signature-base cases.
    si_cases = []
    sig_cases = []
    base_cases = []
    for key, case in SIGNATURE_BASES.items():
        si_cases.append(
            {
                "name": key,
                "section": case["section"],
                "message": case["message"],
                "algorithm": case["algorithm"],
                "signature_input": case["signature_input"],
            }
        )
        if "signature" in case:
            sig_cases.append(
                {
                    "name": key,
                    "section": case["section"],
                    "signature": case["signature"],
                }
            )
        base_cases.append(
            {
                "name": key,
                "section": case["section"],
                "label": "sig-" + key.replace(".", ""),
                "message": case["message"],
                "algorithm": case["algorithm"],
                "signature_input": case["signature_input"],
                "signature_base": case["signature_base"],
                "base_sha256": sha256_hex(case["signature_base"].encode("utf-8")),
            }
        )
    write_json("signature_input_cases.json", si_cases)
    write_json("signature_cases.json", sig_cases)
    write_json("signature_base_cases.json", base_cases)

    # HMAC cases.
    hmac_cases = []
    for case in HMAC_CASES:
        if case["name"] == "rfc9421_b25":
            base = SIGNATURE_BASES["b2.5"]["signature_base"]
            hmac_cases.append(
                {
                    "name": case["name"],
                    "key_b64": case["key_b64"],
                    "data_b64": __import__("base64").b64encode(
                        base.encode("utf-8")
                    ).decode(),
                    "data_text": base,
                    "expected_b64": case["expected"],
                }
            )
        else:
            hmac_cases.append(
                {
                    "name": case["name"],
                    "key_hex": case["key_hex"],
                    "data_hex": case["data_hex"],
                    "expected_hex": case["expected"],
                }
            )
    write_json("hmac_cases.json", hmac_cases)

    # Negative cases.
    write_json("negative_cases.json", NEGATIVE_CASES)

    print(f"Wrote fixtures to {OUT_DIR}")


if __name__ == "__main__":
    main()
