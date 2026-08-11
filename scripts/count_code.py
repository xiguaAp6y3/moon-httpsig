#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Count handwritten MoonBit lines in the project.

Excluded: _build, generated files, test vectors, Python scripts, Markdown,
JSON test data, LICENSE, blank lines, pure-comment lines, and the compiler's
auto-generated pkg.generated.mbti files.

Output keys:
  core_lines    protocol implementation .mbt files
  test_lines    test .mbt files (including test support/generators)
  cli_lines     cmd/httpsig-tool/*.mbt
  example_lines examples/*/main.mbt
  adapter_lines adapters/http11/*.mbt (excluding tests)
  total_handwritten_moonbit_lines  sum of the above
"""

from __future__ import annotations

import glob
import os

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Core protocol files at the module root (excludes _test, support, generators).
CORE_FILES = [
    "accept_signature.mbt",
    "algorithm.mbt",
    "ascii.mbt",
    "base64_value.mbt",
    "clock.mbt",
    "component.mbt",
    "component_params.mbt",
    "constant_time.mbt",
    "derived_components.mbt",
    "digest_binding.mbt",
    "error.mbt",
    "field_components.mbt",
    "hmac_sha256.mbt",
    "key_resolver.mbt",
    "limits.mbt",
    "message.mbt",
    "moon_httpsig.mbt",
    "nonce_store.mbt",
    "ordered_headers.mbt",
    "sf_cursor.mbt",
    "sf_model.mbt",
    "sf_parser.mbt",
    "sf_serializer.mbt",
    "signature_base.mbt",
    "signature_field.mbt",
    "signature_input.mbt",
    "signature_params.mbt",
    "signer.mbt",
    "verification_policy.mbt",
    "verifier.mbt",
]

# Test infrastructure that is not part of the protocol (counts as test code).
TEST_SUPPORT_FILES = [
    "test_support.mbt",
    "test_generator.mbt",
]


def count_mbt(path: str) -> int:
    """Count non-blank, non-comment lines in a MoonBit file."""
    n = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("//"):
                continue
            n += 1
    return n


def main() -> None:
    root = os.path.join(PROJECT, "*.mbt")
    core = 0
    for name in CORE_FILES:
        path = os.path.join(PROJECT, name)
        if os.path.exists(path):
            core += count_mbt(path)

    test = 0
    for name in TEST_SUPPORT_FILES:
        path = os.path.join(PROJECT, name)
        if os.path.exists(path):
            test += count_mbt(path)
    for path in sorted(glob.glob(os.path.join(PROJECT, "*_test.mbt"))):
        test += count_mbt(path)

    cli = 0
    for path in sorted(glob.glob(os.path.join(PROJECT, "cmd", "httpsig-tool", "*.mbt"))):
        cli += count_mbt(path)

    example = 0
    for path in sorted(glob.glob(os.path.join(PROJECT, "examples", "*", "main.mbt"))):
        example += count_mbt(path)

    adapter = 0
    for path in sorted(glob.glob(os.path.join(PROJECT, "adapters", "http11", "*.mbt"))):
        if path.endswith("_test.mbt"):
            test += count_mbt(path)
        else:
            adapter += count_mbt(path)

    total = core + test + cli + example + adapter
    print("core_lines=%d" % core)
    print("test_lines=%d" % test)
    print("cli_lines=%d" % cli)
    print("example_lines=%d" % example)
    print("adapter_lines=%d" % adapter)
    print("total_handwritten_moonbit_lines=%d" % total)


if __name__ == "__main__":
    main()
