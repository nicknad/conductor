#!/usr/bin/env python3
"""Cheap structural checks for the Rust test suite.

These are intentionally not semantic tests: they catch test-shaped code that
cannot fail, copy-pasted tests, disabled tests, and integration targets that
never touch the crate. Mutation testing remains the authority on whether a
given test would catch a regression.

Usage:
    python3 scripts/check_test_quality.py [--root DIR]

Exit status is non-zero when a violation is found. No third-party packages
are required, so this can run directly in CI or a pre-commit hook.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TEST_ATTR = re.compile(r"#\s*\[\s*(?:tokio\s*::\s*)?test\b")
IGNORE_ATTR = re.compile(r"#\s*\[\s*ignore\b")
ASSERTION = re.compile(
    r"\b(?:assert|assert_eq|assert_ne|assert_matches|"
    r"debug_assert|debug_assert_eq|debug_assert_ne)\s*!"
    r"|\b(?:matches|panic|unreachable|todo|unimplemented)\s*!"
    r"|\.(?:expect|unwrap|unwrap_err)\s*\("
)
LOCAL_CALL = re.compile(r"(?<![.:\w])([A-Za-z_]\w*)\s*\(")
PLACEHOLDER = re.compile(
    r"\b(?:scaffold|placeholder|todo|fixme)\b|not\s+(?:yet\s+)?implemented",
    re.IGNORECASE,
)
TAUTOLOGY = re.compile(
    r"assert\s*!\s*\(\s*true\s*\)"
    r"|assert_eq\s*!\s*\(\s*([A-Za-z_]\w*)\s*,\s*\1\s*\)"
    r"|assert_ne\s*!\s*\(\s*([A-Za-z_]\w*)\s*,\s*\2\s*\)"
)


def mask_rust(src: str, *, blank_strings: bool) -> str:
    """Blank comments (and optionally strings) while preserving offsets.

    The result has the same length as ``src`` so parse positions stay valid.
    Rust raw strings, byte strings, C strings, char literals, and nested block
    comments are handled well enough for this repository.
    """
    out = list(src)
    n = len(src)

    def blank(start: int, end: int) -> None:
        for index in range(start, min(end, n)):
            if out[index] != "\n":
                out[index] = " "

    i = 0
    while i < n:
        if src.startswith("//", i):
            end = src.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
            continue

        if src.startswith("/*", i):
            depth = 1
            end = i + 2
            while end < n and depth:
                if src.startswith("/*", end):
                    depth += 1
                    end += 2
                elif src.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            blank(i, end)
            i = end
            continue

        raw = re.match(r'(?:b|c)?r(#*)"', src[i:])
        if raw:
            hashes = raw.group(1)
            end = i + raw.end()
            marker = '"' + hashes
            close = src.find(marker, end)
            end = n if close < 0 else close + len(marker)
            if blank_strings:
                blank(i, end)
            i = end
            continue

        prefixed = src[i] in "bc" and i + 1 < n and src[i + 1] == '"'
        if src[i] == '"' or prefixed:
            end = i + (2 if prefixed else 1)
            while end < n:
                if src[end] == "\\":
                    end += 2
                elif src[end] == '"':
                    end += 1
                    break
                else:
                    end += 1
            if blank_strings:
                blank(i, end)
            i = end
            continue

        char_literal = re.match(r"'(?:\\.|[^\\'])'", src[i:])
        if char_literal:
            end = i + char_literal.end()
            if blank_strings:
                blank(i, end)
            i = end
            continue

        i += 1

    return "".join(out)


def matching_brace(src: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(src)):
        if src[index] == "{":
            depth += 1
        elif src[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(src) - 1


def preceding_docs(src: str, position: int) -> str:
    """Collect contiguous /// docs, skipping attributes between docs and fn."""
    lines = src[:position].splitlines()
    docs: list[str] = []
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped:
            if docs:
                break
            continue
        if stripped.startswith("#["):
            continue
        if stripped.startswith("///"):
            docs.append(stripped[3:].strip())
            continue
        break
    return " ".join(reversed(docs))


def file_docs(src: str) -> str:
    docs = []
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith("//!"):
            docs.append(stripped[3:].strip())
        elif stripped and not stripped.startswith("#!"):
            break
    return " ".join(docs)


def functions(src: str) -> dict[str, dict[str, object]]:
    clean = mask_rust(src, blank_strings=True)
    found: dict[str, dict[str, object]] = {}
    for match in re.finditer(r"\bfn\s+([A-Za-z_]\w*)\s*(?:<[^>{]*>)?\s*\(", clean):
        opening = clean.find("{", match.end())
        if opening < 0:
            continue
        closing = matching_brace(clean, opening)
        prefix_start = max(
            clean.rfind(";", 0, match.start()),
            clean.rfind("}", 0, match.start()),
            0,
        )
        prefix = clean[prefix_start : match.start()]
        found[match.group(1)] = {
            "name": match.group(1),
            "line": src.count("\n", 0, match.start()) + 1,
            "body": src[opening : closing + 1],
            "clean_body": clean[opening : closing + 1],
            "is_test": bool(TEST_ATTR.search(prefix)),
            "docs": preceding_docs(src, match.start()),
        }
    return found


def has_assertion(test: dict[str, object], local: dict[str, dict[str, object]]) -> bool:
    """True when the test or a local helper it calls contains an assertion."""
    pending = [test]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        body = str(current["clean_body"])
        if ASSERTION.search(body):
            return True
        for name in LOCAL_CALL.findall(body):
            if name in seen:
                continue
            seen.add(name)
            helper = local.get(name)
            if helper is not None:
                pending.append(helper)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (default: parent of this script)",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    paths = sorted(
        set(root.glob("src/**/*.rs")) | set(root.glob("tests/**/*.rs"))
    )
    violations: list[tuple[str, str, str]] = []
    tests: list[tuple[Path, dict[str, object]]] = []

    for path in paths:
        source = path.read_text(encoding="utf-8")
        relative = path.relative_to(root)
        local = functions(source)
        file_tests = [fn for fn in local.values() if fn["is_test"]]
        file_docs_text = file_docs(source)

        if str(relative).startswith("tests/"):
            if not file_tests:
                violations.append(
                    ("empty-test-file", str(relative), "integration target has no #[test]")
                )
            if "conductor::" not in source:
                violations.append(
                    (
                        "integration-uses-conductor",
                        str(relative),
                        "integration target never references the crate",
                    )
                )

        # Only test files get the file-doc check. Production modules may
        # legitimately document unimplemented features in their module docs.
        if str(relative).startswith("tests/") and PLACEHOLDER.search(file_docs_text):
            violations.append(
                (
                    "placeholder-test",
                    str(relative),
                    "file docs describe a scaffold/placeholder",
                )
            )

        if IGNORE_ATTR.search(mask_rust(source, blank_strings=True)):
            violations.append(
                ("ignored-test", str(relative), "test is disabled with #[ignore]")
            )

        for test in file_tests:
            tests.append((path, test))
            name = str(test["name"])
            location = f"{relative}::{name}"
            text = f"{name} {test['docs']}"
            if PLACEHOLDER.search(text):
                violations.append(
                    ("placeholder-test", location, "name/docs describe a scaffold/placeholder")
                )
            if re.search(r"\b(?:todo|unimplemented)\s*!", str(test["clean_body"])):
                violations.append(
                    ("placeholder-test", location, "test body is a todo!/unimplemented! stub")
                )
            if not has_assertion(test, local):
                violations.append(
                    (
                        "test-body-has-assertion",
                        location,
                        "test and its local helpers assert nothing",
                    )
                )
            if TAUTOLOGY.search(str(test["clean_body"])):
                violations.append(
                    (
                        "tautological-assertion",
                        location,
                        "assertion is unconditionally true or compares a value with itself",
                    )
                )

    # Exact copy/paste bodies are almost always stale duplicates. Compare with
    # string and char literals intact so tests differing only in fixtures are
    # not reported.
    seen: dict[str, tuple[Path, dict[str, object]]] = {}
    for path, test in tests:
        body = mask_rust(str(test["body"]), blank_strings=False)
        normalized = re.sub(r"\s+", " ", body).strip()
        if len(normalized) < 12:
            continue
        if normalized in seen:
            first_path, first_test = seen[normalized]
            violations.append(
                (
                    "duplicate-test-body",
                    f"{path.relative_to(root)}::{test['name']}",
                    f"identical body to {first_path.relative_to(root)}::{first_test['name']}",
                )
            )
        else:
            seen[normalized] = (path, test)

    for check, location, message in violations:
        print(f"{location}: {check}: {message}")

    if violations:
        print(
            f"\n{len(violations)} test-quality violation(s). "
            "These checks are structural, not exhaustive; use mutation testing "
            "for behavioral coverage.",
            file=sys.stderr,
        )
        return 1

    print(f"test-quality: {len(tests)} tests across {len(paths)} files look structurally sane")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
