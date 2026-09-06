#!/usr/bin/env bash
# Vendor a curated, pinned subset of semgrep-rules for internal use.
#
# Usage: vendor_semgrep_rules.sh <semgrep-rules-checkout> <revision-sha>
#
# Copies <lang>/lang/security rules EXCLUDING audit/ review rules, keeping
# upstream layout verbatim (rule yaml + annotated sibling test files
# colocated: `opengrep test` only pairs colocated tests). Autofix fixtures
# (*.fixed.*) are dropped: sdt never applies fixes, and their format drifts
# across engine versions.
#   rules/opengrep-rules/vendor/semgrep/<lang>/...   (upstream layout,
#   hashed + pinned, alongside the existing vendor/aikido source)
# Scan targets exclude rules/opengrep-rules/vendor/** (pinned third-party
# content is verified by hash, not scanned as first-party code).
# License: Semgrep Rules License v1.0 (internal business use permitted;
# not for competing products/SaaS). License text is vendored alongside.
# Bundle hashes must be reproducible: force byte-wise sorting so the digest
# matches internal/rules.BundleHash (Go sort.Strings) on any machine.
export LC_ALL=C
set -euo pipefail

SRC="${1:?semgrep-rules checkout path required}"
REV="${2:?revision sha required}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/rules/opengrep-rules/vendor/semgrep"
# "tag:upstream-subtree ..." specs. Tags group subtrees into manifest sources.
# Wave 1: core language security. Wave 2: + kotlin/java core, k8s + GitHub
# Actions hygiene, AWS JSON. Terraform provider rules stay out: Trivy
# misconfiguration owns IaC; revisit on demonstrated demand.
SPECS="${SPECS:-python:python/lang/security javascript:javascript/lang/security go:go/lang/security kotlin:kotlin/lang/security kotlin:kotlin/gradle/security java:java/lang c:c/lang/security rust:rust/lang/security kubernetes:yaml/kubernetes/security github-actions:yaml/github-actions/security json:json/aws/security}"

echo "vendoring from $SRC @ $REV"
# Generated tree: wipe and rebuild deterministically from the pinned source.
rm -rf "$DEST"
mkdir -p "$DEST"
cp "$SRC/LICENSE" "$DEST/LICENSE.semgrep-rules"

# Rule files vs test files are selected explicitly: test fixtures
# (*.test.*) and autofix fixtures (*.fixed.*) are never treated as rules.
code_exts="py js ts go java kt rb php c cpp h hpp cs swift scala rs txt tf yaml yml json toml xml"
for spec in $SPECS; do
  tag="${spec%%:*}"
  sub="${spec#*:}"
  base="$SRC/$sub"
  [ -d "$base" ] || { echo "skip $sub: not found"; continue; }
  while IFS= read -r f; do
    case "$f" in *.test.*|*.fixed.*) continue;; esac
    rel="${f#$SRC/}"
    mkdir -p "$DEST/$(dirname "$rel")"
    cp "$f" "$DEST/$rel"
    # Annotated sibling detection-test files stay colocated (opengrep test
    # pairing requirement). Two upstream conventions: <stem>.<ext> and
    # <stem>.test.<ext> (k8s/CI packs). Autofix fixtures (*.fixed.*) are
    # dropped (see header).
    stem="${f%.yaml}"
    stem="${stem%.yml}"
    for ext in $code_exts; do
      for t in "$stem.$ext" "$stem.test.$ext"; do
        [ -f "$t" ] || continue
        case "$t" in *.fixed.*) continue;; esac
        trel="${t#$SRC/}"
        mkdir -p "$DEST/$(dirname "$trel")"
        cp "$t" "$DEST/$trel"
      done
    done
  done < <(find "$base" \( -name "*.yaml" -o -name "*.yml" \) -not -path "*/audit/*" | sort)
done

echo "=== vendored rules:"; find "$DEST" \( -name "*.yaml" -o -name "*.yml" \) -not -name LICENSE\* | wc -l
echo "=== vendored test files:"; find "$DEST" -type f -not -name "*.yaml" -not -name "LICENSE*" | wc -l
echo "revision: $REV"
echo "=== bundle hashes (sha256 over sorted per-file hashes) for manifest.yaml:"
for spec in $SPECS; do
  tag="${spec%%:*}"
  sub="${spec#*:}"
  top="${sub%%/*}"
  [ -d "$DEST/$top" ] || continue
  bundle=$(cd "$DEST/$top" && find . -type f | sort | xargs sha256sum | sha256sum | cut -d' ' -f1)
  count=$(cd "$DEST/$top" && find . \( -name "*.yaml" -o -name "*.yml" \) | wc -l)
  echo "  $top: files=$count bundle_sha256=$bundle"
done
