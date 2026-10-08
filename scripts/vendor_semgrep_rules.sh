#!/usr/bin/env bash
# Vendor a curated, pinned subset of semgrep-rules for internal use.
#
# Usage: vendor_semgrep_rules.sh <semgrep-rules-checkout> <revision-sha>
#
# Copies the subtrees listed in SPECS, EXCLUDING audit/ review rules unless a
# spec names an audit subtree itself, and without the files in SKIP, keeping
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
# Five vendored files carry local edits (shorter messages, one test) and the
# manifest's hashes are those of the edited files. Regenerating overwrites
# them: restore them from git afterwards (git status shows them as modified)
#   rust/lang/security/temp-dir.yml
#   yaml/github-actions/security/{gha-curl-pipe-shell,gha-workflow-env-secret,github-actions-mutable-action-tag}.yaml
#   yaml/kubernetes/security/secrets-in-config-file.test.yaml
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
WAVE12="python:python/lang/security javascript:javascript/lang/security go:go/lang/security kotlin:kotlin/lang/security kotlin:kotlin/gradle/security java:java/lang c:c/lang/security rust:rust/lang/security kubernetes:yaml/kubernetes/security github-actions:yaml/github-actions/security json:json/aws/security"
# Wave 3 (2026-10-08): the injection, request-forgery, deserialisation, XML and
# crypto rules that waves 1 and 2 left out with audit/, the framework rules for
# Spring, Express, Flask, Django and Laravel, and PHP. Measured before and
# after on OWASP Benchmark and on testdata/detection: see docs/detection.md.
# An audit subtree is named explicitly; audit/ is still excluded elsewhere.
WAVE3="java:java/lang/security/audit java:java/spring/security java:java/spring/security/audit"
WAVE3="$WAVE3 javascript:javascript/lang/security/audit javascript:javascript/express/security javascript:javascript/express/security/audit"
WAVE3="$WAVE3 javascript:javascript/jsonwebtoken/security javascript:javascript/jsonwebtoken/security/audit javascript:javascript/node-crypto/security"
WAVE3="$WAVE3 php:php/lang/security php:php/lang/security/audit php:php/laravel/security"
WAVE3="$WAVE3 python:python/flask/security python:python/flask/security/audit python:python/django/security python:python/django/security/audit"
WAVE3="$WAVE3 python:python/requests/security python:python/sqlalchemy/security python:python/sqlalchemy/security/audit"
WAVE3="$WAVE3 go:go/lang/security/audit go:go/jwt-go/security go:go/jwt-go/security/audit"
SPECS="${SPECS:-$WAVE12 $WAVE3}"

# Upstream rule files left out although their subtree is vendored (paths in the
# upstream checkout). Each was measured on real repositories:
#   detect-eval-with-expression    29% of all matching time, no finding in any repository scanned
#   detect-non-literal-regexp      54% of all matching time, fires on library code
#   the other javascript audit     generic patterns that fire almost only inside committed
#   rules below                    third-party libraries (jQuery, CKEditor, ...)
#   express ... raw-html-format    90% of all matching time on repositories with JavaScript
#                                  libraries; direct-response-write covers the same weakness
#   express-check-csurf-...        reports every Express file once
#   no-direct-write-to-response... reports every w.Write in a Go handler
#   django ... query-set-extra     reports a query built from a constant, against its own test
SKIP_DEFAULT="javascript/lang/security/detect-eval-with-expression.yaml"
for name in detect-non-literal-regexp detect-non-literal-require detect-non-literal-fs-filename detect-redos \
            incomplete-sanitization unknown-value-with-script-tag unsafe-dynamic-method unsafe-formatstring \
            prototype-pollution/prototype-pollution-assignment prototype-pollution/prototype-pollution-loop; do
  SKIP_DEFAULT="$SKIP_DEFAULT javascript/lang/security/audit/$name.yaml"
done
SKIP_DEFAULT="$SKIP_DEFAULT javascript/express/security/injection/raw-html-format.yaml"
SKIP_DEFAULT="$SKIP_DEFAULT javascript/express/security/audit/express-check-csurf-middleware-usage.yaml"
SKIP_DEFAULT="$SKIP_DEFAULT go/lang/security/audit/xss/no-direct-write-to-responsewriter.yaml"
SKIP_DEFAULT="$SKIP_DEFAULT python/django/security/audit/query-set-extra.yaml"
SKIP="${SKIP:-$SKIP_DEFAULT}"

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
  # audit/ review rules come in only where a spec names an audit subtree itself.
  case "$sub" in */audit|*/audit/*) audit=() ;; *) audit=(-not -path "*/audit/*") ;; esac
  while IFS= read -r f; do
    case "$f" in *.test.*|*.fixed.*) continue;; esac
    rel="${f#$SRC/}"
    case " $SKIP " in *" $rel "*) echo "skip $rel: listed in SKIP"; continue;; esac
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
  done < <(find "$base" \( -name "*.yaml" -o -name "*.yml" \) "${audit[@]}" | sort)
done

# Four upstream fixtures mark cases that only Semgrep's cross-function engine is
# expected to get right (deepruleid, proruleid, "ruleid: deepok"). OpenGrep's
# intra-file taint analysis gets them right as well, so the annotations are
# rewritten to what OpenGrep must report: an engine that loses this fails
# `sdt rules verify`.
for fixture in java/lang/security/audit/tainted-cmd-from-http-request.java java/lang/security/audit/xss/no-direct-response-writer.java \
               java/spring/security/injection/tainted-sql-string.java java/spring/security/injection/tainted-system-command.java; do
  if [ -f "$DEST/$fixture" ]; then
    sed -i -e 's#// ruleid: deepok:#// ok:#' -e 's#// deepruleid:#// ruleid:#' -e 's#// proruleid:#// ruleid:#' "$DEST/$fixture"
  fi
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
