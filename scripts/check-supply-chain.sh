#!/usr/bin/env bash
# Supply chain policy enforcement.
# Fails CI if any dependency references are unpinned or unverified.
#
# Checks:
#   1. Python requirements.txt — must use == with --hash
#   2. package.json — must not use ^ or ~ ranges
#   3. Dockerfiles — FROM must include @sha256: digest
#   4. GitHub Actions — uses: must reference a commit SHA, not a tag
#
# Usage: scripts/check-supply-chain.sh

set -euo pipefail

ERRORS=0

red()   { printf '\033[0;31m%s\033[0m\n' "$1"; }
green() { printf '\033[0;32m%s\033[0m\n' "$1"; }

# ── 1. Python requirements.txt ─────────────────────────────────────────
echo "Checking Python requirements..."
while IFS= read -r -d '' f; do
  # Skip files that are only comments/blanks
  grep -q '^[^#[:space:]]' "$f" 2>/dev/null || continue

  # Check for unpinned versions (>=, ~=, >)
  unpinned=$(grep -n '^[A-Za-z]' "$f" | grep -E '>=|~=|>[^=]' | grep -v '==' || true)
  if [ -n "$unpinned" ]; then
    red "FAIL: $f has unpinned version ranges:"
    echo "$unpinned"
    ERRORS=$((ERRORS + 1))
  fi

  # Check for missing hashes (has == but no --hash)
  has_pins=$(grep -c '^[A-Za-z].*==' "$f" 2>/dev/null || true)
  has_hashes=$(grep -c '\-\-hash=' "$f" 2>/dev/null || true)
  has_pins=${has_pins:-0}
  has_hashes=${has_hashes:-0}
  if [ "$has_pins" -gt 0 ] && [ "$has_hashes" -eq 0 ]; then
    red "FAIL: $f has pinned versions but no --hash verification"
    ERRORS=$((ERRORS + 1))
  fi
done < <(find . -maxdepth 4 -name "requirements.txt" \
  -not -path "./.venv/*" \
  -not -path "*/cdk.out/*" \
  -not -path "*/node_modules/*" \
  -not -path "./.git/*" \
  -print0 2>/dev/null)

# ── 2. package.json ────────────────────────────────────────────────────
echo "Checking package.json..."
for f in $(find . -maxdepth 2 -name "package.json" -not -path "*/node_modules/*" -not -path "./.git/*" 2>/dev/null); do
  if grep -q '"[\^~]' "$f" 2>/dev/null; then
    red "FAIL: $f has unpinned dependency ranges (^ or ~)"
    ERRORS=$((ERRORS + 1))
  fi
done

# ── 3. Dockerfiles ─────────────────────────────────────────────────────
echo "Checking Dockerfiles..."
for f in $(find . -maxdepth 4 -name "Dockerfile" -not -path "./.git/*" -not -path "*/cdk.out/*" -not -path "*/codeql/*" -not -path "*/node_modules/*" 2>/dev/null); do
  bad_from=$(grep -n '^FROM ' "$f" | grep -v '@sha256:' || true)
  if [ -n "$bad_from" ]; then
    red "FAIL: $f has FROM without @sha256: digest:"
    echo "$bad_from"
    ERRORS=$((ERRORS + 1))
  fi
done

# ── 4. GitHub Actions ──────────────────────────────────────────────────
echo "Checking GitHub Actions..."
for f in $(find .github/workflows -name "*.yml" -o -name "*.yaml" 2>/dev/null); do
  bad_uses=$(grep -n 'uses:.*@v[0-9]' "$f" || true)
  if [ -n "$bad_uses" ]; then
    red "FAIL: $f has actions pinned to version tags, not commit SHAs:"
    echo "$bad_uses"
    ERRORS=$((ERRORS + 1))
  fi
done

# ── Result ─────────────────────────────────────────────────────────────
echo ""
if [ "$ERRORS" -gt 0 ]; then
  red "FAILED: $ERRORS supply chain policy violation(s) found"
  exit 1
else
  green "PASSED: all dependencies pinned and verified"
fi
