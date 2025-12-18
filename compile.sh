#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
IN_DIR="$ROOT/output/json"
OUT_DIR="$ROOT/output/srs"

mkdir -p "$OUT_DIR"

shopt -s nullglob
for f in "$IN_DIR"/*.json; do
  name="$(basename "$f" .json)"
  sing-box rule-set compile --output "$OUT_DIR/${name}.srs" "$f"
done
echo "[OK] compiled to $OUT_DIR"