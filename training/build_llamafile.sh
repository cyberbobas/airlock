#!/usr/bin/env bash
# Merge the LoRA into the base, convert to GGUF, quantize, and wrap as a single
# self-contained llamafile. Recipe — run on a build box with llama.cpp checked
# out and the `llamafile` tool installed (https://github.com/Mozilla-Ocho/llamafile).
#
#   bash training/build_llamafile.sh out/lora dist/airlock-judge
#
# Produces dist/airlock-judge.llamafile — drop it into $AIRLOCK_HOME/models/ and
# BuiltinBackend runs it automatically. No install for the end user.
set -euo pipefail

LORA_DIR="${1:?usage: build_llamafile.sh <lora_dir> <out_prefix>}"
OUT_PREFIX="${2:?usage: build_llamafile.sh <lora_dir> <out_prefix>}"
BASE_MODEL="${BASE_MODEL:-Qwen/Qwen2.5-3B-Instruct}"
LLAMA_CPP="${LLAMA_CPP:-$HOME/llama.cpp}"      # path to a llama.cpp checkout
QUANT="${QUANT:-Q4_K_M}"                        # judge default; Q5_K_M for more quality

work="$(mktemp -d)"
merged="$work/merged"
gguf_f16="$work/model-f16.gguf"
gguf_q="${OUT_PREFIX}.gguf"

echo "[1/4] merge LoRA into $BASE_MODEL"
python - "$BASE_MODEL" "$LORA_DIR" "$merged" <<'PY'
import sys
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
base, lora, out = sys.argv[1], sys.argv[2], sys.argv[3]
m = AutoModelForCausalLM.from_pretrained(base, torch_dtype="auto")
m = PeftModel.from_pretrained(m, lora).merge_and_unload()
m.save_pretrained(out); AutoTokenizer.from_pretrained(base).save_pretrained(out)
print("merged ->", out)
PY

echo "[2/4] convert to GGUF (f16)"
python "$LLAMA_CPP/convert_hf_to_gguf.py" "$merged" --outfile "$gguf_f16" --outtype f16

echo "[3/4] quantize -> $QUANT"
"$LLAMA_CPP/llama-quantize" "$gguf_f16" "$gguf_q" "$QUANT"

echo "[4/4] wrap as llamafile"
# Requires the `llamafile` zipalign tooling; embeds the GGUF + a default arg file
# so the file boots straight into --server mode.
printf -- '-m\n%s\n--host\n127.0.0.1\n--nobrowser\n' "$(basename "$gguf_q")" > "$work/.args"
cp "$(command -v llamafile)" "${OUT_PREFIX}.llamafile"
zipalign -j0 "${OUT_PREFIX}.llamafile" "$gguf_q" "$work/.args"
chmod +x "${OUT_PREFIX}.llamafile"

echo "done: ${OUT_PREFIX}.llamafile"
echo "test:  ${OUT_PREFIX}.llamafile --server --port 8231 --nobrowser"
