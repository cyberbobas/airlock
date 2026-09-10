# Training the Airlock judge

This is how the built-in judge gets smarter at *our* task than any generic model:
we fine-tune a small open model on real gray-zone decisions, then ship it as a
single llamafile. The pipeline is a loop — the more Airlock is used, the more
training signal we have.

## Model

**Qwen2.5-3B-Instruct**, Apache-2.0. Chosen because:
- Apache-2.0 lets us fine-tune, merge, requantize and **ship/commercialize** our
  derivative with no strings (unlike the Llama community license).
- Strong instruction-following for its size, and small enough to judge on CPU on
  the hot path. `7B` is available as a heavier profile for batch/summary use.
- Alternative with an equally clean license: `Phi-3.5-mini` (MIT).

Swap the base by editing `BASE_MODEL` in `finetune_qlora.py`.

**Hardware:** QLoRA (4-bit) of the 3B fits a **16GB GPU** comfortably (~6-10GB
with seq-len 1024, batch 4, gradient checkpointing — the defaults in
`finetune_qlora.py`). The 7B also fits 16GB with `per_device_train_batch_size=1`
and checkpointing on, just slower. Merge + GGUF conversion run on CPU and need no
GPU.

## The loop

```
   real usage
      │  every gray-zone call a human answered allow/block is a labeled example
      ▼
1. HARVEST      airlock ai-dataset --all --out data/judge.jsonl
      │         (local, redacted, opt-in; chat-format SFT JSONL)
      ▼
2. FINE-TUNE    python training/finetune_qlora.py data/judge.jsonl out/lora
      │         QLoRA on Qwen2.5-3B-Instruct (one 24GB GPU is plenty)
      ▼
3. MERGE+GGUF   bash training/build_llamafile.sh out/lora dist/airlock-judge
      │         merge LoRA → convert to GGUF → quantize Q4_K_M → wrap as llamafile
      ▼
4. SHIP         drop airlock-judge.llamafile into the installer, or into
                $AIRLOCK_HOME/models/  →  BuiltinBackend picks it up automatically
```

## 1. Harvest the dataset

```
airlock ai-dataset --all --out data/judge.jsonl
```
Only human-answered gray-zone decisions become examples (see
`airlock/ai/dataset.py`). Every field is redacted first (`airlock/ai/prompts.py`),
and the audit log never stored raw arguments to begin with. Combine JSONL files
harvested from multiple consenting machines to build the corpus. Hold out ~10%
for eval. Also seed the corpus with hand-written examples for actions you have
strong priors on (destructive commands, secret reads, untrusted egress).

Each line is chat-format, identical to what the judge sees at inference:
```json
{"messages":[{"role":"system","content":"...judge system prompt..."},
             {"role":"user","content":"tool: Bash\n..."},
             {"role":"assistant","content":"{\"decision\":\"block\",\"reason\":\"...\"}"}]}
```

## 2–3. Fine-tune and build

See `finetune_qlora.py` (QLoRA SFT) and `build_llamafile.sh` (merge → GGUF →
llamafile). Both are standard recipes; run them on a GPU box, not in CI.

## 4. Ship

`BuiltinBackend` (`airlock/ai/builtin.py`) loads the first `*.llamafile` in
`$AIRLOCK_HOME/models/`, or the path in `AIRLOCK_AI_MODEL`. No user setup — the
model is part of the product. Version the file name (e.g.
`airlock-judge-v1.llamafile`) and record the training corpus + eval numbers per
version.

## Evaluation before shipping (do not skip)

The judge only ever *tightens* and *fails closed*, so the risk of a bad model is
annoyance (over-asking), not a hole. Still, gate each version on the held-out
set: agreement with the human label, and especially **false-allow rate on the
must-block slice must be ~0** (report it in the changelog). A model that would
loosen a call it should have blocked does not ship.
