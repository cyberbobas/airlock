#!/usr/bin/env python3
"""QLoRA SFT of the Airlock judge on harvested gray-zone decisions.

Recipe, not a CI step: run on a GPU box (one 24GB card is enough for a 3B in
4-bit). Reads chat-format JSONL from `airlock ai-dataset` and writes a LoRA
adapter; `build_llamafile.sh` then merges + converts + wraps it.

    pip install "transformers>=4.44" "trl>=0.9" "peft>=0.12" \
                "bitsandbytes>=0.43" "datasets>=2.20" accelerate
    python training/finetune_qlora.py data/judge.jsonl out/lora

Deliberately small and boring: the leverage is the data (real decisions), not
exotic hyperparameters.
"""
import sys

BASE_MODEL = "Qwen/Qwen2.5-3B-Instruct"   # Apache-2.0. 7B for a heavier judge.


def main(argv):
    if len(argv) < 3:
        print("usage: finetune_qlora.py <dataset.jsonl> <out_dir>")
        return 2
    data_path, out_dir = argv[1], argv[2]

    import torch
    from datasets import load_dataset
    from peft import LoraConfig
    from transformers import (AutoModelForCausalLM, AutoTokenizer,
                              BitsAndBytesConfig)
    from trl import SFTConfig, SFTTrainer

    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    bnb = BitsAndBytesConfig(
        load_in_4bit=True, bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL, quantization_config=bnb, torch_dtype=torch.bfloat16,
        device_map="auto",
    )

    ds = load_dataset("json", data_files=data_path, split="train")

    def fmt(ex):
        # chat template -> single training string; loss on the assistant turn.
        return {"text": tok.apply_chat_template(ex["messages"], tokenize=False)}

    ds = ds.map(fmt, remove_columns=ds.column_names)

    peft = LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05, bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
    )
    cfg = SFTConfig(
        # Tuned to fit a 16GB GPU for the 3B in 4-bit: small batch, grad
        # accumulation for an effective batch of 16, gradient checkpointing.
        # For 7B on 16GB drop batch to 1 and keep checkpointing on.
        output_dir=out_dir, num_train_epochs=3, per_device_train_batch_size=4,
        gradient_accumulation_steps=4, gradient_checkpointing=True,
        learning_rate=2e-4, lr_scheduler_type="cosine",
        warmup_ratio=0.03, logging_steps=10, save_strategy="epoch",
        bf16=True, max_seq_length=1024, packing=True, dataset_text_field="text",
    )
    SFTTrainer(model=model, tokenizer=tok, train_dataset=ds,
               peft_config=peft, args=cfg).train()
    model.save_pretrained(out_dir)
    tok.save_pretrained(out_dir)
    print(f"LoRA adapter written to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
