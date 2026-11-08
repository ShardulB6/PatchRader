"""IBM Granite text classifier with LoRA: train, score, and build out-of-fold text scores.

The model reads a CVE description (with "exploited in the wild" wording removed) and outputs
P(exploited). LoRA freezes Granite's weights and trains small adapter matrices in the attention
and feed-forward layers, plus a new classification head.

    from ml import text_model as T
    texts = T.load_texts()                                  # train 2018-2024, val 2025, 2026 scoreboard
    model, log = T.fit(T.labeled(texts, "train", "2024-12-31"))
    scores = T.predict(model, texts[texts.split == "val"])
"""
from __future__ import annotations

import math
import re
import time

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedKFold

from . import config

IN_WILD = re.compile(r"exploited in the wild|actively exploited|may have been exploited|aware of (?:a )?report", re.IGNORECASE)


def device() -> str:
    return "cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu"


def clean(description: str) -> str:
    """Remove sentences (or a trailing clause) saying the bug was already exploited: today's descriptions
    may have gained that wording after the attack, which would leak the label."""
    text = re.sub(r",?\s*as (?:actively )?exploited in the wild[^.]*", "", description or "", flags=re.IGNORECASE)
    return " ".join(s for s in re.split(r"(?<=[.!?])\s+", text) if not IN_WILD.search(s)).strip()


def load_texts() -> pd.DataFrame:
    """The shared text table built by notebooks/trackb_2_finetune_granite.ipynb (texts.parquet):
    one row per CVE with split (train/val/score26), published, kev_date and text = 'assigner | description'."""
    t = pd.read_parquet(config.TEXT_DIR / "texts.parquet")
    assert not t["text"].str.contains(IN_WILD).any()
    return t


def labeled(texts: pd.DataFrame, splits, deadline: str) -> pd.DataFrame:
    """Rows of the given split(s), labeled 'on KEV by deadline' (every row is already not on KEV at its
    snapshot, so this is the benchmark's label)."""
    splits = [splits] if isinstance(splits, str) else splits
    d = texts[texts.split.isin(splits)].sort_values("cve_id", ignore_index=True).copy()
    d["y"] = (d["kev_date"].notna() & (d["kev_date"] <= pd.Timestamp(deadline))).astype(int)
    return d


def _free_memory() -> None:
    """Release a finished model's GPU memory before the next one is built (matters on a laptop GPU)."""
    import gc
    gc.collect()
    if device() == "mps":
        torch.mps.empty_cache()
    elif device() == "cuda":
        torch.cuda.empty_cache()


def _seed(seed: int) -> None:
    np.random.seed(seed); torch.manual_seed(seed)


def build_model(cfg: dict = config.LORA):
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForSequenceClassification
    base = AutoModelForSequenceClassification.from_pretrained(cfg["model"], num_labels=2)
    lora = LoraConfig(r=cfg["r"], lora_alpha=cfg["alpha"], lora_dropout=cfg["dropout"],
                      target_modules=cfg["target_modules"], modules_to_save=cfg["modules_to_save"], task_type="SEQ_CLS")
    return get_peft_model(base, lora)


_TOKENIZERS = {}
def _tok(cfg):
    from transformers import AutoTokenizer
    if cfg["model"] not in _TOKENIZERS:
        _TOKENIZERS[cfg["model"]] = AutoTokenizer.from_pretrained(cfg["model"])
    return _TOKENIZERS[cfg["model"]]


def _encode(texts, cfg, dev):
    enc = _tok(cfg)(list(texts), truncation=True, max_length=cfg["max_length"], padding=True, return_tensors="pt")
    return {k: v.to(dev) for k, v in enc.items()}


@torch.no_grad()
def predict(model, rows: pd.DataFrame, cfg: dict = config.LORA, batch_size: int = 8) -> np.ndarray:
    """P(exploited) for each row, in the rows' order. Texts are sorted by length so batches pad less.
    Batch 8 is the fastest on an M3 GPU (34 rows/s vs. 19 at batch 32) and gives the same scores (max diff 5e-7)."""
    dev = device(); model.to(dev).eval()
    texts = rows["text"].to_numpy()
    order = np.argsort([len(t) for t in texts], kind="stable")
    out = np.empty(len(texts), dtype=np.float32)
    for i in range(0, len(order), batch_size):
        idx = order[i:i + batch_size]
        logits = model(**_encode(texts[idx], cfg, dev)).logits.float()
        out[idx] = torch.softmax(logits, dim=-1)[:, 1].cpu().numpy()
    if dev == "mps":
        torch.mps.empty_cache()
    return out


def fit(rows: pd.DataFrame, cfg: dict = config.LORA, label: str = "lora", seed: int | None = None):
    """Downsample negatives, hold out 10% to watch the loss, then train the LoRA model.
    Returns (model, training log). Each batch of 32 is processed in micro-batches; with a summed,
    weight-normalized loss that is mathematically the same as one batch of 32."""
    seed = cfg["seed"] if seed is None else seed
    _seed(seed); dev = device(); rng = np.random.default_rng(seed)
    y = rows["y"].to_numpy()
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    ft = rows.iloc[np.concatenate([pos, rng.choice(neg, cfg["neg_per_pos"] * len(pos), replace=False)])]
    ft = ft.sample(frac=1, random_state=seed).reset_index(drop=True)
    n_hold = int(len(ft) * cfg["holdout"])
    hold, train = ft.iloc[:n_hold].reset_index(drop=True), ft.iloc[n_hold:].reset_index(drop=True)

    from transformers import get_linear_schedule_with_warmup
    model = build_model(cfg).to(dev)
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=cfg["lr"], weight_decay=cfg["weight_decay"])
    steps = cfg["epochs"] * math.ceil(len(train) / cfg["batch_size"])
    sched = get_linear_schedule_with_warmup(opt, int(cfg["warmup"] * steps), steps)
    weight = torch.tensor([1.0, cfg["pos_weight"]], device=dev)
    loss_sum = torch.nn.CrossEntropyLoss(weight=weight, reduction="sum")
    log = []
    for epoch in range(cfg["epochs"]):
        model.train(); t0 = time.time(); total = 0.0
        order = np.random.default_rng(seed + epoch).permutation(len(train))
        for step, i in enumerate(range(0, len(order), cfg["batch_size"])):
            b = train.iloc[order[i:i + cfg["batch_size"]]]
            yb = torch.tensor(b["y"].to_numpy().astype(np.int64), device=dev)
            norm = weight[yb].sum(); batch_loss = 0.0
            for j in range(0, len(b), cfg["micro_batch"]):
                enc = _encode(b["text"].to_numpy()[j:j + cfg["micro_batch"]], cfg, dev)
                loss = loss_sum(model(**enc).logits.float(), yb[j:j + cfg["micro_batch"]]) / norm
                loss.backward(); batch_loss += loss.item()
            total += batch_loss * len(b)          # batch_loss = the batch's weighted mean loss
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step(); sched.step(); opt.zero_grad()
            if dev == "mps" and step % 25 == 0:
                torch.mps.empty_cache()
        p = np.clip(predict(model, hold, cfg).astype(np.float64), 1e-7, 1 - 1e-7)
        hy = hold["y"].to_numpy(); w = np.where(hy == 1, cfg["pos_weight"], 1.0)
        log.append({"run": label, "epoch": epoch + 1, "train loss": round(total / len(train), 4),
                    "held-out loss": round(float(-(w * np.where(hy == 1, np.log(p), np.log(1 - p))).sum() / w.sum()), 4),
                    "held-out AUC": round(float(roc_auc_score(hy, p)), 3), "minutes": round((time.time() - t0) / 60, 1),
                    "training rows": len(train), "positives": int(train.y.sum())})
        print(log[-1])
    return model, pd.DataFrame(log)


def out_of_fold(rows: pd.DataFrame, score_mask: np.ndarray, cfg: dict = config.LORA, folds: int = 5, label: str = "oof"):
    """Score rows[score_mask] so that every scored row comes from a model that never saw its label
    (stratified k-fold). These are the scores a downstream model may safely train on."""
    rows = rows.reset_index(drop=True)
    scores = np.full(len(rows), np.nan); logs = []
    for f, (fit_idx, out_idx) in enumerate(StratifiedKFold(folds, shuffle=True, random_state=cfg["seed"]).split(rows, rows["y"])):
        target = out_idx[score_mask[out_idx]]
        model, log = fit(rows.iloc[fit_idx], cfg, label=f"{label} fold {f + 1}", seed=cfg["seed"] + f)
        _free_memory()                      # drop the optimizer's leftovers before scoring
        scores[target] = predict(model, rows.iloc[target], cfg)
        logs.append(log); del model
        _free_memory()
    out = rows.loc[score_mask, ["cve_id"]].assign(text_score=scores[score_mask])
    assert out["text_score"].notna().all()
    return out, pd.concat(logs, ignore_index=True)
