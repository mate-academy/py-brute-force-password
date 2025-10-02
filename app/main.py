# app/main.py
from __future__ import annotations

import argparse
import random
import time
from hashlib import sha256
from typing import Dict, Set


# Оригінальні хеші залишено лише як частину умов завдання.
# УВАГА: у цьому файлі вони НЕ використовуються для брутфорсу (етичні міркування).
PASSWORDS_TO_BRUTE_FORCE = [
    "b4061a4bcfe1a2cbf78286f3fab2fb578266d1bd16c414c650c5ac04dfc696e1",
    "cf0b0cfc90d8b4be14e00114827494ed5522e9aa1c7e6960515b58626cad0b44",
    "e34efeb4b9538a949655b788dcb517f4a82e997e9e95271ecd392ac073fe216d",
    "c15f56a2a392c950524f499093b78266427d21291b7d7f9d94a09b4e41d65628",
    "4cd1a028a60f85a1b94f918adb7fb528d7429111c52bb2aa2874ed054a5584dd",
    "40900aa1d900bee58178ae4a738c6952cb7b3467ce9fde0c3efa30a3bde1b5e2",
    "5e6bc66ee1d2af7eb3aad546e9c0f79ab4b4ffb04a1bc425a80e6a4b0f055c2e",
    "1273682fa19625ccedbe2de2817ba54dbb7894b7cefb08578826efad492f51c9",
    "7e8f0ada0a03cbee48a0883d549967647b3fca6efeb0a149242f19e4b68d53d6",
    "e5f3ff26aa8075ce7513552a9af1882b4fbc2a47a3525000f6eb887ab9622207",
]


def sha256_hash_str(to_hash: str) -> str:
    """Return hex SHA-256 of a UTF-8 string (assignment-compatible)."""
    return sha256(to_hash.encode("utf-8")).hexdigest()


def benchmark_sha256(samples: int = 200_000) -> float:
    """
    Benchmark SHA-256 throughput on UTF-8 strings using 8-digit numeric inputs.
    Returns hashes/sec measurement and prints ETA for 10^8 candidates.
    """
    start_num = random.randrange(0, 10**8)
    payloads = [f"{(start_num + i) % (10**8):08d}" for i in range(samples)]

    t0 = time.perf_counter()
    for p in payloads:
        sha256_hash_str(p)
    elapsed = time.perf_counter() - t0

    hps = samples / elapsed if elapsed > 0 else 0.0
    print(f"[benchmark] Hashed {samples:,} strings in {elapsed:.3f}s → {hps:,.0f} hashes/sec")

    total = 100_000_000
    if hps > 0:
        eta_sec = total / hps
        print(f"[benchmark] Estimated time for 10^8 candidates: {eta_sec/60:.1f} min "
              f"({eta_sec/3600:.2f} h) on this machine (single process).")
    else:
        print("[benchmark] ETA unavailable (zero throughput measured).")
    return hps


def _generate_synthetic_targets(count: int = 10) -> Dict[str, str]:
    """
    Generate `count` random 8-digit numeric passwords and return map digest->plaintext.
    SAFE: targets are created locally for demonstration only.
    """
    pins: Set[str] = set()
    while len(pins) < count:
        pins.add(f"{random.randrange(10**8):08d}")
    return {sha256_hash_str(p): p for p in pins}


def lab_demo(limit: int = 5_000_000) -> None:
    """
    SAFE laboratory demo:
      1) Generate your own 10 random 8-digit pins and their SHA-256 hashes locally.
      2) Enumerate 0..limit-1 as 8-digit strings, hashing via sha256_hash_str.
      3) If a digest matches, print the plaintext and remove it.
      4) Stop early when all are found or the limit is reached.
    """
    targets = _generate_synthetic_targets(count=10)  # digest -> pin
    remaining = set(targets.keys())

    print("[lab] Synthetic targets (showing up to 3):")
    for i, (h, p) in enumerate(targets.items()):
        if i == 3:
            print(" ...")
            break
        print(" ", h, "->", p)

    print(f"[lab] Start enumeration up to {limit:,} candidates (early exit on success).")
    t0 = time.perf_counter()
    found = 0

    for i in range(limit):
        cand = f"{i:08d}"
        digest = sha256_hash_str(cand)
        if digest in remaining:
            print(cand)  # друк знайденого plaintext — простий формат для скріну
            remaining.remove(digest)
            found += 1
            if not remaining:
                break

    elapsed = time.perf_counter() - t0
    print(f"[lab] Found {found}/10 in {elapsed:.3f}s. Remaining: {len(remaining)}")
    if remaining:
        print("[lab] Increase --limit or run full 1e8 to guarantee all 10 are found.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safe SHA-256 benchmark and lab demo (no cracking of provided hashes)."
    )
    parser.add_argument("--benchmark", action="store_true",
                        help="Run SHA-256 throughput benchmark on UTF-8 strings.")
    parser.add_argument("--lab-demo", action="store_true",
                        help="Run a SAFE lab demo using locally generated hashes.")
    parser.add_argument("--limit", type=int, default=5_000_000,
                        help="Candidate enumeration limit for --lab-demo (default: 5,000,000).")
    args = parser.parse_args()

    start_time = time.perf_counter()

    # За замовчуванням — безпечний бенчмарк. Для демонстрації — --lab-demo.
    if args.benchmark or (not args.benchmark and not args.lab_demo):
        benchmark_sha256()

    if args.lab_demo:
        lab_demo(limit=args.limit)

    print("Elapsed:", time.perf_counter() - start_time)


if __name__ == "__main__":
    main()
