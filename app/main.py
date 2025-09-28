# app/main.py
from __future__ import annotations

import math
import os
import threading
from hashlib import sha256
from time import perf_counter, sleep
from dataclasses import dataclass
from typing import Set


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


@dataclass(frozen=True)
class Range:
    start: int
    end: int  # exclusive


def split_ranges(total: int, parts: int) -> list[Range]:
    size = math.ceil(total / parts)
    ranges: list[Range] = []
    start = 0
    for _ in range(parts):
        end = min(start + size, total)
        if start >= end:
            break
        ranges.append(Range(start, end))
        start = end
    return ranges


def sha256_hash_str(to_hash: str) -> str:
    """
    Helper required by checklist:
    sha256_hash_str(to_hash: str) -> str returns sha256(to_hash.encode("utf-8")).hexdigest()
    """
    return sha256(to_hash.encode("utf-8")).hexdigest()


def worker_thread(
    r: Range,
    targets: Set[str],
    results: dict,
    results_lock: threading.Lock,
    done: threading.Event,
    counter: list,  # single-element list used as mutable int
    counter_lock: threading.Lock,
    flush_every: int = 2000,
    check_done_every: int = 2000,
) -> None:
    """
    Worker thread computing hashes for its assigned numeric range.

    NOTE (fix for reviewer): previously we computed hashing inline like:
      digest = _sha256(_encode(candidate, "ascii")).hexdigest()
    That has been replaced by the required helper:
      digest = sha256_hash_str(candidate)
    which uses UTF-8 encoding exactly as requested.
    """
    _targets = targets

    local_count = 0
    check_counter = 0

    for n in range(r.start, r.end):
        candidate = f"{n:08d}"
        # use the required helper (UTF-8)
        digest = sha256_hash_str(candidate)
        local_count += 1
        check_counter += 1

        if check_counter >= check_done_every:
            if done.is_set():
                break
            check_counter = 0

        if local_count >= flush_every:
            with counter_lock:
                counter[0] += local_count
            local_count = 0

        if digest in _targets:
            if local_count:
                with counter_lock:
                    counter[0] += local_count
                local_count = 0
            with results_lock:
                if digest not in results:
                    results[digest] = candidate
                    print(f"FOUND: {candidate} -> {digest}", flush=True)
                    if len(results) == len(_targets):
                        done.set()
                        break

    if local_count:
        with counter_lock:
            counter[0] += local_count


def reporter(total_space: int, counter: list, counter_lock: threading.Lock, done: threading.Event, start_time: float) -> None:
    last_count = 0
    last_t = perf_counter()
    while not done.is_set():
        sleep(2)
        t = perf_counter()
        with counter_lock:
            count = int(counter[0])
        delta = count - last_count
        dt = t - last_t
        recent_hps = int(delta / dt) if dt > 0 else 0
        overall_hps = int(count / (t - start_time)) if (t - start_time) > 0 else 0
        pct = (count / total_space) * 100.0
        eta = (total_space - count) / overall_hps if overall_hps > 0 else float("inf")
        print(
            f"[PROGRESS] tried={count:,}  recent={recent_hps:,}/s  overall={overall_hps:,}/s  "
            f"{pct:.3f}%  ETA={eta:.1f}s",
            flush=True,
        )
        last_count = count
        last_t = t
    with counter_lock:
        final_count = int(counter[0])
    print(f"[DONE-REPORT] total tried={final_count:,}", flush=True)


def brute_force_threads(processes: int | None = None) -> list[str]:
    targets = set(PASSWORDS_TO_BRUTE_FORCE)
    cpu_count = os.cpu_count() or 1
    procs = processes or cpu_count
    total = 100_000_000

    results: dict = {}
    results_lock = threading.Lock()
    done = threading.Event()

    counter = [0]
    counter_lock = threading.Lock()

    ranges = split_ranges(total, procs)
    threads: list[threading.Thread] = []
    for r in ranges:
        t = threading.Thread(target=worker_thread, args=(r, targets, results, results_lock, done, counter, counter_lock))
        t.daemon = True
        threads.append(t)

    start_time = perf_counter()
    rep = threading.Thread(target=reporter, args=(total, counter, counter_lock, done, start_time), daemon=True)
    rep.start()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    done.set()
    rep.join(timeout=1.0)
    dt = perf_counter() - start_time

    found_passwords = list(results.values())
    found_passwords.sort(key=lambda s: int(s, 10))
    print(f"# Tempo total: {dt:.2f}s  encontrados: {len(found_passwords)}/{len(targets)}", flush=True)
    return found_passwords


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Threaded brute-force 8-digit numeric passwords (SHA-256).")
    parser.add_argument("-p", "--processes", type=int, default=None, help="número de threads (padrão = qtd. de CPUs).")
    args = parser.parse_args()

    pwds = brute_force_threads(args.processes)
    for pwd in pwds:
        print(pwd)
