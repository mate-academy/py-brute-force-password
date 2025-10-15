import os
import time
from hashlib import sha256
from typing import Tuple, List
from multiprocessing import Pool, Manager, Event

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

CHUNK_SIZE = 100_000
MAX_DIGITS = 8


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def worker(args: Tuple[int, int, List[str], Event]) -> List[Tuple[str, str]]:
    start, end, target_hashes_list, stop_event = args
    target = set(target_hashes_list)

    found: List[Tuple[str, str]] = []

    for i in range(start, end):
        if stop_event.is_set():
            break

        candidate = f"{i:0{MAX_DIGITS}d}"
        h = sha256_hash_str(candidate)
        if h in target:
            found.append((h, candidate))
    return found


def chunk_ranges(total: int, chunk_size: int) -> List[Tuple[int, int]]:
    ranges = []
    for start in range(0, total, chunk_size):
        end = min(start + chunk_size, total)
        ranges.append((start, end))
    return ranges


def brute_force_password(target_hashes: list[str],
                         processes: int | None = None,
                         chunk_size: int = CHUNK_SIZE,
                         stop_after_first: bool = True):
    total = 10 ** MAX_DIGITS
    ranges = chunk_ranges(total, chunk_size)
    manager = Manager()
    stop_event = manager.Event()
    found_results = manager.dict()
    n_targets = len(target_hashes)

    target_list = list(target_hashes)
    tasks = [(start, end, target_list, stop_event) for (start, end) in ranges]

    if processes is None:
        processes = os.cpu_count() or 4

    print(f"Starting search: total={total:,} combos, chunk_size={chunk_size:,}, "
          f"tasks={len(tasks):,}, processes={processes}")

    with Pool(processes=processes) as pool:
        for result in pool.imap_unordered(worker, tasks):
            for h, plain in result:

                found_results[h] = plain
                print(f"Found: {h} -> {plain}")
                print("-" * 100 + "\n")

            if stop_after_first and len(found_results) > 0:
                stop_event.set()
                print("Stop event set — asking other workers to finish early.")
                break
            if len(found_results) >= n_targets:
                stop_event.set()
                print("All target hashes found — stopping search.")
                break


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password(target_hashes=PASSWORDS_TO_BRUTE_FORCE, stop_after_first=False)
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
