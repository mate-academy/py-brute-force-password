# authorized_bruteforce_demo.py
# Educational/demo code for authorized coursework only.
# Scans numeric 8-digit candidates "00000000".."99999999" looking for matches in TARGET_HASHES.
# Splits the search space into disjoint chunks and uses ProcessPoolExecutor to parallelize.

import time
from hashlib import sha256
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
from typing import Dict, Set, Tuple, List

# Example target hashes (replace with hashes you generated for the exercise)
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
    return sha256(to_hash.encode("utf-8")).hexdigest()

def scan_range(start: int, end: int, targets: Set[str]) -> Dict[str, str]:
    found: Dict[str, str] = {}
    for i in range(start, end):
        candidate = f"{i:08d}"
        h = sha256_hash_str(candidate)
        if h in targets:
            found[h] = candidate
    return found

def chunk_ranges(total: int, chunk_size: int) -> List[Tuple[int, int]]:
    ranges = []
    for start in range(0, total, chunk_size):
        end = min(start + chunk_size, total)
        ranges.append((start, end))
    return ranges

def brute_force_password(target_hashes: List[str],
                         total_space: int = 100_000_000,
                         chunk_size: int = 1_000_000):
    assert total_space >= 1
    targets = set(target_hashes)
    found: Dict[str, str] = {}

    cpu_count = max(1, multiprocessing.cpu_count() - 1)
    ranges = chunk_ranges(total_space, chunk_size)

    print(f"Workers: {cpu_count}, total chunks: {len(ranges)}, chunk_size: {chunk_size}")
    with ProcessPoolExecutor(max_workers=cpu_count) as ex:
        futures = {ex.submit(scan_range, start, end, targets): (start, end) for start, end in ranges}
        try:
            for fut in as_completed(futures):
                chunk_start, chunk_end = futures[fut]
                result = fut.result()
                if result:
                    for h, plain in result.items():
                        if h not in found:
                            found[h] = plain
                if len(found) >= len(targets):
                    print("All targets found; attempting to cancel remaining tasks...")
                    return found
        except KeyboardInterrupt:
            print("Interrupted by user; shutting down executor.")

if __name__ == "__main__":
    TEST_TOTAL = 100_000_000
    TEST_CHUNK = 1_000_00
    start_time = time.perf_counter()
    found = brute_force_password(PASSWORDS_TO_BRUTE_FORCE, total_space=TEST_TOTAL, chunk_size=TEST_CHUNK)
    end_time = time.perf_counter()
    for key in found.keys():
        print(f"Hash: {key}. Password {found[key]}")

    print("Elapsed:", end_time - start_time)
