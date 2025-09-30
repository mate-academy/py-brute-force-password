import multiprocessing
import time
from hashlib import sha256
from multiprocessing import Pool

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


TARGETS = set(PASSWORDS_TO_BRUTE_FORCE)
DIGITS = 8
TOTAL = 100_000_000


def worker_task(args):
    start, end = args
    found = {}
    for i in range(start, end):
        _string = f"{i:0{DIGITS}d}"
        _hash = sha256_hash_str(_string)
        if _hash in TARGETS:
            found[_hash] = _string
            if len(found) == len(TARGETS):
                break
    return found


def brute_force_password(chunk_size: int = 100_000) -> None:
    processes = max(1, multiprocessing.cpu_count() - 1)

    tasks = []

    for start in range(0, TOTAL, chunk_size):
        end = min(start + chunk_size, TOTAL)
        tasks.append((start, end))

    found = {}

    with Pool(processes=processes) as pool:
        for result in pool.imap_unordered(worker_task, tasks):
            for _hash, pw in result.items():
                if _hash not in found:
                    found[_hash] = pw
            if len(found) >= len(TARGETS):
                pool.terminate()
                break

    assert len(found) == len(TARGETS), \
        f"Found {len(found)}/{len(TARGETS)} passwords — required all 10."

    print(f"\nDONE. Found {len(found)}/{len(TARGETS)}")

    for _hash in PASSWORDS_TO_BRUTE_FORCE:
        print(f"{_hash} -> {found.get(_hash)}")


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
