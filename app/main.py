# optimized_main.py
import time
import hashlib
import os
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED
from typing import Dict

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

# convert to set for O(1) membership tests
TARGET_HASHES = set(PASSWORDS_TO_BRUTE_FORCE)
TARGET_COUNT = len(TARGET_HASHES)


def sha256_hash_str(password: str) -> str:
    # exact encoding and hashing as required
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def worker_range(start: int, end: int, target_hashes: set) -> Dict[str, str]:
    """
    Check all numeric candidates from start (inclusive) to end (exclusive).
    Each candidate formatted as 8-digit string: f"{i:08d}".
    Returns dict mapping found_hash -> password for hits in this range.
    """
    found: Dict[str, str] = {}
    for i in range(start, end):
        candidate = f"{i:08d}"
        h = sha256_hash_str(candidate)
        if h in target_hashes:
            # avoid overwriting if duplicate, but there are no duplicates in this task
            if h not in found:
                found[h] = candidate
    return found


def main() -> None:
    start_time = time.time()

    MAX = 10 ** 8  # all 8-digit combinations from 00000000 to 99999999
    RANGE_SIZE = 100_000  # size per task; tuneable (trade-off: overhead vs wasted work)
    max_workers = os.cpu_count() or 4

    # collected results
    found_passwords: Dict[str, str] = {}

    # in-flight futures
    in_flight = set()

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        start = 0
        # Submit first batch (up to max_workers) to keep CPU busy
        while len(in_flight) < max_workers and start < MAX:
            f = executor.submit(worker_range, start, min(MAX, start + RANGE_SIZE), TARGET_HASHES)
            in_flight.add(f)
            start += RANGE_SIZE

        # Continue submitting new tasks as others complete, stop early when done
        while in_flight and len(found_passwords) < TARGET_COUNT:
            # wait for at least one future to complete
            done, _ = wait(in_flight, return_when=FIRST_COMPLETED)

            # process completed futures
            for fut in done:
                in_flight.remove(fut)
                try:
                    res = fut.result()
                except Exception as e:
                    # log and continue; in production collect/log exceptions
                    print("Worker raised:", e)
                    res = {}
                # merge results
                for h, pwd in res.items():
                    if h not in found_passwords:
                        found_passwords[h] = pwd

            # if we still have ranges to submit and not finished, submit to keep pipelines full
            while len(in_flight) < max_workers and start < MAX and len(found_passwords) < TARGET_COUNT:
                f = executor.submit(worker_range, start, min(MAX, start + RANGE_SIZE), TARGET_HASHES)
                in_flight.add(f)
                start += RANGE_SIZE

        # optional: cancel remaining not-started futures (best-effort)
        for fut in list(in_flight):
            fut.cancel()

    end_time = time.time()
    total_time = end_time - start_time

    print("\nTotal execution time:", total_time)
    print(f"Found {len(found_passwords)} / {TARGET_COUNT} passwords.")

    if len(found_passwords) < TARGET_COUNT:
        print("Warning: not all passwords were found (search was stopped early or missed).")
    else:
        print("\nAll found passwords:")
        for hash_val, password in found_passwords.items():
            print(f"Hash: {hash_val} -> Password: {password}")

    # assert only if you require all to be found
    assert len(found_passwords) == TARGET_COUNT, "Not all passwords were found!"


if __name__ == "__main__":
    main()
