import time
from concurrent.futures import wait
from hashlib import sha256
import concurrent.futures
import os


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

CPU_COUNT = os.cpu_count() or 1
NUM_OF_PROCESSORS = max(1, CPU_COUNT - 1)

LENGTH_OF_PASSWORD = 8
AMOUNT_OF_SYMBOLS = 10
MAIN_RANGE = AMOUNT_OF_SYMBOLS**LENGTH_OF_PASSWORD
TARGETS = set(PASSWORDS_TO_BRUTE_FORCE)


def check_range(start: int, end: int) -> list:
    found = []

    for passwd in range(start, end):
        candidate = f"{passwd:08d}"
        hash_r = sha256_hash_str(candidate)

        if hash_r in TARGETS:
            print(f"[!] MATCH FOUND: {candidate=} | {hash_r=}")
            found.append((candidate, hash_r))
    return found


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_password() -> dict:
    recovered_data = {}
    with concurrent.futures.ProcessPoolExecutor(
            max_workers=NUM_OF_PROCESSORS
    ) as executor:
        futures = []
        chunk = MAIN_RANGE // NUM_OF_PROCESSORS

        for unit in range(NUM_OF_PROCESSORS):
            start = unit * chunk
            end = (unit + 1) * chunk
            if unit == NUM_OF_PROCESSORS - 1:
                end = MAIN_RANGE

            futures.append(executor.submit(check_range, start, end))

    for f in concurrent.futures.as_completed(futures):
        batch = f.result()
        for passw, hash_v in batch:
            recovered_data[hash_v] = passw
    return recovered_data


if __name__ == "__main__":
    start_time = time.perf_counter()
    results_map = brute_force_password()

    expected_count = len(PASSWORDS_TO_BRUTE_FORCE)
    actual_count = len(results_map)

    assert actual_count == expected_count, (
        f"Expected {expected_count} unique passwords, but found {actual_count}"
    )
    print("\n--- FINAL REPORT ---")
    for hash_v, password in results_map.items():
        print(f"Password: {password} -> Hash: {hash_v}")

    end_time = time.perf_counter()
    print(f"\n[SUCCESS] All {actual_count} passwords recovered.")
    print(f"Elapsed: {end_time - start_time:.2f} seconds")
