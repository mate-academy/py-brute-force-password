import os
import time
from concurrent.futures import as_completed, ProcessPoolExecutor
from hashlib import sha256

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


def brute_force_chunk(start: int, end: int, target_hashes: set) -> dict:
    local_found = {}

    for i in range(start, end):
        candidate = str(i).zfill(8)
        current_hash = sha256_hash_str(candidate)

        if current_hash in target_hashes:
            local_found[current_hash] = candidate
            print(f"[+] Found by worker: {candidate} -> {current_hash}")

            if len(local_found) == len(target_hashes):
                break

    return local_found


def brute_force_password() -> None:
    target_hashes = set(PASSWORDS_TO_BRUTE_FORCE)
    final_found_passwords = {}

    num_workers = os.cpu_count() or 4
    total_space = 100000000
    chunk_size = total_space // num_workers

    print(f"Starting parallel brute-force using {num_workers} CPU workers...")

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = []

        for worker in range(num_workers):
            start = worker * chunk_size
            if worker == num_workers - 1:
                end = total_space
            else:
                end = (worker + 1) * chunk_size

            futures.append(
                executor.submit(brute_force_chunk, start, end, target_hashes)
            )

        for future in as_completed(futures):
            res = future.result()
            final_found_passwords.update(res)

    if len(final_found_passwords) != len(PASSWORDS_TO_BRUTE_FORCE):
        raise RuntimeError(
            "Not all hashes were resolved; expected 10 passwords."
        )

    print("\n=== Final Results ===")
    for item in PASSWORDS_TO_BRUTE_FORCE:
        print(
            f"Hash: {item} -> "
            f"Password: {final_found_passwords[item]}"
        )


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    elapsed_time = round(end_time - start_time, 2)
    print(f"Elapsed: {elapsed_time} seconds")
