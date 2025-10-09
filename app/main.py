import time
import os
from hashlib import sha256
import multiprocessing as mp

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


def find_in_range_task(task: tuple[int, int, set]) -> dict[str, str]:
    start, end, target_hashes = task
    found_passwords = {}
    local_sha256 = sha256_hash_str
    for i in range(start, end):
        candidate = "{:08d}".format(i)
        current_hash = local_sha256(candidate)
        if current_hash in target_hashes:
            found_passwords[current_hash] = candidate
    return found_passwords


def brute_force_passwords() -> None:
    target_hashes = set(PASSWORDS_TO_BRUTE_FORCE)
    all_found_passwords = {}

    num_workers = os.cpu_count() or 1
    total_range = 10 ** 8
    chunk_size = 100_000

    tasks = []
    for start in range(0, total_range, chunk_size):
        end = min(start + chunk_size, total_range)
        tasks.append((start, end, target_hashes))
    total_tasks = len(tasks)

    processed_tasks = 0
    pool_size = min(num_workers, total_tasks)

    with mp.Pool(processes=pool_size) as pool:
        for result in pool.imap_unordered(find_in_range_task, tasks):
            processed_tasks += 1

            if result:
                for found_hash, plaintext in result.items():
                    if found_hash not in all_found_passwords:
                        all_found_passwords[found_hash] = plaintext

            if len(all_found_passwords) >= len(target_hashes):
                pool.terminate()
                break

    print("{:^64}  {}".format("Hash", "Password"))
    for original_hash in PASSWORDS_TO_BRUTE_FORCE:
        password = all_found_passwords.get(original_hash, "NOT FOUND")
        print("{:64}  {}".format(original_hash, password))

    print(f"\nProcessed chunks: {processed_tasks}/{total_tasks} — "
          f"Found passwords: {len(all_found_passwords)}/{len(target_hashes)}")


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_passwords()
    elapsed = time.perf_counter() - start_time
    print("\nElapsed: {:.2f} seconds".format(elapsed))
