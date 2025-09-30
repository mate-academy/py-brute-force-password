import time
import os
import sys
from hashlib import sha256
from multiprocessing import Pool, Manager
from functools import partial

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

SEARCH_SPACE = 100_000_000
SUB_CHUNK_SIZE = 10_000


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def worker_chunk(args, target_hashes, found_dict, stop_flag):
    start, end = args
    found = []
    check_interval = 1000

    for i in range(start, end):
        if i % check_interval == 0 and stop_flag.value:
            break

        password = f"{i:08d}"
        hash_value = sha256_hash_str(password)

        if hash_value in target_hashes:
            if hash_value not in found_dict:
                found_dict[hash_value] = password
                found.append((password, hash_value))

                if len(found_dict) >= len(PASSWORDS_TO_BRUTE_FORCE):
                    stop_flag.value = 1
                    break

    return found


def brute_force_password():
    print("Starting brute force attack...")
    print(f"Search space: {SEARCH_SPACE:,} combinations")
    print(f"Target passwords: {len(PASSWORDS_TO_BRUTE_FORCE)}")

    manager = Manager()
    target_hashes = set(PASSWORDS_TO_BRUTE_FORCE)
    found_dict = manager.dict()
    stop_flag = manager.Value('i', 0)

    workers = os.cpu_count() or 1
    print(f"Using {workers} CPU cores")
    print(f"Sub-chunk size: {SUB_CHUNK_SIZE:,}\n")

    subtasks = []
    for start in range(0, SEARCH_SPACE, SUB_CHUNK_SIZE):
        end = min(start + SUB_CHUNK_SIZE, SEARCH_SPACE)
        subtasks.append((start, end))

    print(f"Total subtasks: {len(subtasks)}")
    print("=" * 50)

    worker_func = partial(
        worker_chunk,
        target_hashes=target_hashes,
        found_dict=found_dict,
        stop_flag=stop_flag
    )

    start_time = time.perf_counter()

    with Pool(processes=workers) as pool:
        try:
            for result in pool.imap_unordered(worker_func, subtasks):
                if result:
                    for password, hash_value in result:
                        count = len(found_dict)
                        print(f"[{count}/{len(PASSWORDS_TO_BRUTE_FORCE)}] Found: {password} -> {hash_value}")

                if stop_flag.value:
                    print("\nAll passwords found! Terminating remaining tasks...")
                    pool.terminate()
                    break

        except KeyboardInterrupt:
            print("\nInterrupted by user")
            pool.terminate()
            raise
        finally:
            pool.close()
            pool.join()

    end_time = time.perf_counter()
    elapsed = end_time - start_time

    print("=" * 50)
    print(f"\nSearch completed in {elapsed:.2f} seconds")
    print(f"Passwords found: {len(found_dict)}/{len(PASSWORDS_TO_BRUTE_FORCE)}\n")

    print("Results:")
    for i, target_hash in enumerate(PASSWORDS_TO_BRUTE_FORCE, 1):
        password = found_dict.get(target_hash, "NOT FOUND")
        status = "✓" if password != "NOT FOUND" else "✗"
        print(f"{i:2}. {status} {password}")

    if len(found_dict) != len(PASSWORDS_TO_BRUTE_FORCE):
        print(f"\nERROR: Expected {len(PASSWORDS_TO_BRUTE_FORCE)} passwords, but found {len(found_dict)}")
        print("Brute force incomplete! Not all passwords were recovered.")
        sys.exit(1)
    else:
        print("\nSuccess! All passwords recovered and verified.")
        return dict(found_dict)


if __name__ == "__main__":
    brute_force_password()