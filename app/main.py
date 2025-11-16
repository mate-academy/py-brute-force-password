import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, wait
from hashlib import sha256
from typing import List

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


SET_BRUTE_FORCE = set(PASSWORDS_TO_BRUTE_FORCE)


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_worker(start: int, end: int) -> List[str]:
    found_passwords = []
    local_target_set = SET_BRUTE_FORCE

    for password in range(start, end):
        pass_str = f"{password:08d}"
        sha_result = sha256_hash_str(pass_str)

        if sha_result in local_target_set:
            found_passwords.append(pass_str)

    return found_passwords


def main_multiprocess_executor() -> None:
    total_numbers = 100_000_000
    cpu_count = multiprocessing.cpu_count()
    workers_count = max(1, cpu_count - 1)

    step = total_numbers // workers_count
    futures = []
    found_all = []

    print(f"Starting brute force with {workers_count} workers...")

    with ProcessPoolExecutor(max_workers=workers_count) as executor:
        for i in range(workers_count):
            start = i * step
            end = total_numbers if i == workers_count - 1 else (i + 1) * step

            futures.append(executor.submit(brute_force_worker, start, end))

        done, _ = wait(futures)

        for future in done:
            result = future.result()
            if result:
                found_all.extend(result)

    print(f"Found passwords: {found_all}")


if __name__ == "__main__":
    start_time = time.perf_counter()

    main_multiprocess_executor()

    end_time = time.perf_counter()
    print(f"Elapsed time: {end_time - start_time:.4f} seconds")