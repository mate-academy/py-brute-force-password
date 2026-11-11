import time
from concurrent.futures import ProcessPoolExecutor
from hashlib import sha256
from multiprocessing import cpu_count, get_context
from typing import List, Set, Tuple


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

PASSWORD_LENGTH = 8
TOTAL_PASSWORDS = 10 ** PASSWORD_LENGTH
TARGET_HASHES: Set[str] = set(PASSWORDS_TO_BRUTE_FORCE)


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def search_password_range(
    range_bounds: Tuple[int, int],
) -> List[str]:
    start_number, end_number = range_bounds
    hash_password = sha256_hash_str
    target_hashes = TARGET_HASHES
    found_passwords: List[str] = []

    for number in range(start_number, end_number):
        candidate = f"{number:08d}"
        if hash_password(candidate) in target_hashes:
            found_passwords.append(candidate)

    return found_passwords


def build_ranges(worker_count: int) -> List[Tuple[int, int]]:
    chunk_size = TOTAL_PASSWORDS // worker_count
    ranges: List[Tuple[int, int]] = []

    for worker_index in range(worker_count):
        start_number = worker_index * chunk_size
        if worker_index == worker_count - 1:
            end_number = TOTAL_PASSWORDS
        else:
            end_number = start_number + chunk_size
        ranges.append((start_number, end_number))

    return ranges


def brute_force_password() -> None:
    worker_count = cpu_count()
    ranges = build_ranges(worker_count)
    found_passwords: List[str] = []

    with ProcessPoolExecutor(
        max_workers=worker_count,
        mp_context=get_context("fork"),
    ) as executor:
        for chunk_passwords in executor.map(
            search_password_range,
            ranges,
        ):
            found_passwords.extend(chunk_passwords)

    for password in sorted(found_passwords):
        print(password)


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
