import time
import multiprocessing
from hashlib import sha256
from concurrent.futures import ProcessPoolExecutor
from typing import List, Tuple, Set

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

# 1 SYNC VERSION -------------------------------------------------------
# def generate_8digit_combinations():
#     """Generator - doesn't store all in memory"""
#     for combo in product(range(10), repeat=8):
#         yield ''.join(map(str, combo))
#
#
# def brute_force_password() -> None:
#     for eight_digit_string in generate_8digit_combinations():
#         hash_str = sha256_hash_str(eight_digit_string)
#         if hash_str in PASSWORDS_TO_BRUTE_FORCE:
#             print(eight_digit_string)
#             print(hash_str)
# RESULT - 250 sec
# END SYNC VERSION ------------------------------------------------------


def check_password_range(args: Tuple[int, int, Set[str]]) -> List[str]:
    """
    Check a range of passwords against target hashes.
    Returns list of passwords that match.
    """
    start, end, target_hashes = args
    found = []

    for num in range(start, end):
        password = f"{num:08d}"
        password_hash = sha256_hash_str(password)

        if password_hash in target_hashes:
            found.append(password)

    return found


# 2 ASYNC VERSION USING executor.map(check_password_range, ranges) ---------
def brute_force_password() -> None:
    """
    Brute force all 8-digit numeric passwords using multiprocessing.
    Prints found passwords to console.
    """
    total_combinations = 100_000_000
    num_workers = multiprocessing.cpu_count()

    # Convert to set for O(1) lookup
    target_hashes_set = set(PASSWORDS_TO_BRUTE_FORCE)

    # Split work across CPU cores
    chunk_size = total_combinations // num_workers
    ranges = []

    for i in range(num_workers):
        start = i * chunk_size
        end = start + chunk_size if i < num_workers - 1 else total_combinations
        ranges.append((start, end, target_hashes_set))

    # Process ranges in parallel
    all_found = []
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        results = executor.map(check_password_range, ranges)

        for found_passwords in results:
            all_found.extend(found_passwords)

    # Print results (sorted for consistency)
    for password in sorted(all_found):
        print(password)
# RESULT - 35 sec
# END ASYNC VERSION USING executor.map(check_password_range, ranges) --------


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
