import multiprocessing
import numpy as np
import time
from concurrent.futures import ProcessPoolExecutor, wait
from hashlib import sha256
from numpy import ndarray

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


def generate_password_list(end_range: int = 100000000) -> ndarray:
    numbers = np.arange(end_range)
    return numbers


def brute_force_password(hash_password: str, combination_len: int = 8) -> dict:
    crack_password = {}
    for combination in generate_password_list():
        if hash_password == sha256_hash_str(str(combination).zfill(combination_len)):
            crack_password[hash_password] = str(combination).zfill(combination_len)
            break
    return crack_password


def brute_force_password_print(index: int, number: str) -> None:
    crack_password = brute_force_password(number)
    print(f"Result of task {index}: {crack_password}")
    print("*******************" * 5)


def main_multiprocessing(in_numbers: list) -> None:
    futures = []
    with ProcessPoolExecutor(multiprocessing.cpu_count() - 1) as executor:
        for index, number in enumerate(in_numbers):
            futures.append(executor.submit(brute_force_password_print, index, number))
    wait(futures)


if __name__ == "__main__":
    start_time = time.perf_counter()
    generate_password_list()
    main_multiprocessing(PASSWORDS_TO_BRUTE_FORCE)
    end_time = time.perf_counter()
    print("Elapsed:", end_time - start_time)
