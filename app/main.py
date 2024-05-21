import time
import multiprocessing
import itertools

from hashlib import sha256
from concurrent.futures import ProcessPoolExecutor, wait


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


def brute_force_password(password_hash: str) -> str:
    for combination in itertools.product("0123456789", repeat=8):
        possible_password = "".join(combination)
        if sha256_hash_str(possible_password) == password_hash:
            return possible_password


def brute_force_password_print(index: int, password_hash: str) -> None:
    print(f"Started {index} password.")
    password = brute_force_password(password_hash)
    print(f"Found {index} password: {password}")


def find_passwords_executor(password_hashes: list[str]) -> None:
    futures = []
    with ProcessPoolExecutor(multiprocessing.cpu_count() - 1) as executor:
        for index, password_hash in enumerate(password_hashes):
            futures.append(executor.submit(
                brute_force_password_print,
                index,
                password_hash
            ))
    wait(futures)


if __name__ == "__main__":
    start_time = time.perf_counter()
    find_passwords_executor(PASSWORDS_TO_BRUTE_FORCE)
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
