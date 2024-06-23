import time
import hashlib
import itertools
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Iterable, Dict

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


def sha256_hash_str(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def check_password(passwords: Iterable[str]) -> Dict[str, str]:
    found_passwords = {}
    for password in passwords:
        hashed_password = sha256_hash_str(password)
        if hashed_password in PASSWORDS_TO_BRUTE_FORCE:
            found_passwords[hashed_password] = password
    return found_passwords


def main() -> None:
    start_time = time.time()

    all_combinations = itertools.product("0123456789", repeat=8)

    chunk_size = 1000000
    chunks = []
    chunk = []

    for combo in all_combinations:
        chunk.append("".join(combo))
        if len(chunk) == chunk_size:
            chunks.append(chunk)
            chunk = []

    if chunk:
        chunks.append(chunk)

    found_passwords = {}
    with ProcessPoolExecutor() as executor:
        futures = [
            executor.submit(check_password, passwords)
            for passwords in chunks
        ]

        for future in as_completed(futures):
            found_passwords.update(future.result())
            if len(found_passwords) >= len(PASSWORDS_TO_BRUTE_FORCE):
                break

    end_time = time.time()
    total_time = end_time - start_time

    print("\nTotal execution time:", total_time)
    assert len(found_passwords) == len(
        PASSWORDS_TO_BRUTE_FORCE
    ), "Not all passwords were found!"

    print("\nAll found passwords:")
    for hash_val, password in found_passwords.items():
        print(f"Hash: {hash_val} -> Password: {password}")


if __name__ == "__main__":
    main()
