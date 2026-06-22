import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from hashlib import sha256
from os import cpu_count


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


def find_passwords_in_range(
    start: int,
    stop: int,
    hashes_to_find: set[bytes],
) -> dict[bytes, str]:
    found_passwords = {}
    hash_password = sha256

    for password_number in range(start, stop):
        password = f"{password_number:08d}"
        hashed_password = hash_password(password.encode()).digest()

        if hashed_password in hashes_to_find:
            found_passwords[hashed_password] = password

    return found_passwords


def brute_force_password() -> None:
    hashes_to_find = {
        bytes.fromhex(password_hash)
        for password_hash in PASSWORDS_TO_BRUTE_FORCE
    }
    found_passwords: dict[bytes, str] = {}
    passwords_count = 100_000_000
    chunk_size = 100_000
    workers_count = cpu_count() or 1
    next_range_start = 0

    with ProcessPoolExecutor(max_workers=workers_count) as executor:
        futures = set()

        while (
            len(futures) < workers_count
            and next_range_start < passwords_count
        ):
            futures.add(executor.submit(
                find_passwords_in_range,
                next_range_start,
                next_range_start + chunk_size,
                hashes_to_find,
            ))
            next_range_start += chunk_size

        while futures and len(found_passwords) < len(hashes_to_find):
            done_futures, futures = wait(
                futures,
                return_when=FIRST_COMPLETED,
            )

            for future in done_futures:
                found_passwords.update(future.result())

            while (
                len(futures) < workers_count
                and next_range_start < passwords_count
                and len(found_passwords) < len(hashes_to_find)
            ):
                futures.add(executor.submit(
                    find_passwords_in_range,
                    next_range_start,
                    next_range_start + chunk_size,
                    hashes_to_find,
                ))
                next_range_start += chunk_size

        for future in futures:
            future.cancel()

    for password_hash in PASSWORDS_TO_BRUTE_FORCE:
        print(found_passwords[bytes.fromhex(password_hash)])


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
