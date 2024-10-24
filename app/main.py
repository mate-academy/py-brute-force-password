import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, wait
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


def find_password(start: int, end: int) -> None:
    print(f"Search from {start} to {end}")
    for num in range(start, end):
        num = str(num).zfill(8)
        num_hash = sha256_hash_str(str(num))
        if num_hash in PASSWORDS_TO_BRUTE_FORCE:
            password_num = PASSWORDS_TO_BRUTE_FORCE.index(num_hash)
            print(f"Password #{password_num}: {num}")


def brute_force_password() -> None:
    futures = []
    num_processes = multiprocessing.cpu_count() - 1
    interval = 100000000 // len(PASSWORDS_TO_BRUTE_FORCE)

    with ProcessPoolExecutor(num_processes) as executor:
        for i, hash_ps in enumerate(PASSWORDS_TO_BRUTE_FORCE):
            futures.append(executor.submit(find_password, interval * i, interval * (i + 1)))

    wait(futures)


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
