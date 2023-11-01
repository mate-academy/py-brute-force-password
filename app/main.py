import time
from concurrent.futures import ProcessPoolExecutor, wait
from hashlib import sha256
from multiprocessing import cpu_count
from typing import Generator

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
    for password in range(start, end):
        eight_num_password = str(password).zfill(8)
        hashed_password = sha256_hash_str(eight_num_password)
        if hashed_password in PASSWORDS_TO_BRUTE_FORCE:
            print(
                f"{PASSWORDS_TO_BRUTE_FORCE.index(hashed_password) + 1} "
                f"Password: {eight_num_password}\n"
                f"Hash: {hashed_password}\n {'-' * 70}"
            )


def chunk_range(total: int, chunks: int) -> Generator:
    chunk_size = total // chunks
    for i in range(chunks):
        start = i * chunk_size
        end = start + chunk_size + (total % chunks if i == chunks - 1 else 0)
        yield start, end


def brute_force_password() -> None:
    futures = []
    max_value = 10**8
    processors = cpu_count() - 1

    with ProcessPoolExecutor(processors) as executor:
        for start, end in chunk_range(max_value, processors):
            futures.append(executor.submit(find_password, start, end))
        wait(futures)


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
