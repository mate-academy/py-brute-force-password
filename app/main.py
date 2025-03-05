import itertools
import time
from concurrent.futures import ProcessPoolExecutor
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
CHARSET = "0123456789"
LENGTH = 8


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_worker(args: tuple) -> list[tuple[str, str]]:
    password_hashes, start, step = args
    results = []

    for candidate in itertools.islice(itertools.product(CHARSET, repeat=LENGTH), start, None, step):
        candidate_str = "".join(candidate)
        candidate_hash = sha256_hash_str(candidate_str)
        if candidate_hash in password_hashes:
            results.append((candidate_hash, candidate_str))
            if len(results) == len(password_hashes):
                break

    return results


def brute_force_password(password_hashes: list[str]) -> list[tuple[str, str]]:
    num_workers = min(len(password_hashes), 8)
    with ProcessPoolExecutor(num_workers) as executor:
        chunk_args = [(password_hashes, i, num_workers) for i in range(num_workers)]
        results = executor.map(brute_force_worker, chunk_args)

    found_passwords = {}
    for result in results:
        for password_hash, password in result:
            found_passwords[password_hash] = password

    return [(ph, found_passwords.get(ph, "Not Found")) for ph in password_hashes]


def display_results(results: list[tuple[str, str]]) -> None:
    for i, (password_hash, password) in enumerate(results, start=1):
        print(f"Password {i}: {password}")


if __name__ == "__main__":
    start_time = time.perf_counter()
    results = brute_force_password(PASSWORDS_TO_BRUTE_FORCE)
    display_results(results)
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
