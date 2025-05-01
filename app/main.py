import time
from hashlib import sha256
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, as_completed


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


def validate_password(
        start: int,
        end: int,
        password_hashes: set,
        found_passwords: set
) -> list:
    results = []
    for i in range(start, end):
        password = str(i).zfill(8)
        hashed = sha256(password.encode("utf-8")).hexdigest()
        if hashed in password_hashes and password not in found_passwords:
            results.append(password)
    return results


def brute_force_password() -> None:
    num_cpu = multiprocessing.cpu_count() - 1
    total_numbers = 100_000_000
    chunk_size = total_numbers // num_cpu
    password_hashes = set(PASSWORDS_TO_BRUTE_FORCE)
    found_passwords = set()

    with ProcessPoolExecutor(num_cpu) as executor:
        futures = []
        for cpu in range(num_cpu):
            start = cpu * chunk_size
            end = (
                (cpu + 1) * chunk_size
                if cpu != num_cpu - 1
                else total_numbers
            )
            futures.append(executor.submit(
                validate_password, start, end, password_hashes, found_passwords
            ))

        for future in as_completed(futures):
            results = future.result()
            for password in results:
                if password not in found_passwords:
                    found_passwords.add(password)
                    print(password)
                    if len(found_passwords) == len(PASSWORDS_TO_BRUTE_FORCE):
                        return


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
