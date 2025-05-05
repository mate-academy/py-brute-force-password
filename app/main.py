import time
from hashlib import sha256
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

# Target hashes to crack
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

HASH_SET = set(PASSWORDS_TO_BRUTE_FORCE)


def sha256_hash_str(to_hash: str) -> str:
    """Hash a string using SHA-256 and return the hexadecimal digest."""
    return sha256(to_hash.encode("utf-8")).hexdigest()


def check_password(start: int, end: int) -> list:
    """Check a range of passwords and return any matches."""
    found_passwords = []

    for i in range(start, end):
        password = f"{i:08d}"
        password_hash = sha256_hash_str(password)
        if password_hash in HASH_SET:
            found_passwords.append((password, password_hash))

    return found_passwords


def brute_force_password() -> None:
    """Brute force 8-digit numeric passwords in parallel."""
    start_time = time.perf_counter()

    num_workers = max(1, multiprocessing.cpu_count() - 1)
    print(f"Using {num_workers} worker processes")

    max_value = 100_000_000

    step = 5_000_000

    all_passwords = []
    found_count = 0

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        for i in range(0, max_value, step):
            end = min(i + step, max_value)
            futures.append(executor.submit(check_password, i, end))

        for future in as_completed(futures):
            result = future.result()
            if result:
                all_passwords.extend(result)
                for pwd, hash_val in result:
                    found_count += 1
                    print(f"Found password: {pwd} for hash: {hash_val}")

                if found_count >= 10:
                    for f in futures:
                        if not f.done():
                            f.cancel()
                    break

    print(f"\nFound {found_count} passwords:")

    hash_positions = {h: i for i, h in enumerate(PASSWORDS_TO_BRUTE_FORCE)}
    all_passwords.sort(key=lambda x: hash_positions.get(x[1], 999))

    for i, (password, hash_val) in enumerate(all_passwords):
        print(f"Found password: {password} and hash: {hash_val}")

if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
