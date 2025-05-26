import hashlib
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import List, Set, Dict


def sha256_hash_str(to_hash: str) -> str:
    """Calculate SHA-256 hash of a string.

    Args:
        to_hash: String to hash

    Returns:
        str: Hexadecimal representation of the hash
    """
    return hashlib.sha256(to_hash.encode("utf-8")).hexdigest()


def process_range(start: int, end: int, target_hashes: Set[str]) -> (
        Dict)[str, str]:
    found_passwords = {}
    for i in range(start, end):
        password = str(i).zfill(8)
        password_hash = sha256_hash_str(password)
        if password_hash in target_hashes:
            found_passwords[password_hash] = password
    return found_passwords


def find_passwords(target_hashes: Set[str]) -> List[str]:
    found_passwords = {}
    chunk_size = 1000000
    total_passwords = 100000000

    with (ProcessPoolExecutor() as executor):
        futures = []
        for start in range(0, total_passwords, chunk_size):
            end = min(start + chunk_size, total_passwords)
            future = executor.submit(process_range, start, end, target_hashes)
            futures.append(future)

        for future in as_completed(futures):
            chunk_results = future.result()
            found_passwords.update(chunk_results)

            if len(found_passwords) == len(target_hashes):
                if all(hash_value in found_passwords for
                       hash_value in target_hashes):
                    break

    return [found_passwords[hash_value] for hash_value in target_hashes]


def main() -> None:
    passwords_to_brute_force = [
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

    target_hashes = set(passwords_to_brute_force)
    found_passwords = find_passwords(target_hashes)

    print("Found passwords:")
    for password in found_passwords:
        print(password)


if __name__ == "__main__":
    main()
