import time
from hashlib import sha256
from multiprocessing import Pool, cpu_count

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


def check_password_range(start: int, end: int, target_hashes: set) -> dict:
    """Check a range of passwords and return found matches"""
    found = {}
    for num in range(start, end):
        password = f"{num:08d}"
        hash_val = sha256_hash_str(password)

        if hash_val in target_hashes:
            found[hash_val] = password

    return found

def brute_force_password() -> None:
    # Create a set for fast hash lookups
    target_hashes = set(PASSWORDS_TO_BRUTE_FORCE)
    total_passwords = 10 ** 8  # 100 million

    # Use all available CPU cores
    num_workers = cpu_count()
    print(f"Using {num_workers} CPU cores")
    print(f"Searching through {total_passwords:,} possible passwords...")

    # Divide the work into equal chunks
    chunk_size = total_passwords // num_workers
    tasks = []

    for i in range(num_workers):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i < num_workers - 1 else total_passwords
        tasks.append((start, end, target_hashes.copy()))  # Copy for each process

    # Option 1: Use multiprocessing.Pool (fastest approach)
    found_passwords = {}

    with Pool(processes=num_workers) as pool:
        # Use starmap to pass multiple arguments
        results = pool.starmap(check_password_range, tasks)

        # Collect results from all workers
        for result in results:
            found_passwords.update(result)

        if found_passwords:
            print(f"\nFound {len(found_passwords)} passwords out of {len(PASSWORDS_TO_BRUTE_FORCE)}:")
            print("-" * 40)

            # Sort passwords in ascending order for readability
            sorted_passwords = sorted(found_passwords.values())
            for i, password in enumerate(sorted_passwords, 1):
                print(f"{i:2}. {password}")
        else:
            print("\nNo passwords found!")

if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
