import multiprocessing
import time
from hashlib import sha256


PASSWORDS_TO_BRUTE_FORCE = {
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
}


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def check_range(start: int, end: int, targets: set) -> list:
    local_found = []
    for i in range(start, end):
        password = f"{i:08d}"
        hashed_pass = sha256_hash_str(password)

        if hashed_pass in targets:
            print(f"Found: {password} -> {hashed_pass}")
            local_found.append((hashed_pass, password))
    return local_found


def run_multiprocessing() -> dict:
    num_processes = multiprocessing.cpu_count()
    total_combinations = 100_000_000
    step = total_combinations // num_processes

    ranges = []
    for i in range(num_processes):
        start = i * step

        end = (i + 1) * step if i < num_processes - 1 else total_combinations
        ranges.append((start, end, PASSWORDS_TO_BRUTE_FORCE))

    print(f"Starting {num_processes} processes...")

    with multiprocessing.Pool(processes=num_processes) as pool:
        results = pool.starmap(check_range, ranges)

    final_results = {}
    for res_list in results:
        for hashed_pass, pwd in res_list:
            final_results[hashed_pass] = pwd

    return final_results


if __name__ == "__main__":
    start_time = time.perf_counter()
    found_passwords = run_multiprocessing()

    end_time = time.perf_counter()

    print("\n" + "=" * 30)
    print("RESULTS SUMMARY:")

    passwords_list = list(found_passwords.values())
    for idx, pwd in enumerate(passwords_list, 1):
        print(f"Password {idx}: {pwd}")

    if len(found_passwords) == 10:
        print("\nSuccess: All 10 passwords found!")
    else:
        print(f"\nWarning: Found {len(found_passwords)}"
              f" passwords instead of 10.")

    print(f"Total elapsed time: {end_time - start_time:.2f} seconds")
    print("=" * 30)
