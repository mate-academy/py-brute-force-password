import multiprocessing
import time
from hashlib import sha256
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


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_password(start, end) -> None:
    results = []
    for i in range(start, end):
        candidate = f"{i:08}"
        encode_candidate = sha256_hash_str(candidate)
        if encode_candidate in PASSWORDS_TO_BRUTE_FORCE:
            results.append(candidate)
    return results


# multiprocessing method Code for CPU-bound
def main_multiprocessing() -> None:
    # Define the range of numbers to brute force (00000000 to 99999999)
    total_candidate = 10 ** 8
    cpu_count = multiprocessing.cpu_count() - 1
    piece_of_work = total_candidate // cpu_count

    # Range for processing
    ranges = [(i * piece_of_work, (i + 1) * piece_of_work) for i in range(piece_of_work)]
    ranges[-1] = (ranges[-1][0], total_candidate) # CHeck last cover range

    futures = []
    found_passwords = []

    with ProcessPoolExecutor(cpu_count) as executor:
        for start, end in ranges:
            futures.append(executor.submit(brute_force_password, start, end))

        for future in as_completed(futures):
            found_passwords.extend(future.result())

            # Exit early if all passwords are found
            if len(found_passwords) >= len(PASSWORDS_TO_BRUTE_FORCE):
                print("All passwords found.")
                executor.shutdown(wait=False, cancel_futures=True)
                break

    # Print the result
    print("Found password")
    for pwd in found_passwords:
        print(pwd)


if __name__ == "__main__":
    start_time = time.perf_counter()
    main_multiprocessing()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
