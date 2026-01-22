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


def chunk_ranges(total: int, chunks: int) -> list[tuple[int, int]]:
    step = total // chunks
    ranges = []
    for i in range(chunks):
        start = i * step
        end = (i + 1) * step if i < chunks - 1 else total
        ranges.append((start, end))

    return ranges


def search_range(args) -> None:
    start, end = args
    results = {}
    for number in range(start, end):
        candidate = f"{number:08d}"
        candidate_hash = sha256_hash_str(candidate)
        if candidate_hash in PASSWORDS_TO_BRUTE_FORCE:
            results[candidate_hash] = candidate

    return results

def brute_force_password() -> None:
    total_combinations = 10 ** 8
    ranges = chunk_ranges(total_combinations, cpu_count())

    found = {}

    with Pool(cpu_count()) as pool:
        for result in pool.imap_unordered(search_range, ranges):
            if result:
                found.update(result)

    return found

if __name__ == "__main__":
    start_time = time.perf_counter()
    found_passwords = brute_force_password()
    end_time = time.perf_counter()

    for password_hash, password in found_passwords.items():
        print(f"Found password: {password_hash[:8]}... -> {password}")

    print("Elapsed:", end_time - start_time)
