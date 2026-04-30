import os
import time
from concurrent.futures import ProcessPoolExecutor
from hashlib import sha256

PASSWORDS_TO_BRUTE_FORCE = frozenset([
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
])

UPPER_BOUND = 100_000_001
CPU_COUNT = os.cpu_count() - 1

def brute_force_worker(start: int, finish: int) -> None:
    passwords_to_brute_force = PASSWORDS_TO_BRUTE_FORCE
    if start < 10_000_001:
        for i in range(start, finish):
            candidate = f"{i:08d}"
            hashed = sha256(candidate.encode()).hexdigest()

            if hashed in passwords_to_brute_force:
                print(f"Found: {candidate} - {hashed}")
    else:
        for i in range(start, finish):
            candidate = i
            hashed = sha256(str(candidate).encode()).hexdigest()

            if hashed in passwords_to_brute_force:
                print(f"Found: {candidate} - {hashed}")

def divide_search_range_into_chunks(
        search_range: int,
        divisor: int
) -> tuple:
    starts = []
    num = 0
    while num < search_range:
        one_seventh = int(search_range / divisor)
        starts.append(num)
        num += one_seventh
        if len(starts) == divisor:
            break
    finishes = [x for x in starts if x > 0]
    finishes.append(UPPER_BOUND)
    return starts, finishes

def main_multiprocessing_executor() -> None:
    starts, finishes = divide_search_range_into_chunks(UPPER_BOUND, 7)

    with ProcessPoolExecutor(max_workers=CPU_COUNT) as executor:
        list(executor.map(brute_force_worker, starts, finishes))

if __name__ == "__main__":
    start_time = time.perf_counter()
    main_multiprocessing_executor()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
