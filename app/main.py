import time
from concurrent.futures import ProcessPoolExecutor, wait, as_completed
from multiprocessing import cpu_count
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

def brute_force_partial(start_stop):
    start, stop = start_stop
    local_found = []
    hash_func = sha256
    for i in range(start, stop):
        password = f"{i:08d}"
        hashed_pass = hash_func(password.encode()).hexdigest()
        if hashed_pass in PASSWORDS_TO_BRUTE_FORCE:
            print(f"Found: {password}")
            local_found.append(password)
    return local_found


def brute_force_password():
    options = 100_000_000
    processes = max(1, cpu_count() - 1)
    step = options // processes

    process_range = []

    for i in range(processes):
        start = i * step
        stop = options if i == processes - 1 else (i + 1) * step
        process_range.append((start, stop))

    total_hacked = []

    with ProcessPoolExecutor(max_workers=processes) as executor:
        futures = [executor.submit(brute_force_partial, part) for part in process_range]

        for future in as_completed(futures):
            total_hacked.extend(future.result())

    return total_hacked


if __name__ == "__main__":
    start_time = time.perf_counter()

    final_results = brute_force_password()

    end_time = time.perf_counter()

    print("\n--- Summary ---")
    print(f"Total passwords found: {len(final_results)}")
    print(f"Passwords: {final_results}")
    print(f"Elapsed time: {end_time - start_time:.2f} seconds")
