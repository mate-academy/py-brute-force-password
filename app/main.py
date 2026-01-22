import time
import os
from tqdm import tqdm
from hashlib import sha256
from concurrent.futures import ProcessPoolExecutor, as_completed

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


def sha256_hash_str(start: int, end: int, passwords: set) -> list:
    found = []
    for num in range(start, end):
        num = f"{num:08d}" # noqa
        num_hash = sha256(num.encode("utf-8")).hexdigest()
        if num_hash in passwords:
            found.append((num, num_hash))
    return found


def brute_force_password() -> None:
    all_founds = {}
    total = 100_000_000
    chunk_size = 10000

    cpus = os.cpu_count()

    print(f"STARTING ON {cpus} CPUS")

    with ProcessPoolExecutor(max_workers=cpus) as executor:
        futures = []
        for start in range(0, total, chunk_size):
            end = start + chunk_size
            futures.append(
                executor.submit(
                    sha256_hash_str,
                    start,
                    end,
                    PASSWORDS_TO_BRUTE_FORCE
                )
            )

        with tqdm(total=total, desc="Progress") as pbar:
            for future in as_completed(futures):
                results = future.result()
                if results:
                    for password, p_hash in results:
                        all_founds[p_hash] = password

                pbar.update(chunk_size)

                if len(all_founds) == len(PASSWORDS_TO_BRUTE_FORCE):
                    print("ALL FOUND")
                    for fut in futures:
                        fut.cancel()
                    break
        print(all_founds)


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
