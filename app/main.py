import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256

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

RANGES = [
    (0, 10_000_000),
    (10_000_000, 20_000_000),
    (20_000_000, 30_000_000),
    (30_000_000, 40_000_000),
    (40_000_000, 50_000_000),
    (50_000_000, 60_000_000),
    (60_000_000, 70_000_000),
    (70_000_000, 80_000_000),
    (80_000_000, 90_000_000),
    (90_000_000, 100_000_000),
]

CHECK_INTERVAL = 10000

manager = None
stop_event = None


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def search_password(password_hash, r, stop_event):
    for i, num in enumerate(range(r[0], r[1])):

        if i % CHECK_INTERVAL == 0 and stop_event.is_set():
            return None

        num_str = f"{num:08d}"
        if sha256_hash_str(num_str) == password_hash:
            print(f"PASSWORD FOUND: {num_str} -> {password_hash}")
            stop_event.set()
            return num_str

    return None


def brute_force_password() -> None:
    with ProcessPoolExecutor(max(1, multiprocessing.cpu_count() - 2)) as executor:
        manager = multiprocessing.Manager()
        for password in PASSWORDS_TO_BRUTE_FORCE:
            stop_event = manager.Event()
            futures = []

            for r in RANGES:
                futures.append(
                    executor.submit(search_password, password, r, stop_event)
                )

            for future in as_completed(futures):
                result = future.result()
                if result:
                    for f in futures:
                        f.cancel()
                    break


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
