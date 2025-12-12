import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, wait
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

TARGETS = set(PASSWORDS_TO_BRUTE_FORCE)


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_worker(start: int, end: int) -> dict[str, str]:
    found: dict[str, str] = {}
    for password in range(start, end):
        s = f"{password:08d}"
        h = sha256_hash_str(s)
        if h in TARGETS:
            found[h] = s
    return found


def brute_force_password() -> None:
    total = 100_000_000
    cpu = multiprocessing.cpu_count()
    workers = max(1, cpu - 1)
    step = total // workers

    futures = []
    found_all: dict[str, str] = {}

    with ProcessPoolExecutor(max_workers=workers) as ex:
        for i in range(workers):
            start = i * step
            end = total if i == workers - 1 else (i + 1) * step
            futures.append(ex.submit(brute_force_worker, start, end))

        done, _ = wait(futures)

        for fut in done:
            found_all.update(fut.result())

    for h in PASSWORDS_TO_BRUTE_FORCE:
        print(found_all[h])


if __name__ == "__main__":
    t0 = time.perf_counter()
    brute_force_password()
    print("Elapsed:", time.perf_counter() - t0)
