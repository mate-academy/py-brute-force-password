import time
import hashlib
import multiprocessing as mp


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

TARGET_SET = set(PASSWORDS_TO_BRUTE_FORCE)


def sha256_hash_str(to_hash: str) -> str:
    return hashlib.sha256(to_hash.encode("utf-8")).hexdigest()


def worker(bounds: tuple[int, int]) -> dict[str, str]:
    """Scan a numeric range [start, end) and return any matching hashes."""
    start, end = bounds
    sha256 = hashlib.sha256
    found = {}
    for i in range(start, end):
        s = "%08d" % i
        h = sha256(s.encode("utf-8")).hexdigest()
        if h in TARGET_SET:
            found[h] = s
    return found


def brute_force_password() -> None:
    start = time.time()
    total = 100_000_000
    n_workers = mp.cpu_count()
    chunk = total // n_workers + 1
    ranges = [(i, min(i + chunk, total)) for i in range(0, total, chunk)]

    print(f"Using {n_workers} worker process(es), chunk size {chunk}")

    results = {}
    with mp.Pool(n_workers) as pool:
        for found in pool.imap_unordered(worker, ranges):
            results.update(found)
            for h, s in found.items():
                print(f"FOUND {h} -> {s}  ({len(results)}/{len(TARGET_SET)})  t={time.time() - start:.1f}s")
            if len(results) == len(TARGET_SET):
                pool.terminate()
                break

    print("\n--- Results in original order ---")
    for h in PASSWORDS_TO_BRUTE_FORCE:
        print(h, "->", results.get(h))

    print(f"\nDone in {time.time() - start:.1f}s")


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
