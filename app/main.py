import time
import hashlib
import multiprocessing
import concurrent.futures as cf
from concurrent.futures import ProcessPoolExecutor, as_completed, Future
from typing import MutableMapping, Tuple, List

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
TARGET_HASHES = frozenset(PASSWORDS_TO_BRUTE_FORCE)

TOTAL = 10 ** 8
CHUNK_SIZE = 1_000_000

DEBUG = False


def sha256_hash_str(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def worker_range(
    range_start: int,
    range_end: int,
    target_hashes: frozenset,
    found_proxy: MutableMapping[str, str],
    lock,
    stop_event,
) -> int:
    found_here = 0
    for i in range(range_start, range_end):
        if stop_event.is_set():
            break
        pwd = f"{i:08d}"
        h = sha256_hash_str(pwd)
        if h in target_hashes:
            with lock:
                if h not in found_proxy:
                    found_proxy[h] = pwd
                    found_here += 1
                    if len(found_proxy) >= len(target_hashes):
                        stop_event.set()
                        break
    return found_here


def make_ranges(total: int, chunk_size: int) -> List[Tuple[int, int]]:
    result: List[Tuple[int, int]] = []
    for start in range(0, total, chunk_size):
        end = min(start + chunk_size, total)
        result.append((start, end))
    return result


def main() -> None:
    start_time = time.time()

    manager = multiprocessing.Manager()
    found_passwords: MutableMapping[str, str] = manager.dict()
    lock = manager.Lock()
    stop_event = manager.Event()

    ranges = make_ranges(TOTAL, CHUNK_SIZE)

    workers = multiprocessing.cpu_count() or 1

    with ProcessPoolExecutor(max_workers=workers) as executor:
        pending: List[Future] = []
        range_iter = iter(ranges)

        for _ in range(workers):
            try:
                range_start, range_end = next(range_iter)
            except StopIteration:
                break
            fut = executor.submit(
                worker_range,
                range_start,
                range_end,
                TARGET_HASHES,
                found_passwords,
                lock,
                stop_event,
            )
            pending.append(fut)

        try:
            while pending:
                done_iter = as_completed(pending)
                done_future = next(done_iter)
                pending.remove(done_future)
                _ = done_future.result()
                if stop_event.is_set():
                    break
                try:
                    range_start, range_end = next(range_iter)
                except StopIteration:
                    continue
                fut = executor.submit(
                    worker_range,
                    range_start,
                    range_end,
                    TARGET_HASHES,
                    found_passwords,
                    lock,
                    stop_event,
                )
                pending.append(fut)

            if stop_event.is_set():
                for fut in pending:
                    fut.cancel()
                for fut in pending:
                    try:
                        fut.result(timeout=5)
                    except cf.TimeoutError:
                        pass
            else:
                for fut in pending:
                    fut.result()
        except KeyboardInterrupt:
            stop_event.set()
            raise

    end_time = time.time()
    elapsed = end_time - start_time

    found_count = len(found_passwords)
    if found_count != len(TARGET_HASHES):
        if DEBUG:
            print(f"Elapsed: {elapsed:.2f}s")
            print(f"Found {found_count} of {len(TARGET_HASHES)} targets")
        raise SystemExit(1)

    plaintexts = sorted(found_passwords.values(), key=lambda s: int(s))
    for pwd in plaintexts:
        print(pwd)

    if DEBUG:
        print("\nDiagnostics:")
        print("Total execution time:", elapsed)
        print("Found mapping (hash -> pwd):")
        for h in sorted(found_passwords.keys()):
            print(f"{h} -> {found_passwords[h]}")


if __name__ == "__main__":
    main()
