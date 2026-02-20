import time
import multiprocessing
from concurrent.futures import (
    ProcessPoolExecutor,
)
from hashlib import sha256
from typing import Callable, Any
from multiprocessing import Manager


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
TARGET_HASHES = set(PASSWORDS_TO_BRUTE_FORCE)


STOP_EVENT = None
FOUND_MAP = None
LOCK = None

def init_worker(
        stop_event: Any, found_map: Any, lock: Any
) -> None:
    global STOP_EVENT, FOUND_MAP, LOCK
    STOP_EVENT = stop_event
    FOUND_MAP = found_map
    LOCK = lock


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def build_tasks(
        chunk_size: int,
        upper_bound: int = 10**8
) -> list[tuple[int, int]]:
    tasks: list[tuple[int, int]] = []
    start_value = 0
    while start_value < upper_bound:
        end_value = min(start_value + chunk_size, upper_bound)
        tasks.append((start_value, end_value))
        start_value = end_value
    return tasks


def brute_force_password(
        start: int, end: int
) -> list[str]:
    local_found: list[str] = []

    for number in range(start, end):
        if (
                STOP_EVENT is not None
                and (number & 1023) == 0
                and STOP_EVENT.is_set()
        ):
            break

        candidate = f"{number:08d}"
        digest = sha256_hash_str(candidate)

        if digest in TARGET_HASHES:
            local_found.append(candidate)

            if FOUND_MAP is not None:
                with LOCK:
                    FOUND_MAP[digest] = candidate
                    if len(FOUND_MAP) >= len(TARGET_HASHES):
                        STOP_EVENT.set()

    return local_found


def run_with_executor(
        tasks: list[tuple[int, int]],
        workers: int,
) -> list[list[str]]:
    with Manager() as manager:
        stop_event = manager.Event()
        found_map = manager.dict()
        lock = manager.Lock()

        with ProcessPoolExecutor(
                max_workers=workers,
                initializer=init_worker,
                initargs=(stop_event, found_map, lock),
        ) as executor:
            futures = [
                executor.submit(brute_force_password, start, end)
                for start, end in tasks
            ]
            return [f.result() for f in futures]


def run_with_pool(
        tasks: list[tuple[int, int]],
        workers: int,
        chunksize: int = 1
) -> list[list[str]]:
    with Manager() as manager:
        stop_event = manager.Event()
        found_map = manager.dict()
        lock = manager.Lock()

        with multiprocessing.Pool(
                processes=workers,
                initializer=init_worker,
                initargs=(stop_event, found_map, lock),
        ) as pool:
            return pool.starmap(
                brute_force_password, tasks, chunksize=chunksize
            )


def flatten(nested: list[list[str]]) -> list[str]:
    return [item for chunk in nested for item in chunk]


def benchmark(
        label: str, func: Callable, *args, **kwargs
) -> tuple[str, float, list[str]]:
    t0 = time.perf_counter()
    nested = func(*args, **kwargs)
    elapsed = time.perf_counter() - t0
    flat = flatten(nested)
    flat.sort()
    return label, elapsed, flat


def print_comparison(
        rows: list[tuple[str, float, list[str]]]
) -> None:
    print("\nComparison:")

    method_header = "Method"
    time_header = "Time (s)"
    found_header = "Found"

    print(f"{method_header:<22} | {time_header:>10} | {found_header:>5}")
    print("-" * 44)
    for name, sec, found in rows:
        print(f"{name:<22} | {sec:>10.3f} | {len(found):>5}")

    if len(rows) >= 2:
        same = rows[0][2] == rows[1][2]
        print("\nSame results:", same)


def best_chunk(
        results: list[tuple[int, float]]
) -> tuple[int, float]:
    return min(results, key=lambda x: x[1])


if __name__ == "__main__":
    chunk_sizes = [10_000, 50_000, 100_000, 500_000, 1_000_000, 5_000_000]

    pool_executor_list = []
    pool_list = []

    executor_name = "ProcessPoolExecutor"
    pool_name = "multiprocessing.Pool"

    workers = max(1, multiprocessing.cpu_count() - 1)

    for chunk_size in chunk_sizes:
        chunk_size_str = (
                ("=" * 55) +
                "CHUNK_SIZE = " +
                str(chunk_size) +
                ("=" * 55)
        )
        chunk_size_str_len = len(chunk_size_str)
        print(chunk_size_str, end="")

        tasks = build_tasks(chunk_size=chunk_size)

        rows: list[tuple[str, float, list[str]]] = []

        rows.append(
            benchmark(
                executor_name,
                run_with_executor, tasks, workers
            )
        )

        rows.append(
            benchmark(
                pool_name,
                run_with_pool, tasks, workers, 1
            )
        )

        unique_found_executor = sorted(set(rows[0][2]))
        unique_found_pool = sorted(set(rows[1][2]))
        expected_count = len(TARGET_HASHES)

        if len(unique_found_executor) != expected_count:
            raise RuntimeError(
                f"Executor: expected {expected_count} passwords, "
                f"but found {len(unique_found_executor)}."
            )

        if len(unique_found_pool) != expected_count:
            raise RuntimeError(
                f"Pool: expected {expected_count} passwords, "
                f"but found {len(unique_found_pool)}."
            )

        rows[0] = (rows[0][0], rows[0][1], unique_found_executor)
        rows[1] = (rows[1][0], rows[1][1], unique_found_pool)

        print("\nFound passwords:")
        for value in rows[0][2]:
            print(value)

        print_comparison(rows)

        pool_executor_list.append((chunk_size, rows[0][1]))
        pool_list.append((chunk_size, rows[1][1]))

        print("=" * chunk_size_str_len, end="\n\n\n\n")

    best_executor_chunk, best_executor_time = best_chunk(pool_executor_list)
    best_pool_chunk, best_pool_time = best_chunk(pool_list)

    print("\nBest chunk size")

    method = "Method"
    chunk = "chunk_size"
    time = "Time (s)"

    print(f"{method:<22} | {chunk:>10} | {time:>10}")
    print("-" * 50)

    print(
        f"{executor_name:<22} | "
        f"{best_executor_chunk:>10} | "
        f"{best_executor_time:>10.3f}"
    )
    print(
        f"{pool_name:<22} | "
        f"{best_pool_chunk:>10} | "
        f"{best_pool_time:>10.3f}"
    )
