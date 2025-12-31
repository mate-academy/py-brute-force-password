import time
from hashlib import sha256
import multiprocessing

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


def brute_force_worker(chunk_start: int,
                       chunk_size: int,
                       target_hashes: set,
                       result_queue: multiprocessing.Queue,
                       ) -> None:
    end = chunk_start + chunk_size
    for num in range(chunk_start, end):
        password = f"{num:08d}"
        hashed = sha256_hash_str(password)

        if hashed in target_hashes:
            result_queue.put((password, hashed))


def brute_force_password() -> dict[str, str]:
    total_combinations = 100_000_000
    num_processes = max(1, multiprocessing.cpu_count() - 1)
    chunk_size = total_combinations // num_processes
    extra = total_combinations % num_processes

    manager = multiprocessing.Manager()
    result_queue = manager.Queue()

    target_hashes_set = set(PASSWORDS_TO_BRUTE_FORCE)

    start = 0
    processes = []

    for i in range(num_processes):
        current_chunk = chunk_size + (1 if i < extra else 0)
        task = multiprocessing.Process(
            target=brute_force_worker,
            args=(start, current_chunk,
                  target_hashes_set, result_queue),
        )
        processes.append(task)
        task.start()
        start += current_chunk

    found_results = {}
    while len(found_results) < len(PASSWORDS_TO_BRUTE_FORCE):
        if not result_queue.empty():
            password, hashed = result_queue.get()
            if hashed not in found_results:
                found_results[hashed] = password
                print(f"Found {password}: {hashed}")

        if all(not task.is_alive() for task in processes) and result_queue.empty():
            break

        time.sleep(0.01)

    for task in processes:
        task.join()

    return found_results


if __name__ == "__main__":
    start_time = time.perf_counter()
    results = brute_force_password()
    end_time = time.perf_counter()

    print("\n" + "=" * 50)
    print("Results:")
    print("=" * 50)
    if results:
        for password, hashed in results.items():
            print(f"{password} → {hashed}")
        print(f"Found: {len(results)} passwords")
    else:
        print("Passwords not found in range 00000000–99999999")

    print("Elapsed:", end_time - start_time)
