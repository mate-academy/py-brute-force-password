import multiprocessing
import time
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

TARGET_HASHES = set(PASSWORDS_TO_BRUTE_FORCE)
TARGET_COUNT = len(TARGET_HASHES)


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def find_passwords_worker(
        start: int,
        end: int,
        found_queue,
        found_counter,
        stop_event: multiprocessing.Event,
        check_interval: int = 10000,
) -> None:
    local_results = []

    for i in range(start, end):
        if i % check_interval == 0 and stop_event.is_set():
            break

        password = f"{i:08d}"
        sha_password = sha256_hash_str(password)

        if sha_password in TARGET_HASHES:
            local_results.append((sha_password, password))

            found_counter.value += 1
            if found_counter.value >= TARGET_COUNT:
                stop_event.set()

    if local_results:
        found_queue.put(local_results)


def brute_force_password() -> None:
    manager = multiprocessing.Manager()
    found_queue = multiprocessing.Queue()
    found_counter = manager.Value('i', 0)
    stop_event = multiprocessing.Event()
    found_dict = {}

    num_processes = multiprocessing.cpu_count()

    total_range = 100_000_000
    chunk_size = total_range // num_processes

    tasks = []

    for i in range(num_processes):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i < num_processes - 1 else total_range

        process = multiprocessing.Process(
            target=find_passwords_worker,
            args=(start, end, found_queue, found_counter, stop_event),
        )
        tasks.append(process)
        process.start()

    for task in tasks:
        task.join()

    while not found_queue.empty():
        results = found_queue.get()
        for sha_hash, password in results:
            if sha_hash not in found_dict:
                found_dict[sha_hash] = password

    found_count = len(found_dict)
    assert found_count == TARGET_COUNT, (
        f"Validation failed: Found {found_count}/{TARGET_COUNT} passwords"
    )

    print(f"\n=== Results ===")
    print(f"Found {found_count} out of {TARGET_COUNT} passwords:")
    for sha_hash in PASSWORDS_TO_BRUTE_FORCE:
        if sha_hash in found_dict:
            print(f"  {found_dict[sha_hash]}")
        else:
            print(f"  NOT FOUND: {sha_hash}")


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
