import multiprocessing
import time
from hashlib import sha256
from queue import Empty

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


def worker(start: int,
           end: int,
           queue: multiprocessing.Queue,
           stop_event: multiprocessing.Event,
           passwords_set: set[str]
           ) -> None:
    local_passwords_set = passwords_set
    local_results = []
    for num in range(start, end):
        if num % 10000 == 0 and stop_event.is_set():
            break
        else:
            num_str = str(num).zfill(8)
            hashed = sha256_hash_str(num_str)
            if hashed in local_passwords_set:
                local_results.append(num_str)
    if local_results:
        queue.put(local_results)


def brute_force_password() -> None:
    passwords_set = set(PASSWORDS_TO_BRUTE_FORCE)
    total = 10 ** 8
    num_cpu = multiprocessing.cpu_count()
    base = total // num_cpu

    manager = multiprocessing.Manager()
    queue = multiprocessing.Queue()
    stop_event = manager.Event()
    set_found = set()

    processes = []
    for num in range(0, num_cpu):
        start = num * base
        end = start + base if num < num_cpu - 1 else total
        process = multiprocessing.Process(
            target=worker,
            args=(start, end, queue, stop_event, passwords_set)
        )
        process.start()
        processes.append(process)

    while len(set_found) < 10:
        try:
            items = queue.get(timeout=0.5)
        except Empty:
            if not any(p.is_alive() for p in processes):
                break
            else:
                continue
        for psw in items:
            set_found.add(psw)
            if len(set_found) >= 10:
                stop_event.set()
                break

    for process in processes:
        process.join()

    print(set_found)


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
