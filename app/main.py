import asyncio
import hashlib
import multiprocessing
import time
from hashlib import sha256
import threading
from multiprocessing import cpu_count, Process, Pipe, Event, Queue
from multiprocessing.connection import wait
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


# def brute_force_password(passwords: list) -> list:
#     count = 0
#     length = len(passwords)
#     passwords = set(passwords)
#     for num in range(100000000):
#         check_pwd = str(num).zfill(8)
#         decoded_password = sha256_hash_str(check_pwd)
#         if decoded_password in passwords:
#             print(check_pwd)
#             count += 1
#             if count == length:
#                 break


# def worker(start, end, target_hashes, found, lock, stop_event):
#     for num in range(start, end):
#         if stop_event.is_set():
#             return
#
#         pwd = str(num).zfill(8)
#         hashed_pwd = sha256(pwd.encode()).hexdigest()
#
#         if hashed_pwd in target_hashes:
#             with lock:
#                 if hashed_pwd not in found:
#                     found[hashed_pwd] = pwd
#                     print({pwd})
#
#                     if len(found) == len(target_hashes):
#                         stop_event.set()
#                         return
#
#
# def brute_force_threading(passwords, num_threads=4):
#     target_hashes = set(passwords)
#     found = {}
#
#     lock = threading.Lock()
#     stop_event = threading.Event()
#
#     threads = []
#     total = 100_000_000
#     chunk = total // num_threads
#
#     for i in range(num_threads):
#         start = i * chunk
#         end = (i + 1) * chunk if i != num_threads - 1 else total
#
#         t = threading.Thread(
#             target=worker,
#             args=(start, end, target_hashes, found, lock, stop_event)
#         )
#         threads.append(t)
#         t.start()
#
#     for t in threads:
#         t.join()
#
#     return list(found.values())



def worker(start, end, target_hashes, queue, stop_event):
    local_found = []
    for num in range(start, end):
        # Перевірка stop_event на кожній ітерації
        if stop_event.is_set():
            break

        pwd = str(num).zfill(8)
        h = sha256_hash_str(pwd)

        if h in target_hashes:
            print(f"[FOUND] {pwd}")
            local_found.append(pwd)

    # Відправляємо тільки якщо щось знайшли
    if local_found:
        queue.put(local_found)

def brute_force_multiprocessing(passwords):
    target_hashes = set(passwords)
    total = 100_000_000
    num_proc = cpu_count()
    chunk = total // num_proc

    stop_event = Event()
    queue = Queue()
    processes = []

    # Запуск процесів
    for i in range(num_proc):
        start = i * chunk
        end = (i + 1) * chunk if i != num_proc - 1 else total
        p = Process(target=worker, args=(start, end, target_hashes, queue, stop_event))
        processes.append(p)
        p.start()

    found = set()

    # Основний цикл
    while len(found) < len(target_hashes):
        try:
            result = queue.get(timeout=0.5)
            found.update(result)  # дедуплікація через set
            if len(found) >= len(target_hashes):
                stop_event.set()
                break
        except Empty:
            # Якщо всі процеси завершились і черга порожня — вихід
            if not any(p.is_alive() for p in processes):
                break
            continue

    # Завершення процесів
    for p in processes:
        p.join(timeout=1)
        if p.is_alive():
            p.terminate()

    return list(found)

# async def worker(start, end, target_hashes, found, stop_event):
#     for num in range(start, end):
#
#         if stop_event.is_set():
#             return
#
#         pwd = str(num).zfill(8)
#         h = hashlib.sha256(pwd.encode()).hexdigest()
#
#         if h in target_hashes:
#             print(f"[FOUND] {pwd}")
#             found.add(pwd)
#
#             if len(found) == len(target_hashes):
#                 stop_event.set()
#                 return
#
#         if num % 1000 == 0:
#             await asyncio.sleep(0)
#
#
# async def brute_force_async(passwords):
#     target_hashes = set(passwords)
#
#     total = 100_000_000
#     num_tasks = 8
#     chunk = total // num_tasks
#
#     found = set()
#     stop_event = asyncio.Event()
#
#     tasks = []
#
#     for i in range(num_tasks):
#         start = i * chunk
#         end = (i + 1) * chunk if i != num_tasks - 1 else total
#
#         tasks.append(
#             asyncio.create_task(
#                 worker(start, end, target_hashes, found, stop_event)
#             )
#         )
#
#     await asyncio.gather(*tasks)
#
#     return list(found)

if __name__ == "__main__":

    start_time = time.perf_counter()
    result = brute_force_multiprocessing(PASSWORDS_TO_BRUTE_FORCE)
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
