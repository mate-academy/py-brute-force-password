import time
from concurrent.futures import ProcessPoolExecutor, wait, as_completed

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


def formatto(number: int) -> str:
    return "{:08}".format(number)


block = int(100000000 / multiprocessing.cpu_count())
password_count = len(PASSWORDS_TO_BRUTE_FORCE)
password_count_current = multiprocessing.Value("i", 0)


def brute(start: int,
          end: int,
          password_count_current: multiprocessing.Value) -> None:

    for number in range(start, end):
        current_combo = formatto(number)
        current_combo_hashed = sha256_hash_str(current_combo)
        if current_combo_hashed in PASSWORDS_TO_BRUTE_FORCE:
            print(f"Password! {current_combo} with hash {current_combo_hashed}")
            with password_count_current.get_lock():
                password_count_current.value += 1
                print(password_count_current.value)
                if password_count_current.value == password_count:
                    break


def brute_force_password() -> None:

    tasks = []
    # my cpu count = 4
    for i in range(multiprocessing.cpu_count()):
        process = multiprocessing.Process(target=brute,
                                          args=(i * block, (i + 1) * block, password_count_current))
        tasks.append(process)
        process.start()

    for task in tasks:
        task.join()


def brute_pool_executor() -> None:
    futures = []

    with ProcessPoolExecutor(multiprocessing.cpu_count()) as executor:
        for i in range(10):
            futures.append(executor.submit(brute, i * block, (i + 1) * block, password_count_current))

    wait(futures)


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_pool_executor()
    end_time = time.perf_counter()
    print("Elapsed:", end_time - start_time)
