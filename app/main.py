import time
from hashlib import sha256

import multiprocessing
import asyncio
import threading

from concurrent.futures import wait, ProcessPoolExecutor

from typing import Any, Callable


def timeit(func: Callable) -> Callable:
    if asyncio.iscoroutinefunction(func):
        async def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            print(f"Test for function {func.__name__}")
            result = await func(*args, **kwargs)
            end_time = time.time()
            print(f"Elapsed:{end_time - start_time}")
            return result
    else:
        def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            print(f"Test for function {func.__name__}")
            result = func(*args, **kwargs)
            end_time = time.time()
            print(f"Elapsed:{end_time - start_time}\n")
            return result
    return wrapper


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


def selection_of_passwords(data: list) -> None:
    for password in data:
        print(f"Brute forcing for {password}")
        for i in range(100000000):
            if sha256_hash_str(str(i)) == password:
                print(f"Password found: {i}")
                break


async def selection_of_passwords_async(data: list) -> None:
    for password in data:
        print(f"Brute forcing for {password}")
        for i in range(100000000):
            if sha256_hash_str(str(i)) == password:
                print(f"Password found: {i}")
                break


@timeit
def brute_force_password(data: list) -> None:
    selection_of_passwords(data)


@timeit
def brute_force_password_multiprocessing(data: list) -> None:
    tasks = []

    for password in data:
        tasks.append(
            multiprocessing.Process(
                target=selection_of_passwords,
                args=(
                    [
                        password,
                    ],
                ),
            )
        )
        tasks[-1].start()

    for task in tasks:
        task.join()


@timeit
def brute_force_password_pool_executor(data: list) -> None:
    futures = []
    with ProcessPoolExecutor() as executor:
        for password in data:
            futures.append(executor.submit(selection_of_passwords, [password]))

    wait(futures)


@timeit
def brute_force_password_threading(data: list) -> None:
    tasks = []

    for password in data:
        tasks.append(
            threading.Thread(
                target=selection_of_passwords,
                args=(
                    [
                        password,
                    ],
                ),
            )
        )
        tasks[-1].start()

    for task in tasks:
        task.join()


@timeit
async def brute_force_password_async(data: list) -> None:
    await selection_of_passwords_async(data)


if __name__ == "__main__":
    brute_force_password(PASSWORDS_TO_BRUTE_FORCE)
    brute_force_password_multiprocessing(PASSWORDS_TO_BRUTE_FORCE)
    brute_force_password_pool_executor(PASSWORDS_TO_BRUTE_FORCE)
    brute_force_password_threading(PASSWORDS_TO_BRUTE_FORCE)
    asyncio.run(brute_force_password_async(PASSWORDS_TO_BRUTE_FORCE))
