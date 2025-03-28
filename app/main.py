import hashlib
import multiprocessing
from itertools import product
import time


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

HASH_SET = set(PASSWORDS_TO_BRUTE_FORCE)


def sha256_hash_str(to_hash: str) -> str:
    return hashlib.sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_passwords(start: int, end: int, result_dict):
    for num in range(start, end):
        password = f"{num:08d}"
        hashed_password = sha256_hash_str(password)

        if hashed_password in HASH_SET:
            result_dict[hashed_password] = password


def main():
    start_time = time.time()

    total_passwords = 10**8
    num_processes = multiprocessing.cpu_count()
    chunk_size = total_passwords // num_processes

    manager = multiprocessing.Manager()
    result_dict = manager.dict()

    processes = []
    for i in range(num_processes):
        start = i * chunk_size
        end = start + chunk_size
        if i == num_processes - 1:
            end = total_passwords
        process = multiprocessing.Process(target=brute_force_passwords, args=(start, end, result_dict))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()

    print("\nУсі знайдені паролі:")
    for hash_value, password in result_dict.items():
        print(f"Хеш: {hash_value}, Пароль: {password}")

    end_time = time.time()
    print(f"\nЧас виконання: {end_time - start_time:.2f} секунд")


if __name__ == "__main__":
    main()
