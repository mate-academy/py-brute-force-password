import time
from hashlib import sha256
from multiprocessing import Pool, cpu_count, Manager
from concurrent.futures import ProcessPoolExecutor, wait

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


def threads_find_password(start, end):
    for num in range(start, end):

        check_password = "{:08d}".format(num)
        if sha256_hash_str(check_password) in PASSWORDS_TO_BRUTE_FORCE:
            print(check_password)



def divide_into_parts(n, num_parts):
    """ Разбивает число n на num_parts частей и возвращает генератор кортежей с началом и концом каждого диапазона. """
    part_size = n // num_parts  # вычисляем размер каждой части
    remainder = n % num_parts  # вычисляем остаток
    start = 0
    for i in range(num_parts):
        if i < remainder:
            end = start + part_size + 1  # добавляем единицу к размеру диапазона
        else:
            end = start + part_size
        yield start, end
        start = end


def brute_force_password() -> None:
    futures = []
    cpus = cpu_count() * 2 - 1
    with ProcessPoolExecutor(cpus) as executor:
        for part in divide_into_parts(1_000_000_00, cpus):
            futures.append(executor.submit(threads_find_password, *part))

    wait(futures)


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
