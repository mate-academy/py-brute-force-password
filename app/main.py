import itertools
import multiprocessing
import time
from concurrent.futures import as_completed
from concurrent.futures.process import ProcessPoolExecutor
from hashlib import sha256


PASSWORDS_TO_BRUTE_FORCE = {
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
}


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_password(password_length: int, start: int, end: int) -> list[tuple]:
    found_password = []
    for i in range(start, end):
        current_password = str(i).zfill(password_length)
        hashed_current_pass = sha256_hash_str(current_password)

        if hashed_current_pass in PASSWORDS_TO_BRUTE_FORCE:
            found_password.append((hashed_current_pass, current_password))
    return found_password


if __name__ == "__main__":
    password_length = 8
    total_combination = 10 ** password_length
    found_password = {}
    print("Start brute forcing...")
    start_time = time.perf_counter()
    num_of_cores = input("Enter count of CPU for using: ")
    try:
        num_of_cores = int(num_of_cores) if num_of_cores else multiprocessing.cpu_count()
        if num_of_cores <= 0:
            raise ValueError("Invalid CPU core count. It must be positive")
    except ValueError:
        print("Invalid enter. Use all CPU core")
        num_of_cores = multiprocessing.cpu_count()


    part_size = total_combination // int(num_of_cores)
    parts = []
    for i in range(num_of_cores):
        start_num = i * part_size
        end_num = (i + 1) * part_size
        if i == num_of_cores - 1:
            end_num = total_combination
        parts.append((password_length, start_num, end_num))

    with ProcessPoolExecutor(max_workers=num_of_cores) as executor:
        futures = [executor.submit(brute_force_password, *p_args) for p_args in parts]

        for future in as_completed(futures):
            found_in_parts = future.result()
            for hashed_pwd, plain_pwd in found_in_parts:
                if hashed_pwd in PASSWORDS_TO_BRUTE_FORCE and hashed_pwd not in found_password:
                    found_password[hashed_pwd] = plain_pwd
                    print(f"Password found: {plain_pwd}, hash: {hashed_pwd}")

            if len(found_password) == len(PASSWORDS_TO_BRUTE_FORCE):
                print("We`ve done")
                for f in futures:
                    f.cancel()
                break

    end_time = time.perf_counter()
    print("End of brute force.")

    print("Elapsed:", end_time - start_time)
