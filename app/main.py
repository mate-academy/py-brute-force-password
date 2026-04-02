import itertools
import multiprocessing
import string
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
PASSWORDS = set(PASSWORDS_TO_BRUTE_FORCE)
chars = string.digits
min_length = 1
max_length = 8

def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


# def brute_force_password() -> None:
#     chars = string.digits
#     i = 0
#     for length in range(9):
#         for candidate in itertools.product(chars, repeat=length):
#             password_str = "".join(candidate)
#             hashed_password = sha256_hash_str(password_str)
#             if hashed_password in PASSWORDS_TO_BRUTE_FORCE:
#                 print(f"Found password: {password_str}")
#                 i += 1
#                 if i == 10:
#                     return

def brute_force_password(args):
    start, end = args
    found = []
    for num in range(start, end):
        password_str = str(num).zfill(max_length)
        hashed_password = sha256_hash_str(password_str)
        if hashed_password in PASSWORDS:
            found.append(password_str)
    return found

def main():
    max_num = 10 ** max_length
    step = 100_000

    ranges = [
        (i, min(i + step, max_num))
        for i in range(0, max_num, step)
    ]

    found_total = []

    with multiprocessing.Pool() as p:
        for result in p.imap_unordered(brute_force_password, ranges, chunksize=10):
            if result:
                found_total.extend(result)
                for r in result:
                    print("Found password:", r)

            if len(found_total) >= len(PASSWORDS_TO_BRUTE_FORCE):
                p.terminate()
                break

if __name__ == "__main__":
    start_time = time.perf_counter()
    main()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
