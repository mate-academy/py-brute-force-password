from multiprocessing import Process, cpu_count, Pool as ProcessPool
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
CPU = cpu_count()


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def get_over(index, uncoded_password: str) -> None:
    for item in range(10**8):
        decoded_password = f"{item:08}"
        if sha256_hash_str(decoded_password) == uncoded_password:
            print(index, decoded_password)
            return


def brute_force_password_multiprocessing() -> None:
    tasks = []
    for index, uncoded_password in enumerate(
        iterable=PASSWORDS_TO_BRUTE_FORCE,
        start=1
    ):
        tasks.append(
            Process(
                target=get_over,
                args=(
                    index,
                    uncoded_password,
                )
            )
        )
        tasks[-1].start()

    for task in tasks:
        task.join()


def brute_force_password_synchronous() -> None:
    passwords = []
    for item in range(10**8):
        decoded_password = f"{item:08}"
        if sha256_hash_str(decoded_password) in PASSWORDS_TO_BRUTE_FORCE:
            passwords.append(decoded_password)
            print(len(passwords), decoded_password)
        if len(passwords) == len(PASSWORDS_TO_BRUTE_FORCE):
            break
    print(list(enumerate(passwords, start=1)))


brut_forced_passwords = []


def get_over_partially(start: int, end: int) -> None:
    for number in range(start, end + 1):
        if len(brut_forced_passwords) == len(PASSWORDS_TO_BRUTE_FORCE):
            break
        hashed_number = sha256_hash_str(f"{number:08d}")
        if hashed_number in PASSWORDS_TO_BRUTE_FORCE:
            print(f"brute forced password {hashed_number}: {number:08d}")
            brut_forced_passwords.append(f"{number:08d}")


def brute_force_password_stolen_chunk():
    tasks = []
    chunk_size = (10 ** 8) // CPU

    for i in range(CPU):
        tasks.append(Process(
            target=get_over_partially,
            args=(
                i * chunk_size,
                (i + 1) * chunk_size,
            )
        )
        )
        tasks[-1].start()

    for task in tasks:
        task.join()


def check_password(password: int) -> None:
    hashed_password = sha256_hash_str(str(password).zfill(8))
    if hashed_password in PASSWORDS_TO_BRUTE_FORCE:
        print(f"Found hash: {hashed_password} for password: {password}")


def brute_force_password_stolen_pool() -> None:
    with ProcessPool() as pool:
        pool.map(check_password, range(10 ** 8))


if __name__ == "__main__":
    print(f"{CPU=}")
    start_time = time.perf_counter()
    # brute_force_password_multiprocessing()
    # brute_force_password_synchronous()
    # brute_force_password_stolen_chunk()
    brute_force_password_stolen_pool()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
