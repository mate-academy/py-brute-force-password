import time
from hashlib import sha256
import multiprocessing as mp

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


def brute_force_range(
        start: int, end: int, passwords: set, result_dict: dict
) -> None:
    for num in range(start, end):
        pwd = f"{num:08d}"
        hashed_pwd = sha256_hash_str(pwd)
        if hashed_pwd in passwords:
            result_dict[hashed_pwd] = pwd
            print(f"[FOUND] {pwd} → {hashed_pwd}")
            if len(result_dict) == len(passwords):
                break


def brute_force_password() -> None:
    manager = mp.Manager()
    result_dict = manager.dict()
    passwords = PASSWORDS_TO_BRUTE_FORCE
    total = 100_000_000
    cpu_cores = max(1, mp.cpu_count() - 1)
    chunk_size = total // cpu_cores
    print(f"Using {cpu_cores} cores, each processing {chunk_size} numbers.\n")
    with mp.Pool(cpu_cores) as pool:
        tasks = []
        for i in range(cpu_cores):
            start = i * chunk_size
            end = total if i == cpu_cores - 1 else (i + 1) * chunk_size
            tasks.append(pool.apply_async(
                brute_force_range, (start, end, passwords, result_dict)))
        for task in tasks:
            task.wait()
    print("\nAll passwords found:")
    for hashed_pwd, pwd in result_dict.items():
        print(f"{pwd} → {hashed_pwd}")
    print(f"\nTotal found: {len(result_dict)} / {len(passwords)}")


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
