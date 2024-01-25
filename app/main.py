import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor, wait
from hashlib import sha256


PASSWORDS_TO_BRUTE_FORCE = [
    "995d8f46286034e25c0f54e7863c925f8c16033ad03d5747b97b96ad64b1f2ad",
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

SMALL_PASSWORDS = [
    "7e071fd9b023ed8f18458a73613a0834f6220bd5cc50357ba3493c6040a9ea8c",
    "1a9a759bef36c387c0ad387ab6426fc3ef3666b17c3b99e88b308314e8dc38ea",
    "b7534c85310d02e647851a6255c6dbe7ac63532253839a6fbc0396afa4f2e1d3",
    "a1d6e6abe42eccbf560a8ce9390396dd9f6581176ad47428e28fe7dfc6d20973",
    "cce448a6aca8dc39b63f2fb3e63d2a7fae58c8005b1842c3444b24481674f612",
    "630b0cb3726eb729a2fb5740378c4de925df7a007eaf23ef0ca830e7de625a0e"
]

PASSWORDS_TO_CRACK = PASSWORDS_TO_BRUTE_FORCE

N_PASS = 100000000


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def print_correct_password(start, end) -> None:
    # print("Starting process...")
    for i in range(start, end):
        hash_pass = sha256_hash_str(f"{i:08}")
        if hash_pass in PASSWORDS_TO_CRACK:
            print("Password found:", f"{i:08}", hash_pass)


def brute_force_password() -> None:
    num_processes = 6
    chunk_size = N_PASS // num_processes
    remainder = N_PASS % num_processes
    start = 0

    futures = []
    with ProcessPoolExecutor(multiprocessing.cpu_count() - 1) as executor:
        for i in range(num_processes):
            end = start + chunk_size + (1 if i < remainder else 0)
            futures.append(executor.submit(
                print_correct_password, start, end
            ))
            start = end

    wait(futures)


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
