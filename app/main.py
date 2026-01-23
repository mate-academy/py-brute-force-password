import hashlib
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

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

MAX = 100_000_000
CHUNK_SIZE = 25_000_000


def check_chunk(start, end, stop_event):
    chunk_hashes = {}

    for i in range(start, end):
        if i % 100_000 == 0 and stop_event.is_set():
            break

        password = f"{i:08d}"
        hash = hashlib.sha256(password.encode()).hexdigest()

        if hash in PASSWORDS_TO_BRUTE_FORCE:
            chunk_hashes[hash] = password

    return chunk_hashes


def main():
    manager = multiprocessing.Manager()
    stop_event = manager.Event()

    hashes = {}

    with ProcessPoolExecutor() as executor:
        futures = []

        for start in range(0, MAX, CHUNK_SIZE):
            end = min(start + CHUNK_SIZE, MAX)
            futures.append(executor.submit(check_chunk, start, end, stop_event))

        for future in as_completed(futures):
            result = future.result()

            for hash, password in result.items():
                if hash not in hashes:
                    hashes[hash] = password
                    print(f"{hash}:{password}")

            if len(hashes) == len(PASSWORDS_TO_BRUTE_FORCE):
                stop_event.set()
                break

    return hashes


if __name__ == "__main__":
    t1 = time.time()
    passwords = main()
    t2 = time.time()

    print("\nPasswords:")
    for p in passwords.values():
        print(p)

    print("Time:", t2 - t1)


