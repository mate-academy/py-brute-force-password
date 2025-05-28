import time
from hashlib import sha256
from multiprocessing import Process, Manager, cpu_count


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

TARGET_HASHES: set[str] = set(PASSWORDS_TO_BRUTE_FORCE)


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def worker(start: int,
           end: int,
           target_hashes: set[str],
           found_dict: dict[str, str]) -> None:
    buffer = bytearray(b"00000000")
    for current_number in range(start, end):
        number = current_number
        for position in range(7, -1, -1):
            buffer[position] = 48 + (number % 10)
            number //= 10
        hash_value = sha256(buffer).hexdigest()
        if hash_value in target_hashes and hash_value not in found_dict:
            found_dict[hash_value] = buffer.decode()


def brute_force_passwords() -> None:
    manager = Manager()
    found_passwords = manager.dict()
    process_count = cpu_count()
    total_combinations = 100_000_000
    block_size = total_combinations // process_count

    processes: list[Process] = []
    for index in range(process_count):
        start_range = index * block_size
        end_range = (index + 1) * block_size\
            if index < process_count - 1\
            else total_combinations
        process = Process(target=worker,
                          args=(start_range,
                                end_range,
                                TARGET_HASHES,
                                found_passwords))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    for hash_value, password in found_passwords.items():
        print(f"{hash_value} → {password}")

    if len(found_passwords) < len(TARGET_HASHES):
        missing_hashes = TARGET_HASHES - set(found_passwords.keys())
        print("Not found:", missing_hashes)


if __name__ == "__main__":
    print("Start")
    start_time = time.perf_counter()
    brute_force_passwords()
    end_time = time.perf_counter()
    print("Elapsed:", end_time - start_time)
