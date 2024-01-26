import multiprocessing
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
NUMBER_OF_PASSWORDS_TO_ITERATE = 100000000
NUMMER_OF_PROCESSES = 32  # number of chunks


class PasswordCracker:
    def __init__(self, passwords_hash_list, num_passwords_to_iterate,
                 num_processes):
        self.passwords_hash_list = passwords_hash_list
        self.passwords_hash_count = len(passwords_hash_list)
        self.num_passwords_to_iterate = num_passwords_to_iterate
        self.num_processes = num_processes

    def sha256_hash_str(self, to_hash: str) -> str:
        return sha256(to_hash.encode("utf-8")).hexdigest()

    def print_correct_password(self, start, end,
                               passwords_cracked, lock) -> None:
        with lock:
            if passwords_cracked.value >= self.passwords_hash_count:
                return

        for i in range(start, end):
            hash_pass = self.sha256_hash_str(f"{i:08}")
            if hash_pass in self.passwords_hash_list:
                print(f"Password found: {i:08}, hash: {hash_pass}")
                with lock:
                    passwords_cracked.value += 1
                    if passwords_cracked.value >= self.passwords_hash_count:
                        break

    def calculate_ranges(self, num_processes):
        chunk_size = max(self.num_passwords_to_iterate // num_processes, 1)
        remainder = self.num_passwords_to_iterate % num_processes
        start = 0
        ranges = []
        for i in range(num_processes):
            end = start + chunk_size + (1 if i < remainder else 0)
            ranges.append((start, end))
            start = end
        return ranges

    def brute_force_password(self) -> None:
        with multiprocessing.Manager() as manager:
            passwords_cracked = manager.Value("i", 0)
            lock = manager.Lock()

            with multiprocessing.Pool(
                processes=multiprocessing.cpu_count() - 1
            ) as pool:
                ranges = self.calculate_ranges(self.num_processes)
                pool.starmap(
                    self.print_correct_password,
                    [(start, end, passwords_cracked, lock)
                     for start, end in ranges]
                )


if __name__ == "__main__":
    start_time = time.perf_counter()
    password_cracker = PasswordCracker(
        PASSWORDS_TO_BRUTE_FORCE,
        NUMBER_OF_PASSWORDS_TO_ITERATE,
        NUMMER_OF_PROCESSES
    )
    password_cracker.brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
