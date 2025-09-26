import multiprocessing
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from hashlib import sha256
from typing import Dict, List, Tuple, Set, Any

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

PASSWORD_SET = set(PASSWORDS_TO_BRUTE_FORCE)

PASSWORD_MAP: Dict[str, int] = {
    hash_val: index for index, hash_val in enumerate(PASSWORDS_TO_BRUTE_FORCE)
}

def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_password(start_range: int,
                         end_range: int,
                         stop_event: Any) -> List[Tuple[str, str, int]]:

    found_results: List[Tuple[str, str, int]] = []
    for i in range(start_range, end_range):

        if i % 10000 == 0 and stop_event.is_set():

            return found_results

        password_candidate = str(i).zfill(8)
        candidate_hash = sha256_hash_str(password_candidate)

        if candidate_hash in PASSWORD_SET:
            hash_index = PASSWORD_MAP[candidate_hash]
            found_results.append((password_candidate, candidate_hash, hash_index))

    return found_results
            # print(f"Password found: index: {hash_index}, {password_candidate}, hash: {candidate_hash}")



def main_multiprocess_executor() -> Set[str]:
    total_passwords = 10 ** 8
    num_processes = multiprocessing.cpu_count()
    chunk_size = total_passwords // num_processes

    found_passwords_by_id: Dict[int, str] = {}
    futures = []

    with multiprocessing.Manager() as manager:
        stop_event = manager.Event()
        with ProcessPoolExecutor(max_workers=num_processes) as executor:

            for i in range(num_processes):
                start = i * chunk_size

                end = (i + 1) * chunk_size if i < num_processes - 1 else total_passwords

                futures.append(executor.submit(brute_force_password, start, end, stop_event))

            for future in as_completed(futures):

                try:
                    results = future.result()

                    for password, candidate_hash, hash_index in results:
                        if hash_index not in found_passwords_by_id:
                            found_passwords_by_id[hash_index] = password

                            print(f"Password found: index: {hash_index}, {password}, hash: {candidate_hash}")

                    if len(found_passwords_by_id) == len(PASSWORD_SET):

                        print("ALL 10 PASSWORDS FOUND. Stop...")
                        stop_event.set()

                        for f in futures:
                            f.cancel()

                        break

                except Exception as e:
                    print(f"Task execution error: {e}", file=sys.stderr)

            return found_passwords_by_id


if __name__ == "__main__":
    start_time = time.perf_counter()
    # brute_force_password()
    main_multiprocess_executor()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
