
import time
import multiprocessing
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


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_password(password_to_check, queue_) -> None:
    password_to_check_finish = password_to_check[0] + "9" * 7
    count = 0
    while password_to_check != password_to_check_finish:
        count += 1
        count_pointer = len(str(count))
        pointer = len(password_to_check) - count_pointer
        first = password_to_check[:pointer]
        second = password_to_check[-count_pointer:]
        if sha256_hash_str(password_to_check) in PASSWORDS_TO_BRUTE_FORCE:
            print(password_to_check)
            queue_.put(password_to_check)
        password_to_check = first + str(int(second) + 1)


if __name__ == "__main__":
    passwords = [
        "00000000",
        "10000000",
        "20000000",
        "30000000",
        "40000000",
        "50000000",
        "60000000",
        "70000000",
        "80000000",
        "90000000",
    ]
    start_time = time.perf_counter()
    process_list = []
    queue = multiprocessing.Queue()
    for password in passwords:
        task = multiprocessing.Process(target=brute_force_password, args=(password, queue))
        process_list.append(task)
        task.start()
    PASSWORDS_TO_BRUTE_FORCE_LENGTH = len(PASSWORDS_TO_BRUTE_FORCE)
    while queue.qsize() != PASSWORDS_TO_BRUTE_FORCE_LENGTH:
        time.sleep(1)
    for process in process_list:
        if process.is_alive():
            process.kill()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
