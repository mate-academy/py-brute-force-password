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


def value_search_for(num1: str) -> None:
    set_number = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    for num2 in set_number:
        for num3 in set_number:
            for num4 in set_number:
                for num5 in set_number:
                    for num6 in set_number:
                        for num7 in set_number:
                            for num8 in set_number:
                                pass_word = num1 + num2 + num3 + num4 + num5 + num6 + num7 + num8
                                if sha256_hash_str(pass_word) in PASSWORDS_TO_BRUTE_FORCE:
                                    print("Password = ", pass_word)


def value_search(num1:str) -> None:
    for number in range(0, 10000000):
        if sha256_hash_str(num1 + format(number, "07d")) in PASSWORDS_TO_BRUTE_FORCE:
            print("Password = ", num1 + format(number, "07d"))


def value_search_recursion(num1: str, level_num: int) -> None:
    set_number = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    for num in set_number:
        number = num1 + num
        if level_num == 0:
            if sha256_hash_str(number) in PASSWORDS_TO_BRUTE_FORCE:
                print("Password = ", number)
        else:
            value_search_recursion(number, level_num - 1)


def brute_force_password() -> None:
    set_number = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
    tasks = []
    for num1 in set_number:
        # tasks.append(multiprocessing.Process(target=value_search_for, args=num1)) #83s
        # tasks.append(multiprocessing.Process(target=value_search, args=num1)) #93s
        tasks.append(multiprocessing.Process(target=value_search_recursion, args=(num1, 6))) #67s

        tasks[-1].start()

    for task in tasks:
        task.join()


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
