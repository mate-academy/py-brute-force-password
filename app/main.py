import time
from hashlib import sha256
from multiprocessing import cpu_count
from multiprocessing.pool import Pool

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

def _logic_function(args) -> dict:
    start, stop, targets = args
    target_set = set(targets)
    found = {}
    for num in range(start, stop):
        num = f"{num:08d}"
        hash_num = sha256_hash_str(num)
        if hash_num in target_set:
            found[hash_num] = num
            if len(found) == len(target_set):
                break
    return found


def brute_force_password() -> None:
    count_cores = cpu_count()
    to_check = 10**8
    amount_numbers_for_one_core = to_check // count_cores
    target_set = set(PASSWORDS_TO_BRUTE_FORCE)

    full_amount = []
    for i in range(count_cores):
        start = (i * amount_numbers_for_one_core)
        if i != count_cores - 1:
            stop = (i + 1) * amount_numbers_for_one_core
        else:
            stop = to_check
        full_amount.append((start, stop, target_set))

    results = {}
    with Pool(count_cores) as pool:
        for result in pool.imap_unordered(_logic_function, full_amount):
            results.update(result)

            if len(results) == len(target_set):
                break

    for element in target_set:
        print(f"Hash password:{element}, password = {results.get(element)}")


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
