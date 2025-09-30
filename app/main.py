import time
from hashlib import sha256
from multiprocessing import Pool, Event, Manager, cpu_count

PASSWORD_LENGTH = 8
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
TARGET_HASHES = set(PASSWORDS_TO_BRUTE_FORCE)
TARGETS_LOCAL = None
STOP_EVENT = None
FOUND_PROXY = None


def init_worker(targets_tuple, stop_event: Event, found_proxy):
    global TARGETS_LOCAL, STOP_EVENT, FOUND_PROXY
    TARGETS_LOCAL = set(targets_tuple)
    STOP_EVENT = stop_event
    FOUND_PROXY = found_proxy


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_password() -> dict[str, str]:
    passwords = {}

    for guess in range(10**PASSWORD_LENGTH):
        guess_str = str(guess).zfill(PASSWORD_LENGTH)
        hashed_password = sha256_hash_str(guess_str)

        if hashed_password in TARGET_HASHES:
            passwords[hashed_password] = guess_str

            if len(passwords) == len(TARGET_HASHES):
                break

    return passwords


def slice_ranges(workers_count: int) -> list[tuple[int, int]]:
    if workers_count == 1:
        return [(0, 10 ** PASSWORD_LENGTH)]

    ranges = []
    size = 10 ** PASSWORD_LENGTH // workers_count

    for worker in range(workers_count):
        start = worker * size
        end = (worker + 1) * size if worker < workers_count - 1 else 10 ** PASSWORD_LENGTH
        ranges.append((start, end))

    return ranges


def check_range(cur_range: tuple[int, int]) -> dict[str, str]:
    targets = TARGETS_LOCAL
    stop = STOP_EVENT

    passwords = {}
    check_interval = 100000

    for i, guess in enumerate(range(cur_range[0], cur_range[1])):
        if i % check_interval == 0 and stop.is_set():
            break

        guess_str = str(guess).zfill(PASSWORD_LENGTH)
        hashed_password = sha256_hash_str(guess_str)

        if hashed_password in targets:
            passwords[hashed_password] = guess_str
            if len(passwords) >= len(targets):
                stop.set()
                break

    return passwords


def print_results(passwords: dict[str, str]) -> None:
    found_count = len(passwords)
    total = len(TARGET_HASHES)

    if found_count == total:
        print("All passwords were found")
    else:
        print(f"Only {found_count} of {total} were found")

    print("Passwords:")
    for password in PASSWORDS_TO_BRUTE_FORCE:
        plaintext = passwords.get(password)
        if plaintext is not None:
            print(f"{password}: {plaintext}")
        else:
            print(f"{password}: NOT FOUND")


if __name__ == "__main__":
    start_time = time.perf_counter()
    print("Brute force with 1 process started...")
    passwords = brute_force_password()
    end_time = time.perf_counter()
    print("1 process elapsed:", end_time - start_time)
    for password in PASSWORDS_TO_BRUTE_FORCE:
        print(f"{password}: {passwords.get(password, "NOT FOUND")}")

    start_time = time.perf_counter()
    workers = max(1, cpu_count() - 1)
    print(f"Brute force with {workers} processes started...")
    ranges = slice_ranges(workers)

    manager = Manager()
    found_proxy = manager.dict()
    stop_event = manager.Event()
    with Pool(
            workers,
            initializer=init_worker,
            initargs=(tuple(TARGET_HASHES), stop_event, found_proxy)
    ) as pool:
        results = pool.map(check_range, ranges)

    end_time = time.perf_counter()
    print(f"{workers} processes elapsed:", end_time - start_time)

    merged = {}
    for result in results:
        merged.update(result)
    print_results(merged)
