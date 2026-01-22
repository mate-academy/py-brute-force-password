import asyncio
import time
from hashlib import sha256
from concurrent.futures import ProcessPoolExecutor

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

HASHES_SET = set(PASSWORDS_TO_BRUTE_FORCE)


def check_range(start: int, end: int) -> list:
    results = []
    for i in range(start, end):
        candidate = f"{i:08d}"  # noqa: E231
        password_hash = sha256(candidate.encode()).hexdigest()
        if password_hash in HASHES_SET:
            results.append((password_hash, candidate))
    return results


async def brute_force_password() -> None:
    loop = asyncio.get_running_loop()
    total_combinations = 100_000_000
    num_workers = 4
    step = total_combinations // num_workers

    found_passwords = {}

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        tasks = []
        for i in range(num_workers):
            start = i * step
            is_last = i == num_workers - 1
            end = total_combinations if is_last else (i + 1) * step
            tasks.append(
                loop.run_in_executor(executor, check_range, start, end)
            )

        for completed_task in await asyncio.gather(*tasks):
            for password_hash, pwd in completed_task:
                found_passwords[password_hash] = pwd

    for password_hash in PASSWORDS_TO_BRUTE_FORCE:
        print(f"{password_hash}: {found_passwords.get(password_hash)}")


if __name__ == "__main__":
    start_ts = time.perf_counter()
    asyncio.run(brute_force_password())
    end_ts = time.perf_counter()
    print(f"Elapsed: {end_ts - start_ts:.2f} seconds")  # noqa: E231
