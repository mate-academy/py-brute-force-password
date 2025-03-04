import asyncio
import hashlib
import time


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


async def brute_force_one_password(password_hash: str, start: int, end: int) -> str:

    for candidate in range(start, end):
        candidate_password = f"{candidate:08d}"
        if hashlib.sha256(candidate_password.encode("utf-8")).hexdigest() == password_hash:
            print(f"Пароль знайдено: {candidate_password} для хешу {password_hash}")
            return candidate_password

    return None


async def crack_one_password(password_hash: str) -> str:
    step = 500_000
    tasks = []

    for start in range(0, 100_000_000, step):
        tasks.append(brute_force_one_password(password_hash, start, start + step))

    results = await asyncio.gather(*tasks)

    for result in results:
        if result is not None:
            return result
    return None


async def main():

    start_time = time.time()

    tasks = [crack_one_password(password_hash) for password_hash in PASSWORDS_TO_BRUTE_FORCE]
    results = await asyncio.gather(*tasks)

    end_time = time.time()

    print("\nЗнайдені паролі:", results)
    print(f"Час виконання: {end_time - start_time:.2f} секунд")


if __name__ == "__main__":
    asyncio.run(main())
