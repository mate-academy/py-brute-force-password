import time
from hashlib import sha256
import multiprocessing
from typing import Optional, List

# общий диапазон (по умолчанию полный 8-значный: 0..99_999_999)
MAX_VALUE = 100_000_000

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


def multiprocces_brute_force(password: str) -> Optional[str]:
    """
    Сканирует диапазон [0, MAX_VALUE) и возвращает первое найденное
    8-символьное строковое представление числа (zfilled) при совпадении хеша.
    Если не найдено — возвращает None.
    """
    for i in range(MAX_VALUE):
        candidate = str(i).zfill(8)  # сохраняем ведущие нули
        if sha256_hash_str(candidate) == password:
            # возвращаем строку с ведущими нулями, не печатаем число без нулей
            return candidate
    return None


def brute_force_passwords() -> None:
    start_time = time.perf_counter()


    with multiprocessing.Pool() as pool:
        results: List[Optional[str]] = pool.map(multiprocces_brute_force, PASSWORDS_TO_BRUTE_FORCE)

    # фильтрация None
    found_passwords = [r for r in results if r is not None]

    end_time = time.perf_counter()
    elapsed = end_time - start_time

    # проверяем требование: ровно 10 паролей
    if len(found_passwords) == len(PASSWORDS_TO_BRUTE_FORCE):
        print(f"Found all {len(found_passwords)} passwords (each exactly 8 chars):")
        for pw in found_passwords:
            print(pw)  # все уже в виде "00001234"
    else:
        print("Warning: did not find all passwords.")
        print(f"Expected {len(PASSWORDS_TO_BRUTE_FORCE)} matches, got {len(found_passwords)}.")
        print("Found (possibly partial):", found_passwords)
        # полезная диагностика: показываем raw results (None or value) aligned with input list
        for idx, (target_hash, res) in enumerate(zip(PASSWORDS_TO_BRUTE_FORCE, results)):
            status = res if res is not None else "<NOT FOUND>"
            print(f"{idx+1:02d}: {target_hash[:8]}... -> {status}")

    print("Elapsed:", elapsed)


if __name__ == "__main__":
    brute_force_passwords()
