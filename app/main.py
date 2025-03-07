import time
import itertools
from hashlib import sha256
from multiprocessing import Pool, cpu_count

PASSWORDS_TO_BRUTE_FORCE = {
    "b4061a4bcfe1a2cbf78286f3fab2fb578266d1bd16c414c650c5ac04dfc696e1": None,
    "cf0b0cfc90d8b4be14e00114827494ed5522e9aa1c7e6960515b58626cad0b44": None,
    "e34efeb4b9538a949655b788dcb517f4a82e997e9e95271ecd392ac073fe216d": None,
    "c15f56a2a392c950524f499093b78266427d21291b7d7f9d94a09b4e41d65628": None,
    "4cd1a028a60f85a1b94f918adb7fb528d7429111c52bb2aa2874ed054a5584dd": None,
    "40900aa1d900bee58178ae4a738c6952cb7b3467ce9fde0c3efa30a3bde1b5e2": None,
    "5e6bc66ee1d2af7eb3aad546e9c0f79ab4b4ffb04a1bc425a80e6a4b0f055c2e": None,
    "1273682fa19625ccedbe2de2817ba54dbb7894b7cefb08578826efad492f51c9": None,
    "7e8f0ada0a03cbee48a0883d549967647b3fca6efeb0a149242f19e4b68d53d6": None,
    "e5f3ff26aa8075ce7513552a9af1882b4fbc2a47a3525000f6eb887ab9622207": None,
}


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def check_password(password: str) -> tuple[str, str] | None:
    hashed = sha256_hash_str(password)
    if hashed in PASSWORDS_TO_BRUTE_FORCE:
        return hashed, password
    return None


def brute_force_password() -> None:
    with Pool(processes=cpu_count()) as pool:
        passwords = ("".join(p) for p
                     in itertools.product("0123456789", repeat=8))

        for result in pool.map(check_password, passwords, chunksize=5000):
            if result:
                hashed, password = result
                PASSWORDS_TO_BRUTE_FORCE[hashed] = password
                print(f"Found: {password} -> {hashed}")

                if all(value is not None for value
                       in PASSWORDS_TO_BRUTE_FORCE.values()):
                    pool.terminate()
                    break


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
    print("Recovered passwords:", PASSWORDS_TO_BRUTE_FORCE)
