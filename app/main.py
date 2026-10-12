
import time
from hashlib import sha256
from itertools import product
from string import digits


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_force_password(target_hash: str, length: int = 4) -> str | None:
    """Find a numeric test password by checking generated candidates."""
    for combination in product(digits, repeat=length):
        candidate = "".join(combination)

        if sha256_hash_str(candidate) == target_hash:
            return candidate

    return None


def main() -> None:
    # Local test data only.
    test_password = "0427"
    target_hash = sha256_hash_str(test_password)

    start_time = time.perf_counter()
    result = brute_force_password(target_hash)
    elapsed_time = time.perf_counter() - start_time

    print("Test password found:", result)
    print("Elapsed:", round(elapsed_time, 4), "seconds")


if __name__ == "__main__":
    main()
