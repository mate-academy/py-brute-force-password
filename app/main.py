from hashlib import sha256
from itertools import product
from string import digits
import time


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def find_test_passwords(
    target_hashes: set[str],
    length: int = 8,
) -> dict[str, str]:
    """Find passwords for locally generated test hashes."""
    found = {}

    for combination in product(digits, repeat=length):
        candidate = "".join(combination)
        candidate_hash = sha256_hash_str(candidate)

        if candidate_hash in target_hashes:
            found[candidate_hash] = candidate

            if len(found) == len(target_hashes):
                break

    return found


def main() -> None:
    # Local test data only.
    test_passwords = [
        "00000001",
        "00000002",
        "00000003",
        "00000004",
        "00000005",
        "00000006",
        "00000007",
        "00000008",
        "00000009",
        "00000010",
    ]
    target_hashes = {
        sha256_hash_str(password)
        for password in test_passwords
    }

    start_time = time.perf_counter()
    results = find_test_passwords(target_hashes)
    elapsed_time = time.perf_counter() - start_time

    print("Test passwords found:")
    for target_hash in target_hashes:
        print(results.get(target_hash, "Not found"))

    print("Elapsed:", round(elapsed_time, 4), "seconds")


if __name__ == "__main__":
    main()
