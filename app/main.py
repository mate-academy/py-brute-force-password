import itertools
import time
from hashlib import sha256
from multiprocessing import Pool, cpu_count

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


def brute_force_password(chunk: list[str]) -> None:
    for password in chunk:
        if sha256_hash_str(password) in PASSWORDS_TO_BRUTE_FORCE:
            print(
                f"Found password: {password} "
                f"for hash: {sha256_hash_str(password)}"
            )
            return


def chunked_combinations(start: int, end: int) -> list[str]:
    symbols_combinations = itertools.product("0123456789", repeat=8)
    return [
        "".join(x) for x in itertools.islice(symbols_combinations, start, end)
    ]


def create_chunks_list(chunk_size: int = 1000000) -> list:
    total_combinations = 10 ** 8
    chunks = [
        (
            i, min(i + chunk_size, total_combinations)
        ) for i in range(0, total_combinations, chunk_size)
    ]
    return chunks


def parallel_chunk_generation(chunk: tuple[int, int]) -> list[str]:
    start, end = chunk
    return chunked_combinations(start, end)


def main_chunked() -> list[list[str]]:
    chunks = create_chunks_list()
    with Pool(cpu_count() - 1) as pool:
        result = pool.map(parallel_chunk_generation, chunks)

    return result


def main() -> None:
    chunks = main_chunked()
    with Pool(cpu_count() - 1) as pool:
        pool.map(brute_force_password, chunks)


if __name__ == "__main__":
    start_time = time.perf_counter()
    main()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
