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


def _worker_range(args: tuple) -> list:
    start, end, target_hashes = args
    local_sha256 = sha256
    targets = set(target_hashes)
    found = []
    for number in range(start, end):
        candidate = f"{number:08d}"
        digest = local_sha256(candidate.encode("utf-8")).hexdigest()
        if digest in targets:
            found.append((digest, candidate))
            targets.remove(digest)
            if not targets:
                break
    return found


def brute_force_password() -> None:
    target_hashes = tuple(PASSWORDS_TO_BRUTE_FORCE)
    target_set = set(target_hashes)
    total_targets = len(target_set)

    max_value = 100_000_000
    workers = max(1, cpu_count())
    chunk_size = 200_000

    ranges = []
    for i in range(0, max_value, chunk_size):
        start = i
        end = i + chunk_size
        if end > max_value:
            end = max_value
        ranges.append((start, end, target_hashes))

    found_map = {}
    start_time = time.perf_counter()

    print(
        f"Starting brute force with {workers} worker(s), "
        f"{len(ranges)} chunks, chunk_size={chunk_size}"
    )

    with Pool(processes=workers) as pool:
        try:
            for idx, result in (
                    enumerate(
                        pool.imap_unordered(_worker_range, ranges), 1
                    )
            ):
                if result:
                    for digest, plaintext in result:
                        if digest not in found_map:
                            found_map[digest] = plaintext
                            print(
                                f"FOUND: {plaintext} -> {digest} "
                                f"(found {len(found_map)}/{total_targets})"
                            )

                if len(found_map) >= total_targets:
                    pool.terminate()
                    break

                if idx % 10 == 0:
                    elapsed = time.perf_counter() - start_time
                    print(
                        f"Processed {idx} chunks, elapsed {elapsed:.1f}s, "
                        f"found {len(found_map)}/{total_targets}"
                    )
        except KeyboardInterrupt:
            print("Interrupted by user; shutting down pool.")
            pool.terminate()
        finally:
            pool.join()

    elapsed = time.perf_counter() - start_time
    print(f"\nFinished. Elapsed: {elapsed:.2f}s")
    print(f"Found {len(found_map)}/{total_targets} passwords:")
    for digest in PASSWORDS_TO_BRUTE_FORCE:
        print(found_map.get(digest, "NOT FOUND"), "->", digest)


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
