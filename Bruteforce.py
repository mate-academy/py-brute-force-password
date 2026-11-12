import hashlib
from multiprocessing import Pool, cpu_count


def sha256_hash_str(to_hash: str) -> str:
    return hashlib.sha256(to_hash.encode("utf-8")).hexdigest()


TARGET_HASHES = {
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
}


def check_range(args):
    start, end = args
    found = {}
    for n in range(start, end):
        candidate = f"{n:08d}"  # zero-padded 8-digit numeric string
        h = sha256_hash_str(candidate)
        if h in TARGET_HASHES:
            found[h] = candidate
    return found


def chunk_ranges(total, n_chunks):
    """Split [0, total) into n_chunks contiguous ranges, spreading the
    remainder across the first few chunks instead of dumping it all
    on the last one."""
    size, remainder = divmod(total, n_chunks)
    ranges = []
    start = 0
    for i in range(n_chunks):
        end = start + size + (1 if i < remainder else 0)
        ranges.append((start, end))
        start = end
    return ranges


if __name__ == "__main__":
    TOTAL = 10**8  # 00000000 to 99999999
    n_workers = cpu_count()

    # Use many more, smaller chunks than workers so results stream back
    # steadily and early-exit actually saves time instead of waiting
    # for one giant chunk to finish.
    n_chunks = n_workers * 20
    ranges = chunk_ranges(TOTAL, n_chunks)

    results = {}
    checked = 0
    with Pool(n_workers) as pool:
        for partial in pool.imap_unordered(check_range, ranges, chunksize=1):
            results.update(partial)
            checked += 1
            print(
                f"\rChecked {checked}/{len(ranges)} chunks, "
                f"found {len(results)}/{len(TARGET_HASHES)}",
                end="",
                flush=True,
            )
            if len(results) == len(TARGET_HASHES):
                break  # stop early once everything is found

    print()
    print(f"Found {len(results)} passwords:")
    for h, pw in results.items():
        print(f"{h} -> {pw}")
