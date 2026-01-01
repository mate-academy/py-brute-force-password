import time
from hashlib import sha256
from multiprocessing import Pool, Manager, cpu_count
from typing import Dict, Set, Tuple


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
    """Hash a string using SHA256."""
    return sha256(to_hash.encode("utf-8")).hexdigest()


def search_range(args: Tuple[int, int, Set[str]]) -> Dict[str, str]:
    """
    Search for passwords in a given range.

    Args:
        args: Tuple of (start, end, target_hashes)

    Returns:
        Dictionary mapping hash to password
    """
    start, end, target_hashes = args
    found: Dict[str, str] = {}

    # Iterate through the range
    for i in range(start, end):
        # Format as 8-digit string with leading zeros
        password = str(i).zfill(8)

        # Calculate hash
        hash_value = sha256_hash_str(password)

        # Check if hash matches any target (O(1) lookup with set)
        if hash_value in target_hashes:
            found[hash_value] = password
            print(f"[Process {start}-{end}] Found: {password} -> {hash_value[:16]}...")

            # Early stopping: if we found all 10, we can stop
            if len(found) == len(target_hashes):
                break

    return found


def brute_force_password() -> None:
    """
    Brute force password search using multiprocessing.
    """
    # Convert to set for O(1) lookup performance
    target_hashes: Set[str] = set(PASSWORDS_TO_BRUTE_FORCE)
    total_passwords = len(target_hashes)

    print(f"Target: {total_passwords} passwords to crack")
    print(f"Search space: 100,000,000 combinations (00000000-99999999)")

    # Determine optimal number of processes
    num_processes = cpu_count()
    print(f"Using {num_processes} CPU cores for parallel processing")
    print("="*70)

    # Divide the search space into chunks
    total_range = 100_000_000
    chunk_size = total_range // num_processes

    # Create ranges for each process
    ranges = []
    for i in range(num_processes):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i < num_processes - 1 else total_range
        ranges.append((start, end, target_hashes))

    # Execute parallel search
    all_found: Dict[str, str] = {}

    with Pool(num_processes) as pool:
        results = pool.map(search_range, ranges)

    # Consolidate results from all processes
    for result in results:
        all_found.update(result)

    # Display final results
    print("\n" + "="*70)
    print(f"RESULTS: Found {len(all_found)}/{total_passwords} passwords")
    print("="*70)

    # Sort by password for cleaner output
    sorted_results = sorted(all_found.items(), key=lambda x: x[1])

    for hash_value, password in sorted_results:
        print(f"Password: {password} -> Hash: {hash_value}")

    print("="*70)


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
