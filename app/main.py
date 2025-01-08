import time
from hashlib import sha256
from concurrent.futures import ProcessPoolExecutor
import multiprocessing
from typing import List, Tuple

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


# Define a function to hash a string using SHA-256 algorithm
def sha256_hash_str(to_hash: str) -> str:
    """
    Hashes a given string using SHA-256
    algorithm and returns the hexadecimal digest.

    Args:
        to_hash (str): The string to be hashed.

    Returns:
        str: The hexadecimal representation of the SHA-256
        hash of the input string.
    """
    return sha256(to_hash.encode("utf-8")).hexdigest()


def check_password_range(start: int, end: int) -> List[Tuple[str, str]]:
    """
    Brute-forces through a range of password numbers, hashes them,
    and checks if any of the hashes match the target hashes.

    Args:
        start (int): The starting number in the range of passwords to check.
        end (int): The ending number in the range of passwords to check.

    Returns:
        list: A list of tuples containing
        the matching passwords and their corresponding hashes.
    """
    found = []
    # Loop over the range of numbers (possible passwords)
    for i in range(start, end):
        # Format the number as an 8-digit string,
        # adding leading zeros if necessary
        password = f"{i:08d}"
        hashed = sha256_hash_str(password)
        if hashed in PASSWORDS_TO_BRUTE_FORCE:
            found.append((password, hashed))
    return found  # Return the list of found passwords and their hashes


def brute_force_password() -> list:
    """
    Initiates the brute force process to find passwords by
    splitting the task across multiple processes.
    Each process works on a separate chunk of
    the password space (from 00000000 to 99999999).

    Returns:
        list: A list of tuples containing
        the found passwords and their corresponding hashes.
    """
    num_processes = (
        multiprocessing.cpu_count()
    )  # Get the number of CPU cores available for parallelism
    chunk_size = (
        100000000 // num_processes
    )  # Divide the total range of passwords
    # (100 million) by the number of processes

    # Using ProcessPoolExecutor to manage multiple processes
    with ProcessPoolExecutor(max_workers=num_processes) as executor:
        futures = []
        # Divide the password space into chunks
        # and assign each chunk to a process
        for i in range(0, 100000000, chunk_size):
            futures.append(
                executor.submit(
                    check_password_range,
                    i,
                    min(i + chunk_size,
                        100000000
                        )
                )
            )

        found_passwords = []
        # Wait for all processes to finish and collect their results
        for future in futures:
            found_passwords.extend(
                future.result()
            )  # Add the results of each process to the list of found passwords

    return found_passwords


if __name__ == "__main__":
    start_time = time.perf_counter()
    found = brute_force_password()
    end_time = time.perf_counter()

    print("Found passwords:")
    # Iterate through each found password and its hash
    for password, hashed in found:
        print(f"Password: {password}, Hash: {hashed}")

    print(f"\nTotal passwords found: {len(found)}")
    print(f"Elapsed time: {end_time - start_time:.2f} sec")
