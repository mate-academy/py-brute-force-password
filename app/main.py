import asyncio
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


#-----------------------------------------
# In the blink of an eye
#-----------------------------------------
def check_range_return(start, end, target_hashes):
    local_found = []
    local_targets = set(target_hashes)

    for num in range(start, end):
        password = f"{num:08d}"
        hashed = sha256_hash_str(password)
        if hashed in local_targets:
            local_found.append((password, hashed))
            local_targets.remove(hashed)
            if not local_targets:
                break
    return local_found


def brute_force_password():
    num_processes = cpu_count()
    total = 10**8
    chunk_size = total // num_processes

    with Pool(num_processes) as pool:
        results = pool.starmap(check_range_return, [
            (
                i * chunk_size,
                (i + 1) * chunk_size if i != num_processes - 1 else total,
                PASSWORDS_TO_BRUTE_FORCE
            )
            for i in range(num_processes)
        ])

    for result in results:
        for password, hashed in result:
            print(f"Found: {password} => {hashed}")


if __name__ == "__main__":
    start_time = time.perf_counter()
    brute_force_password()
    end_time = time.perf_counter()
    print(f"Elapsed time: {end_time - start_time:.2f} seconds")
    print(f"CPU cores used: {cpu_count()}")


#-----------------------------------------
# It takes a while
#-----------------------------------------
# def brute_force_password() -> None:
#     found_passwords = set()
#     target_hashes = set(PASSWORDS_TO_BRUTE_FORCE)
#
#     for num in range(0, 10**8):
#         password = f"{num:08d}"
#         hashed = sha256_hash_str(password)
#
#         if hashed in target_hashes:
#             print(f"Found password: {password} for hash: {hashed}")
#             found_passwords.add(password)
#             target_hashes.remove(hashed)
#
#         if not target_hashes:
#             break
# if __name__ == "__main__":
#     start_time = time.perf_counter()
#     asyncio.run(brute_force_password())
#     end_time = time.perf_counter()
#
#     print("Elapsed:", end_time - start_time)
#-----------------------------------------
# It drags on forever
#-----------------------------------------
# async def check_password(num, target_hashes):
#     password = f"{num:08d}"
#     hashed = sha256_hash_str(password)
#     if hashed in target_hashes:
#         print(f"Found password: {password} for hash: {hashed}")
#         return password
#     return None
#
#
# async def brute_force_password():
#     target_hashes = set(PASSWORDS_TO_BRUTE_FORCE)
#     tasks = []
#
#     for num in range(0, 10 ** 8):
#         task = asyncio.create_task(check_password(num, target_hashes))
#         tasks.append(task)
#
#         if len(tasks) >= 10000:
#             await asyncio.gather(*tasks)
#             tasks = []
#
#     if tasks:
#         await asyncio.gather(*tasks)
#
# if __name__ == "__main__":
#     start_time = time.perf_counter()
#     brute_force_password()
#     end_time = time.perf_counter()
#
#     print("Elapsed:", end_time - start_time)
