import time
from hashlib import sha256
import multiprocessing as mp
from typing import List, Any, Set


PASSWORDS_TO_BRUTE_FORCE: Set[str] = {
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


def sha256_hash_str(to_hash: str) -> str:
    return sha256(to_hash.encode("utf-8")).hexdigest()


def brute_range_print(
        process_idx: int,
        start: int,
        end: int,
        shared_results: Any,
        stop_event: Any
) -> None:
    print(f"Process {process_idx} started: "
          f"range {start} to {end}", flush=True)

    for i in range(start, end):
        if stop_event.is_set():
            break

        candidate: str = f"{i:08d}"
        unh: str = sha256_hash_str(candidate)

        if unh in PASSWORDS_TO_BRUTE_FORCE:
            if candidate not in shared_results:
                shared_results.append(candidate)
                print(f"\n[!] Process {process_idx} "
                      f"found password: {candidate} "
                      f"for hash {unh}", flush=True)

            if len(shared_results) >= 10:
                stop_event.set()
                break

    print(f"Process {process_idx} finished.")


def brute_force_password() -> List[str]:
    num_processes: int = mp.cpu_count()
    total_combinations: int = 100_000_000
    step: int = total_combinations // num_processes

    with (mp.Manager() as manager):
        shared_results: Any = manager.list()
        stop_event: Any = manager.Event()

        processes: List[mp.Process] = []
        for i in range(num_processes):
            start: int = i * step
            end=(i + 1) * step if i != num_processes - 1 else total_combinations

            process = mp.Process(
                target=brute_range_print,
                args=(i, start, end, shared_results, stop_event),
            )
            processes.append(process)
            process.start()

        for pr in processes:
            pr.join()

        return list(shared_results)


if __name__ == "__main__":
    mp.freeze_support()

    start_time: float = time.perf_counter()
    found_passwords_raw: List[str] = brute_force_password()
    end_time: float = time.perf_counter()

    unique_passwords: List[str] = sorted(list(set(found_passwords_raw)))

    print("\n" + "=" * 20)
    print("FINAL UNIQUE PASSWORDS:")
    for pwd in unique_passwords:
        print(pwd)
    print("=" * 20)

    print(f"\nElapsed: {end_time - start_time:.2f} seconds")

    assert len(unique_passwords) == 10, (
        f"Error: Expected 10 unique passwords, found {len(unique_passwords)}"
    )
