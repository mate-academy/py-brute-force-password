import sha256
from multiprocessing import Process, Manager, cpu_count

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


def worker(start: int, end: int, targets: set, result: dict, stop_flag):
    for i in range(start, end):
        if stop_flag.value:
            return

        pwd = f"{i:08d}"
        h = sha256_hash_str(pwd)

        if h in targets:
            result[h] = pwd
            print(f"FOUND: {pwd}")

            if len(result) == len(targets):
                stop_flag.value = True
                return


def main():
    targets = set(PASSWORDS_TO_BRUTE_FORCE)

    manager = Manager()
    result = manager.dict()
    stop_flag = manager.Value("b", False)

    cpu = cpu_count()
    chunk = 100_000_000 // cpu

    processes = []

    for i in range(cpu):
        start = i * chunk
        end = (i + 1) * chunk if i != cpu - 1 else 100_000_000

        p = Process(target=worker, args=(start, end, targets, result, stop_flag))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

    print("\nRESULT:")
    for k, v in result.items():
        print(v)


if __name__ == "__main__":
    main()
