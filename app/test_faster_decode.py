from multiprocessing import Process, Queue
from itertools import cycle
from hashlib import sha256
import time
import psutil


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

PROCS = psutil.cpu_count() - 1 # one less that CPU count
BATCH_SIZE = 10_000  # empirically determined to be a fairly good batch size

start_time = time.perf_counter()


# check a batch of passwords
def process(queue, queue_response) -> None:
    while True:
        batch = queue.get()
        if batch is None:
            break

        for v in map(str.encode, [str(pwd).zfill(8) for pwd in batch]):
            hashed_pwd = sha256(v).hexdigest()
            if hashed_pwd in PASSWORDS_TO_BRUTE_FORCE:
                print(f"Hash '{hashed_pwd}' encoded to password {v}. "
                      f"Time taken: {time.perf_counter() - start_time}")


def main_multiprocess() -> None:
    # pwd_ranges = [
    #     range(start, min(start + BATCH_SIZE, 100_000_000))
    #     for start in range(0, 100_000_000, BATCH_SIZE)
    # ]

    queue_response = Queue()
    # start PROCS processes each with a discrete input queue
    # each process uses the same response queue
    procs = []
    for queue in (queues := [Queue() for _ in range(PROCS)]):
        (proc := Process(target=process, args=(queue, queue_response))).start()
        procs.append(proc)

    qc = cycle(queues)

    [
        next(qc).put(range(start, min(start + BATCH_SIZE, 100_000_000)))
        for start in range(0, 100_000_000, BATCH_SIZE)
    ]
    # for pwd_range in pwd_ranges:
    #     next(qc).put(pwd_range)

    # tells each process to stop
    [queue.put(None) for queue in queues]
    # for queue in queues:
    #     queue.put(None)

    # wait for all subprocesses to end
    [p.join() for p in procs]
    # for p in procs:
    #     p.join()


if __name__ == "__main__":
    main_multiprocess()
    print(f"All hashes encoded. Time taken: {time.perf_counter() - start_time}")
