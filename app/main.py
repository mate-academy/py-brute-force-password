from multiprocessing import Process, Queue
from string import digits
from itertools import product, cycle
from hashlib import sha256
from queue import Empty
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
ONE_PWD_LEN = 8 # len of password
BATCH = 10_000  # empirically determined to be a fairly good batch size
PWD_COUNT = len(PASSWORDS_TO_BRUTE_FORCE) # passwords to find


# check a batch of passwords
def process(queue, queue_response) -> None:

    while len(PASSWORDS_TO_BRUTE_FORCE) != 0:
        batch = queue.get()

        if batch is None:
            break

        for v in map(str.encode, batch):
            hashed_pwd = sha256(v).hexdigest()
            if hashed_pwd in PASSWORDS_TO_BRUTE_FORCE:
                queue_response.put(v)
                print(f"Hash '{hashed_pwd}' encoded to password {v}")
                PASSWORDS_TO_BRUTE_FORCE.remove(hashed_pwd)


# generate passwords
def genpwd() -> str:
    for pwd in product(digits, repeat=ONE_PWD_LEN):
        yield "".join(pwd)


def main_multiprocess() -> None:
    queue_response = Queue()
    # start PROCS processes each with a discrete input queue
    # each process uses the same response queue
    procs = []
    for queue in (queues := [Queue() for _ in range(PROCS)]):
        (proc := Process(target=process, args=(queue, queue_response))).start()
        procs.append(proc)

    batch = []
    qc = cycle(queues)
    results = []

    for pwd in genpwd():
        batch.append(pwd)
        if len(batch) == BATCH:
            # send batch to the next queue in the cycle
            next(qc).put(batch)
            batch = []
            # occasional check for a response
            try:
                results.append(queue_response.get(block=False))
                if len(results) == PWD_COUNT:
                    break
            except Empty:
                pass

    # tells each process to stop
    for queue in queues:
        queue.put(None)

    # wait for all subprocesses to end
    for p in procs:
        p.join()


if __name__ == "__main__":
    start_time = time.perf_counter()
    main_multiprocess()
    multiprocessing_duration = time.perf_counter() - start_time
    print(f"All hashes encoded. Time taken: {multiprocessing_duration}")
