import multiprocessing
import time
from enum import Enum
from hashlib import sha256
from typing import List
from concurrent.futures import ProcessPoolExecutor, wait
from itertools import combinations_with_replacement


class BrutInfo(Enum):
    """
    Enum class defines constants for Brut-force passwords
    """
    PASSWORDS_TO_BRUTE_FORCE: list = [
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
    POSSIBLE_SYMBOLS: tuple = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9")
    MIN_POSSIBLE_NUMBER = 10_000_000
    MAX_RANGE_OF_NUMBERS = 10
    LENGTH_OF_PASSWORD: int = 8


class BrutForceFunctionality:
    """
    Class defines methods connects to brut force specific
    """
    def __init__(self) -> None:
        """
        Initializes class instances
        """
        # I came up with this solution from start but didn't understand why it's working incorrect
        # for example: if you debug it you will find that number '00000010' = '00000011'.
        # This behaviour isn't clear for me
        self.possible_passwords = self._get_all_possible_passwords()

    @staticmethod
    def _get_all_possible_passwords() -> List:
        """
        Gets all possible passwords
        :return: All possible passwords
        """
        return ["".join(password) for password in combinations_with_replacement(
            BrutInfo.POSSIBLE_SYMBOLS.value, BrutInfo.LENGTH_OF_PASSWORD.value)]

    @staticmethod
    def __sha256_hash_str(to_hash: str) -> str:
        """
        Encodes to_hash string to sha256 encryption
        :param to_hash: String that will be encoded to sha256 encryption
        :return: Encoded to_hash digit
        """
        return sha256(to_hash.encode("utf-8")).hexdigest()

    def encode_and_check_password(self, eight_digit_password: str) -> None:
        """
        Encodes and checks password
        :param eight_digit_password: Eight digit password that will be encoded
        """
        sha256_password = self.__sha256_hash_str(eight_digit_password)

        if sha256_password in BrutInfo.PASSWORDS_TO_BRUTE_FORCE.value:
            print(eight_digit_password)

    def fill_password_and_check_it(self, number_to_find_from: int, max_number_to_find: int) -> None:
        """
        Makes 8 digit password and checks it
        :param number_to_find_from: Number from which we start looking for a password
        :param max_number_to_find: Max number till which we are looking for a password
        """
        for password in range(number_to_find_from, max_number_to_find):
            eight_digit_password = str(password).zfill(BrutInfo.LENGTH_OF_PASSWORD.value)
            self.encode_and_check_password(eight_digit_password)

    def brute_force_password(self) -> None:
        """
        Performs brute force by 'PASSWORDS_TO_BRUTE_FORCE' list of passwords
        """
        features = []
        indentation = 1

        with ProcessPoolExecutor(multiprocessing.cpu_count() - 1) as executor:
            for counter in range(BrutInfo.MAX_RANGE_OF_NUMBERS.value):
                number_to_find_from = counter * BrutInfo.MIN_POSSIBLE_NUMBER.value
                max_number_to_find = (counter + indentation) * BrutInfo.MIN_POSSIBLE_NUMBER.value

                features.append(executor.submit(
                    self.fill_password_and_check_it, number_to_find_from, max_number_to_find))
            wait(features)
        print()


if __name__ == "__main__":
    brut_functionality = BrutForceFunctionality()
    print("Start")
    start_time = time.perf_counter()

    brut_functionality.brute_force_password()
    end_time = time.perf_counter()

    print("Elapsed:", end_time - start_time)
