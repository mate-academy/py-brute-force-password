import io
import unittest
from contextlib import redirect_stdout
from hashlib import sha256
from unittest.mock import patch

from app import main


class BruteForcePasswordTests(unittest.TestCase):
    def setUp(self) -> None:
        patches = [
            patch.object(main, "SEARCH_SPACE_SIZE", 21, create=True),
            patch.object(main, "CHUNK_SIZE", 10, create=True),
            patch.object(main, "cpu_count", return_value=2, create=True),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_finds_zero_padded_passwords_in_input_order(self) -> None:
        passwords = ["00000020", "00000000", "00000010", "00000009"]
        hashes = [sha256(password.encode()).hexdigest() for password in passwords]
        output = io.StringIO()

        with patch.object(main, "PASSWORDS_TO_BRUTE_FORCE", hashes):
            with redirect_stdout(output):
                main.brute_force_password()

        self.assertEqual(
            output.getvalue().splitlines(),
            [*passwords, "Found: 4/4"],
        )

    def test_reports_a_password_missing_from_the_search_space(self) -> None:
        hashes = [sha256(b"00000021").hexdigest()]
        output = io.StringIO()

        with patch.object(main, "PASSWORDS_TO_BRUTE_FORCE", hashes):
            with redirect_stdout(output):
                with self.assertRaisesRegex(RuntimeError, "1 password"):
                    main.brute_force_password()

        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
