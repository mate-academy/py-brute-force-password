import contextlib
import io
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from app import main


class PasswordSearchTests(unittest.TestCase):
    def test_hash_matches_known_sha256(self):
        self.assertEqual(
            main.sha256_hash_str(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_range_boundaries_and_leading_zeros(self):
        passwords = ["00000000", "00000009", "00000010"]
        targets = [main.sha256_hash_str(value) for value in passwords]
        with patch.object(main, "PASSWORDS_TO_BRUTE_FORCE", targets):
            self.assertEqual(main.search_range(0, 10), dict(zip(targets[:2], passwords[:2])))
            self.assertEqual(main.search_range(10, 11), {targets[2]: passwords[2]})
            self.assertEqual(main.search_range(11, 11), {})

    def test_upper_endpoint(self):
        digest = main.sha256_hash_str("99999999")
        with patch.object(main, "PASSWORDS_TO_BRUTE_FORCE", [digest]):
            self.assertEqual(
                main.search_range(99999999, 100000000),
                {digest: "99999999"},
            )

    def test_all_chunks_print_in_target_order(self):
        passwords = ["00000009", "00000000", "00000005"]
        targets = [main.sha256_hash_str(value) for value in passwords]
        output = io.StringIO()
        with (
            patch.object(main, "PASSWORDS_TO_BRUTE_FORCE", targets),
            patch.object(main, "SEARCH_SPACE", 12),
            patch.object(main, "CHUNK_SIZE", 4),
            patch.object(main, "ProcessPoolExecutor", ThreadPoolExecutor),
            contextlib.redirect_stdout(output),
        ):
            main.brute_force_password()
        self.assertEqual(output.getvalue().splitlines(), passwords)

    def test_missing_target_is_reported(self):
        with (
            patch.object(main, "SEARCH_SPACE", 0),
            patch.object(main, "ProcessPoolExecutor", ThreadPoolExecutor),
            self.assertRaisesRegex(RuntimeError, "10 exercise passwords"),
        ):
            main.brute_force_password()


if __name__ == "__main__":
    unittest.main()
