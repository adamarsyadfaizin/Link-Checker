import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import run


class RunLauncherTests(unittest.TestCase):
    def test_exit_from_main_menu(self):
        output = io.StringIO()

        with patch("builtins.input", return_value="0"), redirect_stdout(output):
            exit_code = run.main()

        self.assertEqual(exit_code, 0)
        self.assertIn("Welcome to Link Check Toolkit", output.getvalue())
        self.assertIn("Session closed.", output.getvalue())

    def test_link_checker_check_command(self):
        inputs = iter(["1", "check https://google.com", "exit"])
        output = io.StringIO()

        with patch("builtins.input", side_effect=lambda _prompt="": next(inputs)), patch(
            "run.print_result"
        ) as print_result, redirect_stdout(output):
            exit_code = run.main()

        self.assertEqual(exit_code, 0)
        print_result.assert_called_once_with("https://google.com", detailed=False)

    def test_link_checker_explain_command(self):
        inputs = iter(["1", "explain https://goggle.com", "exit"])
        output = io.StringIO()

        with patch("builtins.input", side_effect=lambda _prompt="": next(inputs)), patch(
            "run.print_result"
        ) as print_result, redirect_stdout(output):
            exit_code = run.main()

        self.assertEqual(exit_code, 0)
        print_result.assert_called_once_with("https://goggle.com", detailed=True)


if __name__ == "__main__":
    unittest.main()
