import unittest

from main import analyze


class T(unittest.TestCase):
    def test_counts(self):
        r = analyze("Alpha beta. Beta gamma beta.", 2)
        self.assertEqual(r["words"], 5)
        self.assertEqual(r["sentences"], 2)
        self.assertEqual(r["top_terms"][0], ("beta", 3))


if __name__ == "__main__":
    unittest.main()
