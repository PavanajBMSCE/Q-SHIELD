import unittest
from benchmarking.engine import run_comparative_benchmark

class ComparativeBenchmarkValidationTests(unittest.TestCase):
    def test_rejects_too_few_repetitions(self):
        with self.assertRaises(ValueError):
            run_comparative_benchmark(repetitions=2)

    def test_rejects_unknown_algorithm(self):
        with self.assertRaises(ValueError):
            run_comparative_benchmark(algorithms=["RSA"])

    def test_rejects_duplicate_algorithms(self):
        with self.assertRaises(ValueError):
            run_comparative_benchmark(algorithms=["X25519", "X25519"])

    def test_rejects_invalid_warmups(self):
        with self.assertRaises(ValueError):
            run_comparative_benchmark(warmups=21)

if __name__ == "__main__":
    unittest.main()
