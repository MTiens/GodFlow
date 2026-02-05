import os
from pathlib import Path
from typing import Dict, List

class PayloadManager:
    """
    Manages loading and caching of fuzzing payloads from text files.

    This class is responsible for reading payload files from a specified directory.
    It uses a lazy-loading and caching mechanism to ensure that each payload
    file is read from disk only once, improving performance for tests that
    run many times with the same payload set.

    Attributes:
        payloads_dir (Path): The path to the directory containing payload files.
        _cache (Dict[str, List[str]]): An internal cache to store loaded payloads.
                                       Keys are category names (e.g., 'xss'),
                                       and values are lists of payload strings.
    """

    def __init__(self, payloads_dir: str):
        """
        Initializes the PayloadManager.

        Args:
            payloads_dir: The path to the directory where payload files are stored.
                          (e.g., 'payloads/')

        Raises:
            FileNotFoundError: If the specified payloads directory does not exist.
        """
        self.payloads_dir = Path(payloads_dir)
        self._cache: Dict[str, List[str]] = {}

        if not self.payloads_dir.is_dir():
            raise FileNotFoundError(
                f"Payloads directory not found at: {self.payloads_dir.resolve()}"
            )

    def get_payloads(self, category: str) -> List[str]:
        """
        Retrieves a list of payloads for a given category.

        First, it checks the internal cache. If the payloads are not cached,
        it attempts to load them from a corresponding file (e.g., 'xss' -> 'xss.txt').
        The loaded payloads are then cached for future requests.

        Lines in the payload file that are empty or start with '#' are ignored.

        Args:
            category: The name of the payload category to load (e.g., 'xss', 'sqli').

        Returns:
            A list of payload strings for the category. Returns an empty list
            if the payload file cannot be found or read.
        """
        # 1. Check cache first for performance
        if category in self._cache:
            return self._cache[category]

        payload_file = self.payloads_dir / f"{category}.txt"

        # 2. Check if the specific payload file exists
        if not payload_file.is_file():
            print(f"[WARN] Payload file not found for category '{category}': {payload_file}")
            # Cache the empty result to avoid future file system checks
            self._cache[category] = []
            return []

        # 3. Load from disk if not cached and file exists
        print(f"[INFO] Loading payloads for category '{category}' from {payload_file}...")
        try:
            with payload_file.open('r', encoding='utf-8') as f:
                # Use a list comprehension to read, clean, and filter lines
                payloads = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith('#')
                ]

            # 4. Store in cache for next time
            self._cache[category] = payloads
            return payloads
        except Exception as e:
            print(f"[ERROR] Could not read payload file {payload_file}: {e}")
            # Cache the empty result to avoid retrying a failed read
            self._cache[category] = []
            return []

    def get_all_payloads(self) -> List[str]:
        """
        Loads all payloads from all .txt files in the payloads directory and returns a combined list.
        """
        all_payloads = []
        for file in self.payloads_dir.glob('*.txt'):
            try:
                with file.open('r', encoding='utf-8') as f:
                    payloads = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.strip().startswith('#')
                    ]
                    all_payloads.extend(payloads)
            except Exception as e:
                print(f"[ERROR] Could not read payload file {file}: {e}")
        return all_payloads