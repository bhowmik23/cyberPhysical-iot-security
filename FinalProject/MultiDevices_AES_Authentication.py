import hashlib
import hmac
import os
import secrets
import threading
import time
import subprocess
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from prettytable import PrettyTable

# Parameters
DEVICE_NUMBER = 10
N = 5          # Number of keys in the Secure Vault
M = 16         # Size of each key in bytes (128 bits for AES-128)
CHALLENGE_1_LENGTH = 4
CHALLENGE_2_LENGTH = 3

class SecureVault:
    """
    Secure storage for symmetric keys. Supports XOR combination and HMAC-based updates.
    """
    def __init__(self, n=N, m=M):
        self.keys = [secrets.token_bytes(m) for _ in range(n)]

    def key_xor(self, indices):
        key = self.keys[indices[0]]
        for idx in indices[1:]:
            key = bytes(a ^ b for a, b in zip(key, self.keys[idx]))
        return key

    def update_vault(self, data):
        h = hmac.new(data, b''.join(self.keys), hashlib.sha256).digest()
        partitions = [h[i:i+len(self.keys[0])] for i in range(0, len(h), len(self.keys[0]))]
        for i in range(len(self.keys)):
            self.keys[i] = bytes(a ^ b for a, b in zip(self.keys[i], partitions[i % len(partitions)]))

class IoTServer(threading.Thread):
    """
    Manages sessions, challenges, and vault updates for multiple devices.
    """
    def __init__(self):
        super().__init__()
        self.device_vaults = {}  # {device_id: SecureVault}
        self.sessions = {}       # {device_id: session_data}
        self.lock = threading.Lock()

    def register_device(self, device):
        with self.lock:
            self.device_vaults[device.device_id] = device.vault

    def is_valid_session(self, device_id, session_id):
        with self.lock:
            if 0 < session_id < 100 and device_id in self.device_vaults:
                self.sessions[device_id] = {
                    'vault': self.device_vaults[device_id],
                    'session_id': session_id
                }
                return True
        return False

    def generate_challenge(self, device_id):
        with self.lock:
            session = self.sessions.get(device_id)
            if not session:
                return None
            vault = session['vault']
            c1 = random.sample(range(len(vault.keys)), CHALLENGE_1_LENGTH)
            r1 = secrets.token_bytes(16)
            session.update({'c1': c1, 'r1': r1})
            return (c1, r1)

    def validate_challenge_response(self, device_id, encrypted_response):
        with self.lock:
            session = self.sessions.get(device_id)
            if not session:
                return False
            vault = session['vault']
            c1 = session['c1']
            r1 = session['r1']

            k1 = vault.key_xor(c1)
            cipher = AES.new(k1, AES.MODE_ECB)
            try:
                decrypted = unpad(cipher.decrypt(encrypted_response), 16)
            except ValueError:
                return False

            r1_received = decrypted[:16]
            t1 = decrypted[16:32]
            c2 = list(decrypted[32:35])
            r2 = decrypted[35:51]
            if r1_received != r1:
                return False
            session.update({'c2': c2, 'r2': r2, 't1': t1})
            return True

    def generate_final_response(self, device_id):
        with self.lock:
            session = self.sessions.get(device_id)
            if not session:
                return None
            vault = session['vault']
            c2 = session['c2']
            r2 = session['r2']
            t1 = session['t1']

            k2 = vault.key_xor(c2)
            dynamic_key = bytes(a ^ b for a, b in zip(k2, t1))
            t2 = secrets.token_bytes(16)
            payload = r2 + t2
            encrypted = AES.new(dynamic_key, AES.MODE_ECB).encrypt(pad(payload, 16))
            session['t2'] = t2
            return encrypted

    def finalize_auth(self, device_id):
        with self.lock:
            session = self.sessions.get(device_id)
            if not session:
                return
            vault = session['vault']
            r1 = session['r1']
            r2 = session['r2']
            vault.update_vault(r1 + r2)
            self.device_vaults[device_id] = vault

class IoTDevice(threading.Thread):
    """
    Simulates an IoT device that can mutually authenticate with the server.
    """
    def __init__(self, device_id, server):
        super().__init__()
        self.device_id = device_id
        self.server = server
        self.vault = SecureVault()
        self.authenticated = False
        self.encrypt_time = None
        self.decrypt_time = None
        self.vault_update_time = None
        self.server.register_device(self)

    def run(self):
        session_id = random.randint(1, 99)
        if not self.server.is_valid_session(self.device_id, session_id):
            return

        challenge1 = self.server.generate_challenge(self.device_id)
        if not challenge1:
            return
        c1, r1 = challenge1

        k1 = self.vault.key_xor(c1)
        t1 = secrets.token_bytes(16)
        c2 = random.sample(range(len(self.vault.keys)), CHALLENGE_2_LENGTH)
        r2 = secrets.token_bytes(16)
        payload = r1 + t1 + bytes(c2) + r2

        encrypt_start = time.time()
        encrypted_response = AES.new(k1, AES.MODE_ECB).encrypt(pad(payload, 16))
        self.encrypt_time = time.time() - encrypt_start

        if not self.server.validate_challenge_response(self.device_id, encrypted_response):
            return

        final_response = self.server.generate_final_response(self.device_id)
        if not final_response:
            return

        session_data = self.server.sessions[self.device_id]
        k2 = self.vault.key_xor(session_data['c2'])
        dynamic_key = bytes(a ^ b for a, b in zip(k2, t1))
        decrypt_start = time.time()
        try:
            decrypted = unpad(AES.new(dynamic_key, AES.MODE_ECB).decrypt(final_response), 16)
        except ValueError:
            return
        self.decrypt_time = time.time() - decrypt_start

        r2_received = decrypted[:16]
        if r2_received == r2:
            vault_start = time.time()
            self.server.finalize_auth(self.device_id)
            self.vault_update_time = time.time() - vault_start
            self.authenticated = True

if __name__ == "__main__":
    server = IoTServer()
    server.start()
    devices = [IoTDevice(f"Device{i+1:02}", server) for i in range(DEVICE_NUMBER)]
    for device in devices:
        device.start()
    for device in devices:
        device.join()
    server.join()

    metrics_table = PrettyTable()
    metrics_table.field_names = ["Device ID", "Encrypt (ms)", "Decrypt (ms)", "Vault Update (ms)", "Status"]
    encrypt_times, decrypt_times, vault_times = [], [], []

    for device in devices:
        status = "Success" if device.authenticated else "Failed"
        encrypt = f"{device.encrypt_time*1000:.4f}" if device.encrypt_time else "N/A"
        decrypt = f"{device.decrypt_time*1000:.4f}" if device.decrypt_time else "N/A"
        vault = f"{device.vault_update_time*1000:.4f}" if device.vault_update_time else "N/A"
        if device.authenticated:
            encrypt_times.append(device.encrypt_time)
            decrypt_times.append(device.decrypt_time)
            vault_times.append(device.vault_update_time)
        metrics_table.add_row([device.device_id, encrypt, decrypt, vault, status])

    print("\nAES-128 Authentication Performance Metrics:")
    print(metrics_table)

    if encrypt_times or decrypt_times or vault_times:
        avg_table = PrettyTable()
        avg_table.field_names = ["Metric", "Average Time (ms)"]
        if encrypt_times:
            avg_table.add_row(["Encryption", f"{sum(encrypt_times)*1000/len(encrypt_times):.4f}"])
        if decrypt_times:
            avg_table.add_row(["Decryption", f"{sum(decrypt_times)*1000/len(decrypt_times):.4f}"])
        if vault_times:
            avg_table.add_row(["Vault Update", f"{sum(vault_times)*1000/len(vault_times):.4f}"])
        total = sum([
            sum(encrypt_times)*1000/len(encrypt_times) if encrypt_times else 0,
            sum(decrypt_times)*1000/len(decrypt_times) if decrypt_times else 0,
            sum(vault_times)*1000/len(vault_times) if vault_times else 0
        ])
        avg_table.add_row(["Total Time", f"{total:.4f}"])
        print("\nAverage Operation Times:")
        print(avg_table)

    print("\nInitiating ECC Authentication Comparison...\n")
    try:
        subprocess.run(['python', 'MultiDevices_ECC_Authentication.py'], check=True)
    except Exception as e:
        print(f"ECC Authentication: {e}")
