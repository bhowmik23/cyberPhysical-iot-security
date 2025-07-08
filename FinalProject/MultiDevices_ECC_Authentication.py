import secrets
import time
from ecdsa import SigningKey, VerifyingKey, NIST256p
from prettytable import PrettyTable

DEVICE_NUMBER = 10

class IoTDevice:
    """
    Simulates an IoT device with ECDSA key pair for authentication.
    """
    def __init__(self, device_id):
        self.device_id = device_id
        # Key generation timing
        start_time = time.perf_counter()
        self.private_key = SigningKey.generate(curve=NIST256p)
        self.public_key = self.private_key.verifying_key
        self.key_gen_time = (time.perf_counter() - start_time) * 1000  # ms
        self.sign_time = 0.0
        self.status = "Failed"

    def get_public_key(self):
        """Returns public key in PEM format."""
        return self.public_key.to_pem()

    def sign_challenge(self, challenge):
        """Signs a challenge and measures the signing time."""
        start_time = time.perf_counter()
        signature = self.private_key.sign(challenge)
        self.sign_time = (time.perf_counter() - start_time) * 1000  # ms
        return signature

class Server:
    """
    Manages device registration, challenge issuance, and signature verification.
    """
    def __init__(self):
        self.registered_devices = {}  # device_id: VerifyingKey
        self.verify_times = {}        # device_id: verify time in ms

    def register_device(self, device_id, public_key_pem):
        self.registered_devices[device_id] = VerifyingKey.from_pem(public_key_pem)

    def generate_challenge(self):
        """Returns a cryptographically random 256-bit challenge."""
        return secrets.token_bytes(32)

    def verify_signature(self, device_id, challenge, signature):
        """Verifies a signature and records verification time."""
        if device_id not in self.registered_devices:
            return False
        public_key = self.registered_devices[device_id]
        start_time = time.perf_counter()
        try:
            result = public_key.verify(signature, challenge)
        except Exception:
            result = False
        self.verify_times[device_id] = (time.perf_counter() - start_time) * 1000  # ms
        return result

def simulate_authentication(server, device):
    """
    Runs full authentication (registration, challenge, sign, verify) for one device.
    """
    server.register_device(device.device_id, device.get_public_key())
    t0 = time.perf_counter()
    challenge = server.generate_challenge()
    signature = device.sign_challenge(challenge)
    verification = server.verify_signature(device.device_id, challenge, signature)
    total_time = (time.perf_counter() - t0) * 1000  # ms
    device.status = "Success" if verification else "Failed"
    return {
        "key_gen_time": device.key_gen_time,
        "sign_time": device.sign_time,
        "verify_time": server.verify_times.get(device.device_id, 0.0),
        "total_time": total_time,
        "status": device.status
    }

if __name__ == "__main__":
    server = Server()
    devices = [IoTDevice(f"Device{i+1:02}") for i in range(DEVICE_NUMBER)]

    results = [simulate_authentication(server, device) for device in devices]

    # Table output
    results_table = PrettyTable()
    results_table.field_names = [
        "Device ID", "KeyGen (ms)", "Sign (ms)", "Verify (ms)", "Total (ms)", "Status"
    ]
    key_gen_times, sign_times, verify_times, total_times = [], [], [], []

    for i, result in enumerate(results):
        device = devices[i]
        results_table.add_row([
            device.device_id,
            f"{result['key_gen_time']:.4f}",
            f"{result['sign_time']:.4f}",
            f"{result['verify_time']:.4f}",
            f"{result['total_time']:.4f}",
            result['status']
        ])
        if result['status'] == "Success":
            key_gen_times.append(result['key_gen_time'])
            sign_times.append(result['sign_time'])
            verify_times.append(result['verify_time'])
            total_times.append(result['total_time'])

    # Average calculation
    avg_table = PrettyTable()
    avg_table.field_names = ["Metric", "Average Time (ms)"]
    if key_gen_times:
        avg_table.add_row(["Key Generation", f"{sum(key_gen_times)/len(key_gen_times):.4f}"])
    if sign_times:
        avg_table.add_row(["Signature Creation", f"{sum(sign_times)/len(sign_times):.4f}"])
    if verify_times:
        avg_table.add_row(["Signature Verification", f"{sum(verify_times)/len(verify_times):.4f}"])
    if total_times:
        avg_table.add_row(["Total Authentication", f"{sum(total_times)/len(total_times):.4f}"])

    print("\nECC Authentication Performance Metrics")
    print(results_table)
    print("\nPerformance Averages (Success Only)")
    print(avg_table)
