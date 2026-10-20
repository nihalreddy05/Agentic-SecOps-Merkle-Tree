import json
import time
import random
import os

LIVE_DIR = 'live_db/'


class HackerAgent:
    def __init__(self):
        self.is_running = False

    def execute_attack(self, attack_vector=None):
        if not self.is_running and attack_vector is None:
            return

        try:
            files = [f for f in os.listdir(LIVE_DIR) if f.endswith('.json')]
            if not files: return

            target_file = random.choice(files)
            filepath = os.path.join(LIVE_DIR, target_file)

            with open(filepath, 'r') as f:
                data = json.load(f)
            if not data: return

            if not attack_vector: attack_vector = random.choice(['tamper', 'delete', 'insert'])

            if attack_vector == 'tamper':
                data[random.randint(0, len(data) - 1)] = "MALICIOUS_BYTES_123"
            elif attack_vector == 'delete' and len(data) > 1:
                data.pop(random.randint(0, len(data) - 1))
            else:
                data.append("FAKE_BLOCK_INSERTED")

            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception:
            pass

    def run(self):
        while True:
            if self.is_running:
                self.execute_attack()
                time.sleep(random.uniform(1.5, 2.5))
            else:
                time.sleep(0.5)