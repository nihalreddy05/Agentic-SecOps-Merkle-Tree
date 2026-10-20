import json
import time
import os
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from forensics import AuditChain
from setup_engine import MerkleTree
from cryptography.fernet import Fernet, InvalidToken

LIVE_DIR = 'live_db/'
BACKUP_DIR = 'secure_backup/'


class GuardAgent(FileSystemEventHandler):
    def __init__(self):
        self.is_active = True
        self.is_healing = False
        self.audit_chain = AuditChain()
        self.shards = {}

        if os.path.exists('secret.key'):
            with open('secret.key', 'rb') as f:
                self.cipher_suite = Fernet(f.read())
        else:
            self.cipher_suite = None

        for filename in os.listdir(LIVE_DIR):
            if filename.startswith('shard') and filename.endswith('.json'):
                self.load_shard(filename)

    def load_shard(self, filename):
        live_path = os.path.join(LIVE_DIR, filename)
        backup_path = os.path.join(BACKUP_DIR, filename.replace('shard', 'backup'))

        live_data = None
        for attempt in range(5):
            try:
                with open(live_path, 'r') as f:
                    live_data = json.load(f, strict=False)
                    break
            except (json.JSONDecodeError, IOError):
                time.sleep(0.2)

        backup_data = None
        for attempt in range(5):
            try:
                with open(backup_path, 'r') as f:
                    backup_data = json.load(f, strict=False)
                    break
            except (json.JSONDecodeError, IOError):
                time.sleep(0.2)

        if live_data is not None and backup_data is not None:
            self.shards[filename] = {
                'data': live_data,
                'backup': backup_data,
                'tree': MerkleTree(live_data),
                'backup_tree': MerkleTree(backup_data)
            }

    def on_modified(self, event):
        if not self.is_active: return
        if event.src_path.endswith('.json') and not self.is_healing:
            filename = os.path.basename(event.src_path)
            if filename in self.shards:
                self.detect_and_heal(filename)

    def forensic_diff(self, shard, corrupted_index, live_data):
        try:
            orig_enc = self.shards[shard]['backup'][corrupted_index]
            tampered_enc = live_data[corrupted_index]
            if orig_enc == tampered_enc: return "N/A"

            orig_dec = json.loads(self.cipher_suite.decrypt(orig_enc.encode('utf-8')).decode('utf-8'))
            try:
                tampered_dec = json.loads(self.cipher_suite.decrypt(tampered_enc.encode('utf-8')).decode('utf-8'))
                changed_cols = [k for k in orig_dec if orig_dec.get(k) != tampered_dec.get(k)]
                return ", ".join(changed_cols) if changed_cols else "Row Swapped"
            except InvalidToken:
                return "Ciphertext Destroyed"
        except Exception:
            return "Decryption Failed"

    def detect_and_heal(self, filename):
        time.sleep(0.1)
        live_path = os.path.join(LIVE_DIR, filename)
        backup_path = os.path.join(BACKUP_DIR, filename.replace('shard', 'backup'))
        shard_info = self.shards[filename]

        live_data = None
        for attempt in range(5):
            try:
                with open(live_path, 'r') as f:
                    live_data = json.load(f, strict=False)
                break
            except (json.JSONDecodeError, IOError):
                time.sleep(0.2)

        if live_data is None: return

        try:
            attack_type, action, severity = "None", "No Action", "INFO"
            log_index = "N/A"
            log_col = "N/A"

            if len(live_data) > len(shard_info['data']):
                attack_type, action, severity = "Malicious Insertion", "Full Restoration", "HIGH"
                log_index = "End of File"
                log_col = "N/A (Row Added)"
                self.is_healing = True
                with open(backup_path, 'r') as f:
                    clean = json.load(f, strict=False)
                with open(live_path, 'w') as f:
                    json.dump(clean, f, indent=4)
            elif len(live_data) < len(shard_info['data']):
                attack_type, action, severity = "Structural Deletion", "Full Restoration", "CRITICAL"
                log_index = "Missing"
                log_col = "N/A (Row Dropped)"
                self.is_healing = True
                with open(backup_path, 'r') as f:
                    clean = json.load(f, strict=False)
                with open(live_path, 'w') as f:
                    json.dump(clean, f, indent=4)
            else:
                new_tree = MerkleTree(live_data)
                if shard_info['tree'].get_root() != new_tree.get_root():
                    attack_type = "Data Poisoning"
                    corrupted_index = shard_info['tree'].find_corrupted_index(new_tree.tree)
                    log_index = str(corrupted_index)
                    compromised_col = self.forensic_diff(filename, corrupted_index, live_data)
                    log_col = compromised_col
                    severity = "CRITICAL" if "Destroyed" in compromised_col else "MEDIUM"
                    action = f"Hot-Swapped Index {corrupted_index}"

                    if shard_info['backup_tree'].leaves[corrupted_index] == shard_info['tree'].leaves[corrupted_index]:
                        self.is_healing = True
                        live_data[corrupted_index] = shard_info['backup'][corrupted_index]
                        with open(live_path, 'w') as f:
                            json.dump(live_data, f, indent=4)
                    else:
                        action = "Healing Failed"
                        severity = "CRITICAL"

            if attack_type != "None":
                self.audit_chain.add_log(attack_type, log_index, action, log_col, severity)

                healed_data = None
                for attempt in range(5):
                    try:
                        with open(live_path, 'r') as f:
                            healed_data = json.load(f, strict=False)
                        break
                    except (json.JSONDecodeError, IOError):
                        time.sleep(0.2)

                if healed_data:
                    shard_info['data'] = healed_data
                    shard_info['tree'] = MerkleTree(healed_data)
                self.is_healing = False
        except Exception:
            pass

    def authorized_update(self, filename, row_index, new_plaintext_dict):
        self.is_healing = True
        live_path = os.path.join(LIVE_DIR, filename)
        backup_path = os.path.join(BACKUP_DIR, filename.replace('shard', 'backup'))
        shard_info = self.shards[filename]

        new_enc = self.cipher_suite.encrypt(json.dumps(new_plaintext_dict, sort_keys=True).encode('utf-8')).decode(
            'utf-8')

        live_data = shard_info['data']
        live_data[row_index] = new_enc
        with open(live_path, 'w') as f: json.dump(live_data, f, indent=4)

        backup_data = shard_info['backup']
        backup_data[row_index] = new_enc
        with open(backup_path, 'w') as f: json.dump(backup_data, f, indent=4)

        shard_info['tree'] = MerkleTree(live_data)
        shard_info['backup_tree'] = MerkleTree(backup_data)

        self.is_healing = False
        return True


if __name__ == "__main__":
    event_handler = GuardAgent()
    observer = Observer()
    observer.schedule(event_handler, path=LIVE_DIR, recursive=False)
    observer.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()