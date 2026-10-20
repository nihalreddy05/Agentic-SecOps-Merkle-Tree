import hashlib
import json
import os
import math
import time
from cryptography.fernet import Fernet
import pandas as pd


class MerkleTree:
    def __init__(self, data_list):
        self.leaves = [self.hash_data(data) for data in data_list]
        self.tree = self.build_tree(self.leaves)

    def hash_data(self, data):
        return hashlib.sha256(str(data).encode('utf-8')).hexdigest()

    def build_tree(self, leaves):
        tree = [leaves]
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(self.hash_data(left + right))
            tree.append(next_level)
            current_level = next_level
        return tree

    def get_root(self):
        return self.tree[-1][0] if self.tree else None

    def find_corrupted_index(self, new_tree_levels):
        def traverse(level, index):
            if level == 0: return index
            left_idx = index * 2
            right_idx = index * 2 + 1
            if left_idx < len(self.tree[level - 1]):
                if self.tree[level - 1][left_idx] != new_tree_levels[level - 1][left_idx]:
                    return traverse(level - 1, left_idx)
            if right_idx < len(self.tree[level - 1]):
                return traverse(level - 1, right_idx)
            return traverse(level - 1, left_idx)

        root_level = len(self.tree) - 1
        return traverse(root_level, 0)


def process_multiple_csvs(csv_paths):
    """Reads multiple CSVs, keeps them separate, splits EACH into 3 Shards, encrypts, and saves."""

    key = Fernet.generate_key()
    cipher_suite = Fernet(key)
    with open('secret.key', 'wb') as f:
        f.write(key)

    os.makedirs('live_db', exist_ok=True)
    os.makedirs('secure_backup', exist_ok=True)

    # Clear old files safely
    for old_file in os.listdir('live_db'):
        for attempt in range(10):
            try:
                os.remove(f'live_db/{old_file}')
                break
            except PermissionError:
                time.sleep(0.2)

    for old_file in os.listdir('secure_backup'):
        try:
            os.remove(f'secure_backup/{old_file}')
        except PermissionError:
            pass

    total_records = 0

    for path in csv_paths:
        df = pd.read_csv(path)
        # Standardize column names to lowercase just for safety
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_', regex=False)
        plaintext_db = df.to_dict(orient='records')

        encrypted_db = [cipher_suite.encrypt(json.dumps(r, sort_keys=True, default=str).encode('utf-8')).decode('utf-8')
                        for r in plaintext_db]

        # Extract base filename without extension to use in shard name
        base_name = os.path.basename(path).split('.')[0]
        # Clean base name to be filesystem safe (alphanumeric only)
        base_name = "".join([c for c in base_name if c.isalnum() or c in ('_', '-')])

        # Split THIS dataset into 3 Shards
        shard_size = math.ceil(len(encrypted_db) / 3)
        for i in range(3):
            start = i * shard_size
            end = start + shard_size
            shard_data = encrypted_db[start:end]

            shard_filename = f"shard_{base_name}_{i + 1}.json"
            backup_filename = f"backup_{base_name}_{i + 1}.json"

            with open(f'live_db/{shard_filename}', 'w') as f: json.dump(shard_data, f, indent=4)
            with open(f'secure_backup/{backup_filename}', 'w') as f: json.dump(shard_data, f, indent=4)

        total_records += len(plaintext_db)

    return total_records