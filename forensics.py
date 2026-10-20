import hashlib
import time

class AuditBlock:
    def __init__(self, attack_type, index, action, compromised_column, severity, prev_hash):
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.attack_type = attack_type
        self.index = index
        self.action = action
        self.compromised_column = compromised_column
        self.severity = severity
        self.prev_hash = prev_hash
        self.current_hash = self.compute_hash()
        self.next = None

    def compute_hash(self):
        data = f"{self.timestamp}{self.attack_type}{self.index}{self.action}{self.compromised_column}{self.severity}{self.prev_hash}"
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

class AuditChain:
    def __init__(self):
        self.head = AuditBlock("System Init", "N/A", "Guard Agent Initialized", "N/A", "INFO", "0" * 64)
        self.tail = self.head

    def add_log(self, attack_type, index, action, compromised_column, severity):
        new_block = AuditBlock(attack_type, index, action, compromised_column, severity, self.tail.current_hash)
        self.tail.next = new_block
        self.tail = new_block