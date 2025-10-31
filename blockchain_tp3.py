import hashlib
import json
from datetime import datetime

class Block:
    def __init__(self, index, timestamp, data, previous_hash=""):
        # Position of the block in the chain
        self.index = index
        # Creation timestamp
        self.timestamp = timestamp
        # Arbitrary block data (e.g., transactions)
        self.data = data
        # Hash of the previous block (link)
        self.previous_hash = previous_hash
        # Proof-of-work nonce
        self.nonce = 0
        # Hash of the current block (set after mining)
        self.hash = self.compute_hash()

    def compute_hash(self):
        # Concatenate the block data to form a string (including nonce)
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}{self.nonce}".encode()
        return hashlib.sha256(block_string).hexdigest()

    def isDifferent(self, other):
        return self.previous_hash != other.hash

    def mine_block(self, difficulty):
        # Tente des nonces jusqu'à ce que le hash commence par '0'*difficulty
        target = '0' * difficulty
        while True:
            self.hash = self.compute_hash()
            if self.hash.startswith(target):
                break
            self.nonce += 1
        print(f"Bloc miné ! Nonce final : {self.nonce}, Hash : {self.hash}")

    

class Blockchain:
    def __init__(self):
        # Initialize difficulty before creating genesis block
        self.difficulty = 4
        # Start with empty chain, then append the mined genesis block
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """Create the first block (genesis block)"""
        genesis_block = Block(
            index=0,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data="Bloc de genèse",
            previous_hash="0"
        )
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)
        return genesis_block
    
    def get_last_block(self):
        return self.chain[-1]
    
    def add_block(self, data):
        previous_block = self.get_last_block()
        new_block = Block(
            index=previous_block.index + 1,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            data=data,
            previous_hash=previous_block.hash
        )
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        return new_block
    
    def get_latest_block(self):
        """Get the latest block in the chain"""
        return self.chain[-1]
    
    def is_chain_valid(self):
        """Check if the blockchain is valid"""
        target = '0' * self.difficulty
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Check link
            if current_block.previous_hash != previous_block.hash:
                return False, f"Block {current_block.index} has invalid previous_hash"
            
            # Check hash integrity (including nonce)
            if current_block.hash != current_block.compute_hash():
                return False, f"Block {current_block.index} has invalid hash"
            
            # Check proof-of-work
            if not current_block.hash.startswith(target):
                return False, f"Block {current_block.index} does not satisfy proof-of-work"
        
        # Optionally check genesis PoW as well
        if len(self.chain) > 0 and not self.chain[0].hash.startswith(target):
            return False, "Genesis block does not satisfy proof-of-work"
        return True, "Blockchain is valid"

if __name__ == "__main__":
    # Create automated blockchain
    blockchain = Blockchain()
    
    print("--------------------------------")
    print("Genesis Block (Automatically Created)")
    genesis_block = blockchain.get_latest_block()
    print("Index:", genesis_block.index)
    print("Timestamp:", genesis_block.timestamp)
    print("Données:", genesis_block.data)
    print("Previous Hash:", genesis_block.previous_hash)
    print("Hash:", genesis_block.hash)

    # Add blocks automatically
    print("--------------------------------")
    print("Adding blocks automatically...")
    
    # Add first transaction block
    bloc1 = blockchain.add_block("Alice envoie 5 BTC")
    print("Index:", bloc1.index)
    print("Timestamp:", bloc1.timestamp)
    print("Données:", bloc1.data)
    print("Previous Hash:", bloc1.previous_hash)
    print("Hash:", bloc1.hash)
    print("Is Different:", bloc1.isDifferent(genesis_block))

    # Add second transaction block
    bloc2 = blockchain.add_block("Bob envoie 3 BTC")
    print("--------------------------------")
    print("Index:", bloc2.index)
    print("Timestamp:", bloc2.timestamp)
    print("Données:", bloc2.data)
    print("Previous Hash:", bloc2.previous_hash)
    print("Hash:", bloc2.hash)
    print("Is Different:", bloc2.isDifferent(bloc1))

    # Add third transaction block
    bloc3 = blockchain.add_block("Charlie envoie 2 BTC")
    print("--------------------------------")
    print("Index:", bloc3.index)
    print("Timestamp:", bloc3.timestamp)
    print("Données:", bloc3.data)
    print("Previous Hash:", bloc3.previous_hash)
    print("Hash:", bloc3.hash)
    print("Is Different:", bloc3.isDifferent(bloc2))

    # Display the full chain
    print("--------------------------------")
    print("Blockchain")
    for bloc in blockchain.chain:
        print(
            f"Bloc {bloc.index} : data={bloc.data}, prev_hash={bloc.previous_hash}, hash={bloc.hash}"
        )
    
    # Validate the blockchain
    print("--------------------------------")
    print("Blockchain Validation")
    is_valid, message = blockchain.is_chain_valid()
    print(f"Blockchain is valid: {is_valid}")
    print(f"Message: {message}")

    # Also display as JSON for verification
    print("--------------------------------")
    print("Blockchain as JSON")
    print(json.dumps([b.__dict__ for b in blockchain.chain], indent=4, ensure_ascii=False))

    # Simulate tampering: modify data of an existing block and validate again
    print("--------------------------------")
    print("Tamper Simulation: modify block 1 data")
    if len(blockchain.chain) > 1:
        original_data = blockchain.chain[1].data
        blockchain.chain[1].data = original_data + " (modified)"
        print(f"Block 1 data changed from '{original_data}' to '{blockchain.chain[1].data}'")
        is_valid_after_tamper, message_after = blockchain.is_chain_valid()
        print(f"Blockchain is valid after tampering: {is_valid_after_tamper}")
        print(f"Message: {message_after}")
