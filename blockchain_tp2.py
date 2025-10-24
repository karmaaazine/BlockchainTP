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
        # Hash of the current block (to be computed later)
        self.hash = self.compute_hash()

    def compute_hash(self):
        # Concatenate the block data to form a string
        block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}".encode()
        return hashlib.sha256(block_string).hexdigest()

    def isDifferent(self, other):
        return self.previous_hash != other.hash


class Blockchain:
    def __init__(self):
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
        self.chain.append(genesis_block)
        return genesis_block
    
    def add_block(self, data):
        """Add a new block to the blockchain with automatic index and timestamp"""
        previous_block = self.chain[-1]
        new_block = Block(
            index=len(self.chain),  # Automatic index based on chain length
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # Current system time
            data=data,
            previous_hash=previous_block.hash
        )
        self.chain.append(new_block)
        return new_block
    
    def get_latest_block(self):
        """Get the latest block in the chain"""
        return self.chain[-1]
    
    def is_chain_valid(self):
        """Check if the blockchain is valid"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Check if current block's previous_hash matches previous block's hash
            if current_block.previous_hash != previous_block.hash:
                return False, f"Block {current_block.index} has invalid previous_hash"
            
            # Check if current block's hash is valid
            if current_block.hash != current_block.compute_hash():
                return False, f"Block {current_block.index} has invalid hash"
        
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


