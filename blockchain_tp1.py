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
        self.hash = ""


if __name__ == "__main__":
    
    genesis_block = Block(
        0,
        "2025-10-12 00:00",
        "Bloc de genèse",
        previous_hash="0",
    )

    blockchain = [genesis_block]

    print("--------------------------------")
    print("Genesis Block")
    print("Index:", genesis_block.index)
    print("Timestamp:", genesis_block.timestamp)
    print("Données:", genesis_block.data)
    print("Previous Hash:", genesis_block.previous_hash)
    print("Hash:", genesis_block.hash)  # empty for now

    bloc1 = Block(
        1,
        "2025-10-12 00:05",
        "Alice envoie 5 BTC",
        previous_hash=genesis_block.hash,
    )
    blockchain.append(bloc1)

    print("--------------------------------")
    print("Index:", bloc1.index)
    print("Timestamp:", bloc1.timestamp)
    print("Données:", bloc1.data)
    print("Previous Hash:", bloc1.previous_hash)
    print("Hash:", bloc1.hash)

    bloc2 = Block(
        2,
        "2025-10-12 00:10",
        "Bob envoie 3 BTC",
        previous_hash=bloc1.hash,
    )
    blockchain.append(bloc2)

    print("--------------------------------")
    print("Index:", bloc2.index)
    print("Timestamp:", bloc2.timestamp)
    print("Données:", bloc2.data)
    print("Previous Hash:", bloc2.previous_hash)
    print("Hash:", bloc2.hash)

    bloc3 = Block(
        3,
        "2025-10-12 00:15",
        "Charlie envoie 2 BTC",
        previous_hash=bloc2.hash,
    )
    blockchain.append(bloc3)

    print("--------------------------------")
    print("Index:", bloc3.index)
    print("Timestamp:", bloc3.timestamp)
    print("Données:", bloc3.data)
    print("Previous Hash:", bloc3.previous_hash)
    print("Hash:", bloc3.hash)
    # Display the full chain
    for bloc in blockchain:
        print(
            f"Bloc {bloc.index} : data={bloc.data}, prev_hash={bloc.previous_hash}, hash={bloc.hash}"
        )


