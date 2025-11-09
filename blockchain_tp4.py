import hashlib
import time
from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class Transaction:
    """Représente un transfert de valeur entre deux adresses."""

    from_addr: Optional[str]
    to_addr: str
    amount: float


class Block:
    """Bloc contenant une liste de transactions et supportant la preuve de travail."""

    def __init__(self, timestamp: float, transactions: List[Transaction], previous_hash: str = ""):
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.create_hash()

    def create_hash(self) -> str:
        block_string = (
            str(self.previous_hash)
            + str(self.timestamp)
            + str([asdict(t) for t in self.transactions])
            + str(self.nonce)
        ).encode()
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty: int) -> None:
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.create_hash()
        print(f"Bloc miné ! Nonce={self.nonce}, Hash={self.hash}")


class Blockchain:
    """Blockchain simplifiée avec transactions, récompense et gestion de solde."""

    def __init__(self, difficulty: int = 2, mining_reward: float = 10.0):
        self.chain: List[Block] = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.pending_transactions: List[Transaction] = []
        self.mining_reward = mining_reward

    def create_genesis_block(self) -> Block:
        return Block(timestamp=time.time(), transactions=[], previous_hash="0")

    def get_last_block(self) -> Block:
        return self.chain[-1]

    def create_transaction(self, transaction: Transaction) -> None:
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, miner_address: str) -> None:
        if not self.pending_transactions:
            print("Aucune transaction en attente à miner.")
            return

        block = Block(
            timestamp=time.time(),
            transactions=self.pending_transactions.copy(),
            previous_hash=self.get_last_block().hash,
        )
        block.mine_block(self.difficulty)
        self.chain.append(block)
        print("Bloc validé et ajouté à la chaîne.")

        # La récompense est ajoutée aux transactions en attente pour le prochain bloc
        self.pending_transactions = [
            Transaction(from_addr=None, to_addr=miner_address, amount=self.mining_reward)
        ]

    def get_balance_of_address(self, address: str) -> float:
        balance = 0.0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.from_addr == address:
                    balance -= transaction.amount
                if transaction.to_addr == address:
                    balance += transaction.amount
        return balance

    def is_chain_valid(self) -> bool:
        for index in range(1, len(self.chain)):
            current_block = self.chain[index]
            previous_block = self.chain[index - 1]

            if current_block.hash != current_block.create_hash():
                return False
            if current_block.previous_hash != previous_block.hash:
                return False
        return True


def display_chain(blockchain: Blockchain) -> None:
    print("===== BLOCKCHAIN =====")
    for idx, block in enumerate(blockchain.chain):
        print(f"Bloc {idx}")
        print(f"  Timestamp        : {block.timestamp}")
        print(f"  Previous Hash    : {block.previous_hash}")
        print(f"  Hash             : {block.hash}")
        print(f"  Nonce            : {block.nonce}")
        print(f"  Transactions ({len(block.transactions)}) :")
        if not block.transactions:
            print("    (aucune transaction)")
        for tx in block.transactions:
            print(f"    De {tx.from_addr} vers {tx.to_addr} montant {tx.amount}")
        print("-------------------------")


if __name__ == "__main__":
    blockchain = Blockchain(difficulty=2, mining_reward=10.0)

    print("=== Création des transactions initiales ===")
    blockchain.create_transaction(Transaction("Alice", "Bob", 50))
    blockchain.create_transaction(Transaction("Bob", "Charlie", 25))

    print("\n=== Minage des transactions en attente par Miner1 ===")
    blockchain.mine_pending_transactions("Miner1")
    print(f"Solde de Miner1 : {blockchain.get_balance_of_address('Miner1')}")

    print("\n=== Minage du bloc récompense par Miner1 ===")
    blockchain.mine_pending_transactions("Miner1")
    print(f"Solde de Miner1 : {blockchain.get_balance_of_address('Miner1')}")

    print("\n=== Solde des autres participants ===")
    print(f"Solde d'Alice   : {blockchain.get_balance_of_address('Alice')}")
    print(f"Solde de Bob    : {blockchain.get_balance_of_address('Bob')}")
    print(f"Solde de Charlie: {blockchain.get_balance_of_address('Charlie')}")

    print("\n=== Validation de la chaîne ===")
    print(f"Chaîne valide ? {blockchain.is_chain_valid()}")

    print()
    display_chain(blockchain)
