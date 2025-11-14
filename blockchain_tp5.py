import hashlib
import time
from dataclasses import dataclass, asdict
from typing import List, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


@dataclass
class Transaction:
    """Représente un transfert de valeur entre deux adresses."""
    
    from_addr: Optional[str]
    to_addr: str
    amount: float


class Wallet:
    """Portefeuille avec génération de clés RSA pour la cryptographie."""
    
    def __init__(self, key_size: int = 2048, verbose: bool = True):
        # Génération d'une paire de clés RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()
        if verbose:
            print(f"Clés RSA {key_size} bits générées avec succès")
    
    def encrypt_message(self, message: bytes) -> bytes:
        """Chiffre un message avec la clé publique."""
        ciphertext = self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def decrypt_message(self, ciphertext: bytes) -> bytes:
        """Déchiffre un message avec la clé privée."""
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    def sign_message(self, message: bytes) -> bytes:
        """Signe un message avec la clé privée."""
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, message: bytes, signature: bytes) -> bool:
        """Vérifie une signature avec la clé publique."""
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


# Fonctions utilitaires pour les signatures (Exercice 2)
def signer_message(privkey, msg: bytes) -> bytes:
    """Retourne la signature RSA du message donné."""
    return privkey.sign(
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verifier_signature(pubkey, msg: bytes, sig: bytes) -> bool:
    """Retourne True si la signature est valide, False sinon."""
    try:
        pubkey.verify(
            sig,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# Exercice 3 : Arbre de Merkle
def sha256_hex(data: bytes) -> str:
    """Calcule le hash SHA256 et retourne l'hexadécimal."""
    return hashlib.sha256(data).hexdigest()


def hash_pair(left: str, right: str) -> str:
    """Combine deux hash et retourne le hash du résultat."""
    return sha256_hex(bytes.fromhex(left) + bytes.fromhex(right))


def make_leaf_hashes(transactions: List[str]) -> List[str]:
    """Crée les hash des feuilles (transactions)."""
    return [sha256_hex(tx.encode()) for tx in transactions]


def merkle_root(leaf_hashes: List[str]) -> str:
    """Calcule la racine de l'arbre de Merkle."""
    if not leaf_hashes:
        return ''
    
    current = leaf_hashes.copy()
    while len(current) > 1:
        # Si le nombre de nœuds est impair, dupliquer le dernier
        if len(current) % 2 == 1:
            current.append(current[-1])
        # Combiner les paires
        current = [hash_pair(current[i], current[i+1]) for i in range(0, len(current), 2)]
    
    return current[0]


def merkle_proof(leaf_hashes: List[str], index: int) -> List[tuple]:
    """Génère une preuve d'inclusion pour une transaction donnée."""
    proof = []
    idx = index
    current = leaf_hashes.copy()
    
    while len(current) > 1:
        # Si le nombre de nœuds est impair, dupliquer le dernier
        if len(current) % 2 == 1:
            current.append(current[-1])
        
        # Trouver le frère (sibling) - utiliser XOR pour inverser le dernier bit
        sibling_idx = idx ^ 1
        if sibling_idx < len(current):
            sibling_hash = current[sibling_idx]
            is_left = sibling_idx < idx
            proof.append((sibling_hash, is_left))
        
        # Passer au niveau supérieur
        idx = idx // 2
        current = [hash_pair(current[i], current[i+1]) for i in range(0, len(current), 2)]
    
    return proof


def verify_proof(leaf_hash: str, proof: List[tuple], root: str) -> bool:
    """Vérifie une preuve d'inclusion Merkle."""
    computed = leaf_hash
    for sibling, is_left in proof:
        if is_left:
            computed = hash_pair(sibling, computed)
        else:
            computed = hash_pair(computed, sibling)
    return computed == root


class Block:
    """Bloc contenant une liste de transactions, Merkle root et signature du mineur."""

    def __init__(self, index: int, transactions: List[Transaction], prev_hash: str, 
                 miner_private_key=None, timestamp: float = None):
        self.index = index
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.transactions = transactions
        self.prev_hash = prev_hash
        
        # Convertir les transactions en format string pour le Merkle Tree
        transaction_strings = [
            f"{tx.from_addr}->{tx.to_addr}:{tx.amount}" 
            if tx.from_addr else f"REWARD->{tx.to_addr}:{tx.amount}"
            for tx in transactions
        ]
        
        # Calculer la racine Merkle
        if transaction_strings:
            leaf_hashes = make_leaf_hashes(transaction_strings)
            self.merkle_root = merkle_root(leaf_hashes)
        else:
            self.merkle_root = ""
        
        # Hash global du bloc (header)
        header = f"{self.index}{self.timestamp}{self.merkle_root}{self.prev_hash}".encode()
        self.hash = sha256_hex(header)
        
        # Signature du mineur (si une clé privée est fournie)
        if miner_private_key:
            self.signature = signer_message(miner_private_key, self.hash.encode())
        else:
            self.signature = None
    
    def verify_block(self, miner_public_key) -> bool:
        """Vérifie la signature et la validité interne du bloc."""
        if self.signature is None:
            return False
        
        # Recalculer le hash du header
        header = f"{self.index}{self.timestamp}{self.merkle_root}{self.prev_hash}".encode()
        header_hash = sha256_hex(header)
        
        # Vérifier que le hash correspond
        if self.hash != header_hash:
            return False
        
        # Vérifier la signature
        return verifier_signature(miner_public_key, header_hash.encode(), self.signature)
    
    def get_header_hash(self) -> str:
        """Retourne le hash du header du bloc."""
        header = f"{self.index}{self.timestamp}{self.merkle_root}{self.prev_hash}".encode()
        return sha256_hex(header)


class Blockchain:
    """Blockchain simplifiée avec transactions, Merkle root et signatures."""

    def __init__(self, mining_reward: float = 10.0):
        self.chain: List[Block] = [self.create_genesis_block()]
        self.pending_transactions: List[Transaction] = []
        self.mining_reward = mining_reward

    def create_genesis_block(self) -> Block:
        """Crée le bloc de genèse (sans signature)."""
        return Block(index=0, transactions=[], prev_hash="0", miner_private_key=None)

    def get_last_block(self) -> Block:
        return self.chain[-1]

    def create_transaction(self, transaction: Transaction) -> None:
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, miner_wallet: Wallet, miner_address: str = None) -> None:
        """Mine les transactions en attente avec le wallet du mineur."""
        if not self.pending_transactions:
            print("Aucune transaction en attente à miner.")
            return

        last_block = self.get_last_block()
        new_index = last_block.index + 1
        
        # Créer le nouveau bloc avec signature du mineur
        block = Block(
            index=new_index,
            transactions=self.pending_transactions.copy(),
            prev_hash=last_block.hash,
            miner_private_key=miner_wallet.private_key
        )
        
        self.chain.append(block)
        print(f"Bloc {new_index} validé et ajouté à la chaîne.")
        print(f"  Merkle Root: {block.merkle_root}")
        print(f"  Hash: {block.hash}")
        print(f"  Signature valide: {block.verify_block(miner_wallet.public_key)}")

        # La récompense est ajoutée aux transactions en attente pour le prochain bloc
        reward_address = miner_address if miner_address else "Miner"
        self.pending_transactions = [
            Transaction(from_addr=None, to_addr=reward_address, amount=self.mining_reward)
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

    def is_chain_valid(self, miner_public_key) -> bool:
        """Vérifie la validité de la chaîne (chaînage et signatures)."""
        for index in range(1, len(self.chain)):
            current_block = self.chain[index]
            previous_block = self.chain[index - 1]

            # Vérifier le chaînage
            if current_block.prev_hash != previous_block.hash:
                return False
            
            # Vérifier la signature du bloc
            if not current_block.verify_block(miner_public_key):
                return False
            
            # Vérifier que le hash correspond
            if current_block.hash != current_block.get_header_hash():
                return False
        
        return True


def display_chain(blockchain: Blockchain) -> None:
    print("===== BLOCKCHAIN =====")
    for block in blockchain.chain:
        print(f"Bloc {block.index}")
        print(f"  Timestamp        : {block.timestamp}")
        print(f"  Previous Hash    : {block.prev_hash}")
        print(f"  Hash             : {block.hash}")
        print(f"  Merkle Root      : {block.merkle_root}")
        print(f"  Signature        : {'Présente' if block.signature else 'Absente'}")
        print(f"  Transactions ({len(block.transactions)}) :")
        if not block.transactions:
            print("    (aucune transaction)")
        for tx in block.transactions:
            from_addr = tx.from_addr if tx.from_addr else "REWARD"
            print(f"    De {from_addr} vers {tx.to_addr} montant {tx.amount}")
        print("-------------------------")


if __name__ == "__main__":
    print("=" * 70)
    print("EXERCICE 1 : Cryptographie asymétrique (RSA)")
    print("=" * 70)
    
    # Exercice 1.1 : Génération de clés RSA 2048 bits
    print("\n1.1 Génération de clés RSA 2048 bits")
    start_time = time.time()
    wallet_2048 = Wallet(key_size=2048, verbose=False)
    time_2048 = time.time() - start_time
    print(f"Temps de génération: {time_2048:.4f} secondes")
    
    # Exercice 1.2 : Génération de clés RSA 4096 bits
    print("\n1.2 Génération de clés RSA 4096 bits")
    start_time = time.time()
    wallet_4096 = Wallet(key_size=4096, verbose=False)
    time_4096 = time.time() - start_time
    print(f"Temps de génération: {time_4096:.4f} secondes")
    print(f"Ratio: {time_4096/time_2048:.2f}x plus long")
    
    # Exercice 1.3 : Chiffrement et déchiffrement
    print("\n1.3 Chiffrement et déchiffrement d'un message")
    message = b"Blockchain et cryptographie asymetrique"
    print(f"Message initial: {message.decode()}")
    
    ciphertext = wallet_2048.encrypt_message(message)
    print(f"Message chiffré (hex): {ciphertext.hex()[:80]}...")
    
    plaintext = wallet_2048.decrypt_message(ciphertext)
    print(f"Message déchiffré: {plaintext.decode()}")
    print("[OK] Le message peut etre dechiffre uniquement avec la cle privee")
    
    print("\n" + "=" * 70)
    print("EXERCICE 2 : Signature numérique")
    print("=" * 70)
    
    # Exercice 2.1 : Création d'une signature
    print("\n2.1 Création d'une signature")
    message = b"Transaction : Alice -> Bob : 3 BTC"
    signature = wallet_2048.sign_message(message)
    print(f"Signature (hex): {signature.hex()[:80]}...")
    
    # Exercice 2.2 : Vérification de la signature
    print("\n2.2 Vérification de la signature")
    is_valid = wallet_2048.verify_signature(message, signature)
    print(f"Signature valide: {is_valid}")
    print("[OK] Le message est authentique")
    
    # Exercice 2.3 : Test avec message modifié
    print("\n2.3 Test avec message modifié")
    modified_message = b"Transaction : Alice -> Bob : 30 BTC"  # Montant modifié
    is_valid_modified = wallet_2048.verify_signature(modified_message, signature)
    print(f"Signature valide après modification: {is_valid_modified}")
    print("[OK] La signature est invalide après modification du message")
    
    # Exercice 2.4 : Fonctions utilitaires
    print("\n2.4 Fonctions utilitaires")
    test_msg = b"Test de signature"
    test_sig = signer_message(wallet_2048.private_key, test_msg)
    is_valid_test = verifier_signature(wallet_2048.public_key, test_msg, test_sig)
    print(f"Signature valide avec fonctions utilitaires: {is_valid_test}")
    
    print("\n" + "=" * 70)
    print("EXERCICE 3 : Arbre de Merkle")
    print("=" * 70)
    
    # Exercice 3.1 : Construction du Merkle Tree
    print("\n3.1 Construction du Merkle Tree")
    transactions = ["Alice->Bob:5", "Bob->Charlie:3", "Dave->Eve:1"]
    print(f"Transactions: {transactions}")
    
    leaf_hashes = make_leaf_hashes(transactions)
    print(f"Hash des feuilles: {len(leaf_hashes)} feuilles")
    
    root = merkle_root(leaf_hashes)
    print(f"Merkle Root: {root}")
    
    # Exercice 3.2 : Preuve d'inclusion
    print("\n3.2 Preuve d'inclusion")
    transaction_index = 1
    print(f"Transaction à vérifier: {transactions[transaction_index]}")
    
    proof = merkle_proof(leaf_hashes, transaction_index)
    print(f"Preuve générée: {len(proof)} éléments")
    
    is_proof_valid = verify_proof(leaf_hashes[transaction_index], proof, root)
    print(f"Preuve valide: {is_proof_valid}")
    print("[OK] La transaction est incluse dans l'arbre de Merkle")
    
    # Exercice 3.3 : Test avec transaction modifiée
    print("\n3.3 Test avec transaction modifiée")
    modified_transactions = ["Alice->Bob:5", "Bob->Charlie:30", "Dave->Eve:1"]  # Montant modifié
    modified_leaf_hashes = make_leaf_hashes(modified_transactions)
    modified_root = merkle_root(modified_leaf_hashes)
    print(f"Nouveau Merkle Root: {modified_root}")
    print(f"Racine différente: {modified_root != root}")
    print("[OK] Toute modification invalide la racine Merkle")
    
    print("\n" + "=" * 70)
    print("EXERCICE 4 : Bloc signé avec Merkle Root")
    print("=" * 70)
    
    # Exercice 4.1 : Création de blocs signés
    print("\n4.1 Création de blocs signés")
    miner_wallet = Wallet(key_size=2048, verbose=False)
    
    # Créer une blockchain
    blockchain = Blockchain(mining_reward=10.0)
    
    # Créer des transactions
    print("\nCréation de transactions...")
    blockchain.create_transaction(Transaction("Alice", "Bob", 50))
    blockchain.create_transaction(Transaction("Bob", "Charlie", 25))
    
    # Miner le premier bloc
    print("\nMinage du bloc 1...")
    blockchain.mine_pending_transactions(miner_wallet, "Miner1")
    
    # Miner le deuxième bloc (récompense)
    print("\nMinage du bloc 2 (récompense)...")
    blockchain.mine_pending_transactions(miner_wallet, "Miner1")
    
    # Afficher la blockchain
    print("\n4.2 Affichage de la blockchain")
    display_chain(blockchain)
    
    # Exercice 4.3 : Vérification des blocs
    print("\n4.3 Vérification des blocs")
    for i, block in enumerate(blockchain.chain):
        if block.signature:
            is_valid_block = block.verify_block(miner_wallet.public_key)
            print(f"Bloc {i} - Signature valide: {is_valid_block}")
    
    # Exercice 4.4 : Validation de la chaîne
    print("\n4.4 Validation de la chaîne")
    is_chain_valid = blockchain.is_chain_valid(miner_wallet.public_key)
    print(f"Chaîne valide: {is_chain_valid}")
    
    # Exercice 4.5 : Test de falsification
    print("\n4.5 Test de falsification")
    if len(blockchain.chain) > 1:
        # Modifier une transaction dans un bloc
        original_tx = blockchain.chain[1].transactions[0]
        blockchain.chain[1].transactions[0] = Transaction("Alice", "Bob", 500)  # Montant modifié
        
        # Recalculer la racine Merkle
        transaction_strings = [
            f"{tx.from_addr}->{tx.to_addr}:{tx.amount}" 
            if tx.from_addr else f"REWARD->{tx.to_addr}:{tx.amount}"
            for tx in blockchain.chain[1].transactions
        ]
        leaf_hashes_new = make_leaf_hashes(transaction_strings)
        blockchain.chain[1].merkle_root = merkle_root(leaf_hashes_new)
        
        # Recalculer le hash
        header = f"{blockchain.chain[1].index}{blockchain.chain[1].timestamp}{blockchain.chain[1].merkle_root}{blockchain.chain[1].prev_hash}".encode()
        blockchain.chain[1].hash = sha256_hex(header)
        
        print("Transaction modifiée dans le bloc 1")
        is_chain_valid_after_tamper = blockchain.is_chain_valid(miner_wallet.public_key)
        print(f"Chaine valide après falsification: {is_chain_valid_after_tamper}")
        print("[OK] Toute alteration invalide le bloc")
        
        # Restaurer la transaction originale pour la démo
        blockchain.chain[1].transactions[0] = original_tx
        transaction_strings_orig = [
            f"{tx.from_addr}->{tx.to_addr}:{tx.amount}" 
            if tx.from_addr else f"REWARD->{tx.to_addr}:{tx.amount}"
            for tx in blockchain.chain[1].transactions
        ]
        leaf_hashes_orig = make_leaf_hashes(transaction_strings_orig)
        blockchain.chain[1].merkle_root = merkle_root(leaf_hashes_orig)
        header_orig = f"{blockchain.chain[1].index}{blockchain.chain[1].timestamp}{blockchain.chain[1].merkle_root}{blockchain.chain[1].prev_hash}".encode()
        blockchain.chain[1].hash = sha256_hex(header_orig)
    
    # Exercice 4.6 : Soldes
    print("\n4.6 Soldes des participants")
    print(f"Solde de Miner1: {blockchain.get_balance_of_address('Miner1')}")
    print(f"Solde d'Alice: {blockchain.get_balance_of_address('Alice')}")
    print(f"Solde de Bob: {blockchain.get_balance_of_address('Bob')}")
    print(f"Solde de Charlie: {blockchain.get_balance_of_address('Charlie')}")
    
    print("\n" + "=" * 70)
    print("Tous les exercices sont terminés avec succès!")
    print("=" * 70)
