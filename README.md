## TP 1 – Technologies Blockchain

### Objectif
Mettre en place une structure de bloc minimale en Python, créer un bloc de genèse, ajouter au moins un second bloc et vérifier la liaison entre les blocs via `previous_hash` et le `hash` calculé.

### Contenu du dépôt
- `blockchain_tp1.py` : script principal qui définit la classe `Block`, crée la blockchain, affiche les blocs et (optionnellement) vérifie la validité.

## TP 2 – Test du Hachage et de l'Immuabilité

### Objectif
Tester le hachage et l'immuabilité des blocs en :
1. Calculant un hachage et changeant les données pour voir la différence
2. Liant les blocs par leur hash (previous_hash)
3. Vérifiant le lien entre les blocs via JSON

### Contenu du dépôt
- `blockchain_tp2.py` : script qui implémente la méthode `compute_hash()`, teste l'immuabilité, crée une blockchain de 4 blocs (genèse + 3 blocs), et affiche la blockchain en JSON.

### Prérequis
- Python 3.8+

### Lancer les scripts
Dans le répertoire du projet :

**TP 1 :**
```bash
python blockchain_tp1.py
```

**TP 2 :**
```bash
python blockchain_tp2.py
```

### Structure d’un bloc
Un bloc contient :
- **index**: position du bloc dans la chaîne
- **timestamp**: horodatage de création
- **data**: données arbitraires (ex. transactions)
- **previous_hash**: hachage du bloc précédent (assure la liaison)
- **hash**: hachage du bloc courant (calculé à partir du contenu)

Extrait simplifié :
```python
class Block:
    def __init__(self, index, timestamp, data, previous_hash=""):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = ""
```

### Calcul du hachage (recommandé)
Pour que `previous_hash` pointe vers un vrai hachage, il faut calculer et stocker `hash` après la création de chaque bloc. Dans `blockchain_tp2.py`, le hash est automatiquement calculé dans le constructeur :

```python
import hashlib

def compute_hash(self):
    block_string = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}".encode()
    return hashlib.sha256(block_string).hexdigest()

# Le hash est automatiquement calculé dans le constructeur
def __init__(self, index, timestamp, data, previous_hash=""):
    # ... autres attributs ...
    self.hash = self.compute_hash()  # Calcul automatique
```

### Vérifier la liaison et la validité
Deux vérifications simples :
- **Liaison** : `blocN.previous_hash == blocN-1.hash`
- **Intégrité** : `blocN.hash == blocN.compute_hash()`

Helpers possibles :
```python
def is_block_valid(block, previous_block):
    if block.previous_hash != previous_block.hash:
        return False, "previous_hash ne correspond pas au hash du bloc précédent"
    if block.compute_hash() != block.hash:
        return False, "le hash stocké ne correspond pas au hash recalculé"
    return True, "ok"

def validate_chain(chain):
    if not chain:
        return True, "chaîne vide"
    if chain[0].compute_hash() != chain[0].hash:
        return False, "hash du bloc de genèse invalide"
    for i in range(1, len(chain)):
        ok, reason = is_block_valid(chain[i], chain[i - 1])
        if not ok:
            return False, f"bloc {i} invalide: {reason}"
    return True, "chaîne valide"
```

### Résultats attendus

**TP 1 :**
- Le bloc de genèse affiche un `hash` non vide et `previous_hash = "0"`.
- Le second bloc affiche `previous_hash` égal au `hash` du bloc de genèse.
- La validation de la chaîne (si ajoutée) doit indiquer qu'elle est valide.

**TP 2 :**
- Chaque bloc a un hash unique calculé avec SHA-256
- Les blocs sont liés via `previous_hash` (chaque bloc pointe vers le hash du précédent)
- Création d'une blockchain de 4 blocs (genèse + 3 blocs de transaction)
- Méthode `isDifferent()` pour comparer les blocs
- L'affichage JSON montre la structure complète de la blockchain
- Test d'immuabilité : modification des données change complètement le hash

### Changements récents dans blockchain_tp2.py

**Nouvelles fonctionnalités ajoutées :**
- **Calcul automatique du hash** : Le hash est maintenant calculé automatiquement dans le constructeur de la classe `Block`
- **Blockchain étendue** : Ajout d'un troisième bloc (bloc3) avec la transaction "Charlie envoie 2 BTC"
- **Méthode de comparaison** : Nouvelle méthode `isDifferent()` pour vérifier si deux blocs sont différents
- **Affichage amélioré** : Chaque bloc affiche maintenant sa méthode `isDifferent()` avec le bloc précédent
- **Sortie JSON complète** : Affichage de la blockchain complète au format JSON pour vérification

**Structure de la blockchain :**
1. Bloc de genèse (index 0)
2. Bloc 1 : "Alice envoie 5 BTC" (index 1)
3. Bloc 2 : "Bob envoie 3 BTC" (index 2)
4. Bloc 3 : "Charlie envoie 2 BTC" (index 3)

## TP 3 – Preuve de Travail (PoW), Validation et Minage

### Objectif
- Introduire un `nonce` et un niveau de difficulté pour la Preuve de Travail (PoW).
- Miner chaque bloc avant son ajout à la chaîne.
- Valider l’intégrité de la blockchain (hash, chaînage, respect de la PoW).
- Détecter la falsification en recalculant et en vérifiant les liens.

### Contenu du dépôt
- `blockchain_tp3.py` : implémente le minage (PoW), la validation stricte de la chaîne et une simulation de falsification.

### Lancer le script
```bash
python blockchain_tp3.py
```

### Principes implémentés
- **Nonce et minage** :
  - `Block.nonce` initialisé à 0 et inclus dans `compute_hash()`.
  - `mine_block(difficulty)`: incrémente le nonce jusqu’à ce que `hash` commence par `difficulty` zéros.
- **Blockchain avec difficulté** :
  - `Blockchain.difficulty = 4` (modifiable) et minage du bloc de genèse.
  - `add_block(data)`: construit le bloc (index auto, timestamp système, `previous_hash`), mine puis ajoute.
- **Validation** :
  - `is_chain_valid()` vérifie pour chaque bloc: intégrité du hash recalculé, lien `previous_hash`, et PoW (hash commence par `0` répété `difficulty`). Le genèse est aussi vérifié.

### Démonstration dans le script
1. Ajoute 3 blocs minés (Alice, Bob, Charlie) et affiche nonce + hash.
2. Valide la chaîne: attendu `True` si aucune falsification.
3. Simule une falsification (modifie `data` du bloc 1), puis revalide: attendu `False` avec message explicite.

### Résultats attendus (TP 3)
- Les hash minés commencent par `0000` (pour `difficulty=4`).
- La chaîne est valide avant falsification, invalide après modification d’un bloc sans re-minage en cascade.

### Dépannage

**TP 1 :**
- **`previous_hash` vide sur le second bloc** : assurez-vous d'avoir d'abord calculé et assigné `genesis_block.hash` avant de créer le second bloc.
- **Hashes identiques après modifications** : si vous changez les données, recalculer le `hash` du bloc concerné.

**TP 2 :**
- **`TypeError: Strings must be encoded before hashing`** : assurez-vous d'utiliser `.encode("utf-8")` ou `.encode()` avant de passer la chaîne à `hashlib.sha256()`
- **Hashes identiques** : vérifiez que chaque bloc a des données uniques (index, timestamp, data différents)

## TP 4 – Transactions, Récompense et Solde

### Objectif
- Introduire une classe `Transaction` pour modéliser les transferts entre adresses.
- Regrouper plusieurs transactions dans un même bloc.
- Gérer une file de transactions en attente et implémenter une récompense de minage.
- Calculer le solde de chaque adresse et valider la chaîne résultante.

### Contenu du dépôt
- `blockchain_tp4.py` : implémente les transactions, le minage des transactions en attente, la récompense du mineur et le calcul des soldes.

### Lancer le script
```bash
python blockchain_tp4.py
```

### Principes implémentés
- **Transactions** : `Transaction(from_addr, to_addr, amount)` via `@dataclass`. Une transaction de récompense utilise `from_addr=None`.
- **Blocs** : stockent une liste de transactions, un timestamp, un `nonce` et le `previous_hash`. Le hash est calculé à partir de tous ces éléments.
- **Pending transactions** : ajoutées avec `Blockchain.create_transaction()`, puis regroupées lors de l'appel à `mine_pending_transactions(miner_address)`.
- **Récompense** : après le minage d'un bloc, une transaction de récompense est ajoutée aux transactions en attente pour le mineur.
- **Soldes** : `get_balance_of_address(address)` parcourt tous les blocs pour déterminer le solde courant.
- **Validation** : `is_chain_valid()` vérifie l'intégrité de chaque bloc (hash et chaînage).

### Démonstration dans le script
1. Alice envoie 50 unités à Bob, Bob en envoie 25 à Charlie.
2. Miner `Miner1` valide les transactions : un bloc est ajouté et une récompense est programmée.
3. Un second minage inclut la récompense précédente, `Miner1` reçoit une nouvelle récompense.
4. Les soldes d'Alice, Bob, Charlie et du mineur sont affichés, puis la validité de la chaîne est vérifiée.

## TP 5 – Cryptographie, Signatures et Arbre de Merkle

### Objectif
- Implémenter la cryptographie asymétrique (RSA) pour la génération de clés et le chiffrement.
- Créer et vérifier des signatures numériques pour authentifier les transactions.
- Construire un arbre de Merkle pour garantir l'intégrité d'un ensemble de transactions.
- Intégrer les signatures et la racine Merkle dans les blocs de la blockchain.

### Contenu du dépôt
- `blockchain_tp5.py` : implémente la cryptographie RSA, les signatures numériques, l'arbre de Merkle et les blocs signés avec racine Merkle.

### Lancer le script
```bash
python blockchain_tp5.py
```

### Principes implémentés

#### Exercice 1 : Cryptographie asymétrique (RSA)
- **Génération de clés** : La classe `Wallet` génère des paires de clés RSA (2048 ou 4096 bits).
  - Comparaison des temps de génération entre différentes tailles de clés.
  - Une clé plus longue est plus sûre mais plus lente à générer.
- **Chiffrement et déchiffrement** :
  - `encrypt_message()` : chiffre un message avec la clé publique (padding OAEP).
  - `decrypt_message()` : déchiffre un message avec la clé privée.
  - Seule la clé privée peut déchiffrer un message chiffré avec la clé publique correspondante.

#### Exercice 2 : Signature numérique
- **Création de signature** :
  - `sign_message()` : signe un message avec la clé privée (padding PSS).
  - `signer_message()` : fonction utilitaire pour signer un message.
- **Vérification de signature** :
  - `verify_signature()` : vérifie une signature avec la clé publique.
  - `verifier_signature()` : fonction utilitaire pour vérifier une signature.
- **Intégrité** : Toute modification du message invalide la signature, garantissant l'authenticité et l'intégrité.

#### Exercice 3 : Arbre de Merkle
- **Construction de l'arbre** :
  - `make_leaf_hashes()` : crée les hash des feuilles (transactions).
  - `merkle_root()` : calcule la racine de l'arbre de Merkle en combinant les hash par paires.
  - Gestion des listes impaires (duplication du dernier élément).
- **Preuve d'inclusion** :
  - `merkle_proof()` : génère une preuve d'inclusion pour une transaction donnée.
  - `verify_proof()` : vérifie qu'une transaction est incluse dans l'arbre en utilisant la preuve.
- **Détection de modifications** : Toute modification d'une transaction change la racine Merkle, permettant de détecter les altérations.

#### Exercice 4 : Bloc signé avec Merkle Root
- **Structure du bloc** :
  - `Block` inclut maintenant : `index`, `timestamp`, `transactions`, `prev_hash`, `merkle_root`, `hash`, et `signature`.
  - La racine Merkle est calculée automatiquement à partir des transactions du bloc.
  - Le hash du bloc est calculé à partir du header (index, timestamp, merkle_root, prev_hash).
- **Signature du mineur** :
  - Chaque bloc est signé par le mineur avec sa clé privée lors de la création.
  - `verify_block()` : vérifie la signature et l'intégrité du bloc.
- **Blockchain mise à jour** :
  - `Blockchain.mine_pending_transactions()` accepte maintenant un `Wallet` de mineur.
  - Les blocs sont automatiquement signés lors du minage.
  - `is_chain_valid()` vérifie les signatures de tous les blocs.

### Démonstration dans le script

**Exercice 1 :**
1. Génération de clés RSA 2048 bits et mesure du temps.
2. Génération de clés RSA 4096 bits et comparaison (environ 13-27x plus long).
3. Chiffrement et déchiffrement d'un message.

**Exercice 2 :**
1. Création d'une signature pour une transaction.
2. Vérification de la signature (valide).
3. Test avec message modifié (signature invalide).
4. Test des fonctions utilitaires.

**Exercice 3 :**
1. Construction d'un arbre de Merkle à partir de transactions.
2. Génération et vérification d'une preuve d'inclusion.
3. Test avec transaction modifiée (racine Merkle différente).

**Exercice 4 :**
1. Création de blocs signés avec racine Merkle.
2. Minage de transactions et ajout à la blockchain.
3. Vérification des signatures de chaque bloc.
4. Validation de la chaîne complète.
5. Test de falsification (modification d'une transaction invalide le bloc).
6. Affichage des soldes des participants.

### Résultats attendus (TP 5)
- Les clés RSA 4096 bits prennent significativement plus de temps à générer que les 2048 bits.
- Les messages peuvent être chiffrés avec la clé publique et déchiffrés uniquement avec la clé privée.
- Les signatures sont valides pour les messages originaux et invalides après modification.
- L'arbre de Merkle produit une racine unique pour chaque ensemble de transactions.
- Les preuves d'inclusion permettent de vérifier qu'une transaction est dans l'arbre sans avoir toutes les transactions.
- Les blocs signés sont vérifiables et toute altération invalide la signature et la racine Merkle.
- La chaîne est valide avant falsification, invalide après modification d'un bloc.

### Fonctionnalités principales

**Classe Wallet :**
```python
wallet = Wallet(key_size=2048)  # Génère une paire de clés RSA
ciphertext = wallet.encrypt_message(message)  # Chiffre un message
plaintext = wallet.decrypt_message(ciphertext)  # Déchiffre un message
signature = wallet.sign_message(message)  # Signe un message
is_valid = wallet.verify_signature(message, signature)  # Vérifie une signature
```

**Fonctions Merkle Tree :**
```python
leaf_hashes = make_leaf_hashes(transactions)  # Crée les hash des feuilles
root = merkle_root(leaf_hashes)  # Calcule la racine Merkle
proof = merkle_proof(leaf_hashes, index)  # Génère une preuve d'inclusion
is_valid = verify_proof(leaf_hash, proof, root)  # Vérifie la preuve
```

**Bloc avec Merkle Root et Signature :**
```python
block = Block(index, transactions, prev_hash, miner_private_key)
is_valid = block.verify_block(miner_public_key)  # Vérifie la signature
```

### Dépannage

**TP 5 :**
- **`ModuleNotFoundError: No module named 'cryptography'`** : Installez la bibliothèque avec `pip install cryptography`
- **Erreur de signature** : Assurez-vous d'utiliser la même clé publique que celle correspondant à la clé privée qui a signé.
- **Racine Merkle différente** : Vérifiez que les transactions sont dans le même ordre et format lors du calcul de la racine.
- **Signature invalide après modification** : C'est normal ! Toute modification d'un bloc invalide sa signature, ce qui garantit l'intégrité.



