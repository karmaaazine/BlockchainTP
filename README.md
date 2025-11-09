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



