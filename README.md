## TP 1 – Technologies Blockchain

### Objectif
Mettre en place une structure de bloc minimale en Python, créer un bloc de genèse, ajouter au moins un second bloc et vérifier la liaison entre les blocs via `previous_hash` et le `hash` calculé.

### Contenu du dépôt
- `blockchain_tp1.py` : script principal qui définit la classe `Block`, crée la blockchain, affiche les blocs et (optionnellement) vérifie la validité.

### Prérequis
- Python 3.8+

### Lancer le script
Dans le répertoire du projet :
```bash
python blockchain_tp1.py
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
Pour que `previous_hash` pointe vers un vrai hachage, il faut calculer et stocker `hash` après la création de chaque bloc. Exemple :
```python
import hashlib

def compute_hash(self):
    content = f"{self.index}{self.timestamp}{self.data}{self.previous_hash}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

# Après instanciation du bloc
genesis_block.hash = genesis_block.compute_hash()
bloc1 = Block(1, "2025-10-12 00:05", "Alice envoie 5 BTC", previous_hash=genesis_block.hash)
bloc1.hash = bloc1.compute_hash()
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
- Le bloc de genèse affiche un `hash` non vide et `previous_hash = "0"`.
- Le second bloc affiche `previous_hash` égal au `hash` du bloc de genèse.
- La validation de la chaîne (si ajoutée) doit indiquer qu’elle est valide.

### Dépannage
- **`previous_hash` vide sur le second bloc** : assurez-vous d’avoir d’abord calculé et assigné `genesis_block.hash` avant de créer le second bloc.
- **Hashes identiques après modifications** : si vous changez les données, recalculer le `hash` du bloc concerné.



