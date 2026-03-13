import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_aes_gcm(plaintext: str, key: bytes = None) -> dict:
    """
    Chiffre un texte avec AES-GCM
    
    Args:
        plaintext: Texte à chiffrer
        key: Clé de 32 bytes (si None, génère une nouvelle clé)
    
    Returns:
        Dictionnaire contenant le ciphertext, nonce et la clé
    """
    # Générer une clé si non fournie
    if key is None:
        key = AESGCM.generate_key(bit_length=256)
    
    # Créer l'objet AESGCM
    aesgcm = AESGCM(key)
    
    # Générer un nonce (IV) aléatoire de 12 bytes (recommandé pour GCM)
    nonce = os.urandom(12)
    
    # Chiffrer le message (ajoute automatiquement l'authentification)
    ciphertext = aesgcm.encrypt(
        nonce, 
        plaintext.encode('utf-8'), 
        None  # Pas de données associées
    )
    
    return {
        'ciphertext': ciphertext,
        'nonce': nonce,
        'key': key
    }

def decrypt_aes_gcm(ciphertext: bytes, nonce: bytes, key: bytes) -> str:
    """
    Déchiffre un texte avec AES-GCM
    
    Args:
        ciphertext: Texte chiffré
        nonce: Nonce utilisé pour le chiffrement
        key: Clé de déchiffrement
    
    Returns:
        Texte déchiffré
    """
    aesgcm = AESGCM(key)
    
    # Déchiffrer (vérifie automatiquement l'authenticité)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext.decode('utf-8')

# Version avec encodage base64 pour stockage facile
def encrypt_to_base64(plaintext: str, key: bytes = None) -> dict:
    """Chiffre et retourne les données en base64"""
    if key is None:
        key = AESGCM.generate_key(bit_length=256)
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    
    return {
        'ciphertext_b64': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce_b64': base64.b64encode(nonce).decode('utf-8'),
        'key_b64': base64.b64encode(key).decode('utf-8')
    }

def decrypt_from_base64(ciphertext_b64: str, nonce_b64: str, key_b64: str) -> str:
    """Déchiffre à partir de données en base64"""
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = base64.b64decode(nonce_b64)
    key = base64.b64decode(key_b64)
    
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    
    return plaintext.decode('utf-8')

# Version avec format JSON pour stockage structuré
def encrypt_to_json(plaintext: str, key: bytes = None) -> str:
    """Chiffre et retourne un JSON string"""
    result = encrypt_to_base64(plaintext, key)
    import json
    return json.dumps(result)

def decrypt_from_json(json_str: str) -> str:
    """Déchiffre à partir d'un JSON string"""
    import json
    data = json.loads(json_str)
    return decrypt_from_base64(
        data['ciphertext_b64'],
        data['nonce_b64'],
        data['key_b64']
    )

####################################################################################################


if __name__ == "__main__":
    
    # Exemple 1: Utilisation simple avec génération automatique de clé
    print("="*50)
    print("EXEMPLE 1: Chiffrement simple")
    print("="*50)

    message = "Ceci est mon message secret!"
    print(f"Message original: {message}")

    # Chiffrer
    resultat = encrypt_aes_gcm(message)
    print(f"\nClé (hex): {resultat['key'].hex()}")
    print(f"Nonce (hex): {resultat['nonce'].hex()}")
    print(f"Message chiffré (hex): {resultat['ciphertext'].hex()}")

    # Déchiffrer
    message_dechiffre = decrypt_aes_gcm(
        resultat['ciphertext'],
        resultat['nonce'],
        resultat['key']
    )
    print(f"\nMessage déchiffré: {message_dechiffre}")

    # Vérification
    assert message == message_dechiffre
    print("✓ Chiffrement/déchiffrement réussi!")


    # Exemple 2: Avec une clé spécifique
    print("\n" + "="*50)
    print("EXEMPLE 2: Avec clé spécifique")
    print("="*50)

    # Créer une clé spécifique (important: 32 bytes pour AES-256)
    ma_cle = os.urandom(32)  # ou b'macle_32_bytes_pour_aes_256!!'  (doit faire 32 bytes)
    print(f"Ma clé (hex): {ma_cle.hex()}")

    message2 = "Mot de passe: monSuperMotDePasse123"
    print(f"Message: {message2}")

    # Chiffrer avec la clé spécifique
    resultat2 = encrypt_aes_gcm(message2, ma_cle)
    print(f"Chiffré: {resultat2['ciphertext'].hex()}")

    # Déchiffrer
    dechiffre2 = decrypt_aes_gcm(resultat2['ciphertext'], resultat2['nonce'], ma_cle)
    print(f"Déchiffré: {dechiffre2}")


    # Exemple 3: Stockage en base64 (pour fichier/BDD)
    print("\n" + "="*50)
    print("EXEMPLE 3: Format base64 (pour stockage)")
    print("="*50)

    message3 = "Email: user@example.com, Password: secret123"
    print(f"Message: {message3}")

    # Chiffrer en base64
    resultat_b64 = encrypt_to_base64(message3)
    print(f"Clé (b64): {resultat_b64['key_b64']}")
    print(f"Nonce (b64): {resultat_b64['nonce_b64']}")
    print(f"Chiffré (b64): {resultat_b64['ciphertext_b64']}")

    # Déchiffrer depuis base64
    dechiffre_b64 = decrypt_from_base64(
        resultat_b64['ciphertext_b64'],
        resultat_b64['nonce_b64'],
        resultat_b64['key_b64']
    )
    print(f"Déchiffré: {dechiffre_b64}")


    # Exemple 4: Format JSON (pratique pour fichiers)
    print("\n" + "="*50)
    print("EXEMPLE 4: Format JSON")
    print("="*50)

    message4 = "Données sensibles: coordonnées bancaires"
    print(f"Message: {message4}")

    # Chiffrer en JSON
    json_data = encrypt_to_json(message4)
    print(f"JSON stockable:\n{json_data}")

    # Déchiffrer depuis JSON
    dechiffre_json = decrypt_from_json(json_data)
    print(f"\nDéchiffré: {dechiffre_json}")


    # Exemple 5: Sauvegarde dans un fichier
    print("\n" + "="*50)
    print("EXEMPLE 5: Sauvegarde dans fichier")
    print("="*50)

    # Chiffrer
    message5 = "Ce message sera sauvegardé dans un fichier"
    resultat5 = encrypt_to_json(message5)

    # Sauvegarder
    with open('message_chiffre.json', 'w') as f:
        f.write(resultat5)
    print("Message chiffré sauvegardé dans 'message_chiffre.json'")

    # Lire et déchiffrer
    with open('message_chiffre.json', 'r') as f:
        data = f.read()
    dechiffre5 = decrypt_from_json(data)
    print(f"Message déchiffré depuis fichier: {dechiffre5}")



#######################################################################################################



"""



from cryptography.fernet import Fernet
import json
import os

class SimplePasswordManager:
    def __init__(self, master_password: str):
        # Derive key from master password
        self.key = base64.urlsafe_b64encode(
            hashlib.sha256(master_password.encode()).digest()
        )
        self.cipher = Fernet(self.key)
        self.vault_file = "passwords.json"
    
    def save_password(self, service: str, username: str, password: str):
        # Load existing
        vault = self._load_vault()
        
        # Add new entry
        vault[service] = {
            'username': username,
            'password': password
        }
        
        # Encrypt and save
        encrypted = self.cipher.encrypt(json.dumps(vault).encode())
        with open(self.vault_file, 'wb') as f:
            f.write(encrypted)
    
    def get_password(self, service: str):
        vault = self._load_vault()
        return vault.get(service)
    
    def _load_vault(self):
        if not os.path.exists(self.vault_file):
            return {}
        with open(self.vault_file, 'rb') as f:
            encrypted = f.read()
        decrypted = self.cipher.decrypt(encrypted)
        return json.loads(decrypted.decode())

# Usage
pm = SimplePasswordManager("my-master-password")
pm.save_password("gmail", "user@gmail.com", "hunter2")
print(pm.get_password("gmail"))



"""