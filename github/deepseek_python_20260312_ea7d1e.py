import json
import os
import stat
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass
import platform

class SecureKeyManager:
    """
    A secure key manager that stores keys in read-only JSON files
    with proper permissions and encryption
    """
    
    def __init__(self, key_file="keys.json", use_encryption=True):
        self.key_file = key_file
        self.use_encryption = use_encryption
        self.master_key = None
        self.keys = {}
        
    def set_read_only_permissions(self, filepath):
        """Set file to read-only based on operating system"""
        try:
            if platform.system() == "Windows":
                # Windows: Remove write permission for all users
                os.chmod(filepath, stat.S_IREAD)
            else:
                # Unix/Linux: Remove write permission for all (read-only for owner, group, others)
                os.chmod(filepath, 0o444)  # 444 = read-only for all
            print(f"✅ File {filepath} is now read-only")
        except Exception as e:
            print(f"⚠️ Warning: Could not set read-only permissions: {e}")
    
    def set_read_write_permissions(self, filepath):
        """Temporarily set file to read-write for updates"""
        try:
            if platform.system() == "Windows":
                os.chmod(filepath, stat.S_IWRITE | stat.S_IREAD)
            else:
                os.chmod(filepath, 0o644)  # 644 = read-write for owner, read for others
        except Exception as e:
            print(f"⚠️ Warning: Could not set read-write permissions: {e}")
    
    def generate_master_key(self, password=None):
        """Generate a master key from password or create a new one"""
        if password:
            # Derive key from password
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return key, salt
        else:
            # Generate random key
            return Fernet.generate_key(), None
    
    def encrypt_key(self, key_data, master_key):
        """Encrypt a key using master key"""
        f = Fernet(master_key)
        encrypted_data = f.encrypt(json.dumps(key_data).encode())
        return encrypted_data
    
    def decrypt_key(self, encrypted_data, master_key):
        """Decrypt a key using master key"""
        f = Fernet(master_key)
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    
    def generate_application_key(self, key_name, key_type="aes"):
        """Generate a new application-specific key"""
        if key_type == "aes":
            # Generate AES-256 key
            key = os.urandom(32)
            encoded_key = base64.b64encode(key).decode('utf-8')
        elif key_type == "fernet":
            # Generate Fernet key
            key = Fernet.generate_key()
            encoded_key = key.decode('utf-8')
        else:
            # Generate random token
            key = os.urandom(48)
            encoded_key = base64.b64encode(key).decode('utf-8')
        
        return {
            "name": key_name,
            "type": key_type,
            "key": encoded_key,
            "created": self.get_timestamp(),
            "version": 1
        }
    
    def get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.utcnow().isoformat()
    
    def save_key_readonly(self, key_name, key_data, password=None):
        """
        Save a key to read-only JSON file
        If file exists, it will temporarily get write permission, update, then revert to read-only
        """
        try:
            # Check if file exists and set write permission temporarily
            file_exists = os.path.exists(self.key_file)
            if file_exists:
                self.set_read_write_permissions(self.key_file)
            
            # Load existing keys
            existing_keys = {}
            if file_exists:
                try:
                    with open(self.key_file, 'r') as f:
                        existing_keys = json.load(f)
                except (json.JSONDecodeError, PermissionError):
                    existing_keys = {}
            
            # Generate master key if needed
            if self.use_encryption and password:
                master_key, salt = self.generate_master_key(password)
                # Encrypt the key data
                encrypted_data = self.encrypt_key(key_data, master_key)
                
                # Store encrypted data
                if "encrypted_keys" not in existing_keys:
                    existing_keys["encrypted_keys"] = {}
                existing_keys["encrypted_keys"][key_name] = {
                    "data": base64.b64encode(encrypted_data).decode('utf-8'),
                    "salt": base64.b64encode(salt).decode('utf-8') if salt else None
                }
            else:
                # Store plaintext (not recommended for production)
                if "plain_keys" not in existing_keys:
                    existing_keys["plain_keys"] = {}
                existing_keys["plain_keys"][key_name] = key_data
            
            # Add metadata
            existing_keys["metadata"] = {
                "last_updated": self.get_timestamp(),
                "version": "1.0",
                "encryption_enabled": self.use_encryption
            }
            
            # Write to file
            with open(self.key_file, 'w') as f:
                json.dump(existing_keys, f, indent=2)
            
            # Set back to read-only
            self.set_read_only_permissions(self.key_file)
            
            print(f"✅ Key '{key_name}' saved successfully to {self.key_file}")
            return True
            
        except Exception as e:
            print(f"❌ Error saving key: {e}")
            return False
    
    def retrieve_key(self, key_name, password=None):
        """
        Retrieve a key from read-only JSON file
        """
        try:
            if not os.path.exists(self.key_file):
                print(f"❌ Key file {self.key_file} not found")
                return None
            
            # File is read-only, but we can read from it
            with open(self.key_file, 'r') as f:
                key_store = json.load(f)
            
            # Check if encryption is enabled
            if self.use_encryption and password:
                if "encrypted_keys" not in key_store or key_name not in key_store["encrypted_keys"]:
                    print(f"❌ Key '{key_name}' not found")
                    return None
                
                # Get encrypted data
                encrypted_entry = key_store["encrypted_keys"][key_name]
                encrypted_data = base64.b64decode(encrypted_entry["data"])
                salt = base64.b64decode(encrypted_entry["salt"]) if encrypted_entry["salt"] else None
                
                # Regenerate master key from password
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                master_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                
                # Decrypt the key
                key_data = self.decrypt_key(encrypted_data, master_key)
                print(f"✅ Key '{key_name}' retrieved successfully")
                return key_data
                
            else:
                # Plaintext retrieval
                if "plain_keys" not in key_store or key_name not in key_store["plain_keys"]:
                    print(f"❌ Key '{key_name}' not found")
                    return None
                
                print(f"✅ Key '{key_name}' retrieved successfully")
                return key_store["plain_keys"][key_name]
                
        except Exception as e:
            print(f"❌ Error retrieving key: {e}")
            return None
    
    def list_keys(self):
        """List all available keys"""
        try:
            if not os.path.exists(self.key_file):
                print("No key file found")
                return []
            
            with open(self.key_file, 'r') as f:
                key_store = json.load(f)
            
            keys = []
            if "encrypted_keys" in key_store:
                keys.extend(key_store["encrypted_keys"].keys())
            if "plain_keys" in key_store:
                keys.extend(key_store["plain_keys"].keys())
            
            print(f"📋 Available keys: {', '.join(keys) if keys else 'None'}")
            return keys
            
        except Exception as e:
            print(f"❌ Error listing keys: {e}")
            return []
    
    def verify_file_permissions(self):
        """Verify the current file permissions"""
        try:
            if os.path.exists(self.key_file):
                stats = os.stat(self.key_file)
                mode = stats.st_mode
                
                print(f"\n📁 File: {self.key_file}")
                print(f"Permissions (octal): {oct(mode & 0o777)}")
                
                if platform.system() == "Windows":
                    is_readonly = not bool(mode & stat.S_IWRITE)
                else:
                    is_readonly = not bool(mode & stat.S_IWUSR)
                
                print(f"Read-only: {is_readonly}")
                return is_readonly
            else:
                print("File doesn't exist yet")
                return False
        except Exception as e:
            print(f"Error checking permissions: {e}")
            return False


# Example usage and testing
def main():
    print("🔐 Secure Key Management System")
    print("=" * 50)
    
    # Initialize key manager
    key_manager = SecureKeyManager("app_keys.json", use_encryption=True)
    
    while True:
        print("\n📋 Menu:")
        print("1. Generate and save new key")
        print("2. Retrieve existing key")
        print("3. List all keys")
        print("4. Verify file permissions")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == "1":
            # Generate new key
            key_name = input("Enter key name (e.g., 'api_key', 'db_password'): ").strip()
            key_type = input("Enter key type (aes/fernet/token) [default: aes]: ").strip() or "aes"
            
            # Generate the key
            key_data = key_manager.generate_application_key(key_name, key_type)
            print(f"\n🔑 Generated key: {key_data['key'][:20]}... (truncated)")
            
            # Set password for encryption
            if key_manager.use_encryption:
                password = getpass.getpass("Enter encryption password: ")
                confirm = getpass.getpass("Confirm password: ")
                
                if password != confirm:
                    print("❌ Passwords don't match!")
                    continue
            else:
                password = None
            
            # Save key
            key_manager.save_key_readonly(key_name, key_data, password)
            
        elif choice == "2":
            # Retrieve key
            key_name = input("Enter key name to retrieve: ").strip()
            
            if key_manager.use_encryption:
                password = getpass.getpass("Enter encryption password: ")
            else:
                password = None
            
            retrieved_key = key_manager.retrieve_key(key_name, password)
            if retrieved_key:
                print(f"\n📦 Retrieved key data:")
                print(json.dumps(retrieved_key, indent=2))
        
        elif choice == "3":
            # List keys
            key_manager.list_keys()
        
        elif choice == "4":
            # Verify permissions
            key_manager.verify_file_permissions()
        
        elif choice == "5":
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice!")


# Advanced example: Auto-rotating keys with read-only storage
class KeyRotationManager(SecureKeyManager):
    """Extended key manager with automatic key rotation"""
    
    def rotate_key(self, key_name, password=None):
        """Rotate an existing key"""
        # Retrieve old key
        old_key = self.retrieve_key(key_name, password)
        if not old_key:
            return False
        
        # Generate new key of same type
        new_key = self.generate_application_key(
            f"{key_name}_v{old_key.get('version', 0) + 1}",
            old_key.get('type', 'aes')
        )
        
        # Archive old key
        old_key['archived'] = True
        old_key['archived_at'] = self.get_timestamp()
        
        # Save both keys temporarily
        self.set_read_write_permissions(self.key_file)
        
        # Load current store
        with open(self.key_file, 'r') as f:
            key_store = json.load(f)
        
        # Archive old key
        if "archived_keys" not in key_store:
            key_store["archived_keys"] = []
        key_store["archived_keys"].append(old_key)
        
        # Remove old from active
        if self.use_encryption and password:
            del key_store["encrypted_keys"][key_name]
        else:
            del key_store["plain_keys"][key_name]
        
        # Add new key
        if self.use_encryption and password:
            master_key, salt = self.generate_master_key(password)
            encrypted_data = self.encrypt_key(new_key, master_key)
            key_store["encrypted_keys"][key_name] = {
                "data": base64.b64encode(encrypted_data).decode('utf-8'),
                "salt": base64.b64encode(salt).decode('utf-8')
            }
        else:
            key_store["plain_keys"][key_name] = new_key
        
        # Save and set read-only
        with open(self.key_file, 'w') as f:
            json.dump(key_store, f, indent=2)
        
        self.set_read_only_permissions(self.key_file)
        print(f"✅ Key '{key_name}' rotated successfully")
        return True


if __name__ == "__main__":
    main()