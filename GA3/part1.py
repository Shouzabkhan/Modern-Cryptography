from hashlib import sha256  # For Merkle hashing
from ascon import ascon_hash
import os

#If error comes up of .DS_Store
# find . -name "*.DS_Store" -type f -delete 

# Limitation of this code:
# Each subdirectory: max 1 snapshots. Not more than that. Else it crashes.
# No code implemented on taking snapshots of data from social. I just added random snapshots for understanding.  



def calculate_file_hash(file_path):
    hasher = sha256()  # Or any other suitable hash function
    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4096)  # Read in chunks
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def calculate_merkle_hash(directory_path):
    hashes = []
    for item in os.listdir(directory_path):
        item_path = os.path.join(directory_path, item)
        if os.path.isfile(item_path):
            hashes.append(calculate_file_hash(item_path))
        elif os.path.isdir(item_path):
            hashes.append(calculate_merkle_hash(item_path))

    # Build the Merkle tree (simplified binary tree example)
    while len(hashes) > 1:
        new_hashes = []
        for i in range(0, len(hashes), 2):
            combined_hash = ascon_hash.ascon_hash((hashes[i] + hashes[i + 1]), variant="Ascon-Hash", hashlength=32)
            new_hashes.append(combined_hash)
        hashes = new_hashes

    return hashes[0]  # Merkle root


def generate_hash_chain(snapshots_dir, hash_store_file):
    for day_dir in sorted(os.listdir(snapshots_dir)):  # Process days in order
        snapshot_dir = os.path.join(snapshots_dir, day_dir)
        merkle_root = calculate_merkle_hash(snapshot_dir)

        with open(hash_store_file, "a+") as file:
            previous_hash = file.readline().strip()
            if not previous_hash:  # Check for empty string
                new_hash = merkle_root  # Initial case
            else:
                combined_data = previous_hash + merkle_root
                new_hash = ascon_hash.ascon_hash(combined_data, variant="Ascon-Hash", hashlength=32)
            file.write(new_hash + "\n")
            
def generate_key_pair(key_size=2048):
    """
    Generates a new RSA key pair.

    Args:
        key_size (int, optional): The key size in bits (default: 2048).

    Returns:
        tuple: A tuple containing the private key and public key objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key


def load_key_pair(private_key_file, public_key_file):
    """
    Loads an existing RSA key pair from PEM-encoded files.

    Args:
        private_key_file (str): The path to the private key file (PEM format).
        public_key_file (str): The path to the public key file (PEM format).

    Returns:
        tuple: A tuple containing the private key and public key objects,
              or None if either file is not found.
    """
    try:
        with open(private_key_file, "rb") as f:
            private_key = rsa.PrivateKey.from_pem(f.read())
        with open(public_key_file, "rb") as f:
            public_key = rsa.PublicKey.from_pem(f.read())
        return private_key, public_key
    except (FileNotFoundError, ValueError):
        print(f"Error: Failed to load key pair from files.")
        return None


if __name__ == "__main__":
    snapshots_dir = "snapshots"
    hash_store_file = "hash_chain.txt"
    generate_hash_chain(snapshots_dir, hash_store_file)
