import hashlib
import coincurve
import base58
import math
from collections import defaultdict

# Function to generate a Bitcoin address from a public key
def pubkey_to_address(public_key_bytes):
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    
    # Add network byte (0x00 for mainnet)
    network_byte = b'\x00' + ripemd160_hash
    
    # Perform double SHA256 for checksum
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    
    # Final address is base58 encoding of the network byte + checksum
    address_bytes = network_byte + checksum
    return base58.b58encode(address_bytes).decode()

# Function to generate a public key from a private key
def generate_pubkey(private_key_int):
    private_key_bytes = private_key_int.to_bytes(32, 'big')
    private_key = coincurve.PrivateKey(private_key_bytes)
    return private_key.public_key.format(compressed=True)

# Baby-step Giant-step search algorithm
def bsgs_search(target_address, start_key, end_key, step_size):
    m = math.isqrt(end_key - start_key)  # Baby-step size
    baby_steps = defaultdict(list)
    
    # Baby-step phase: store addresses for m small steps
    print(f"Generating {m} baby steps...")
    for i in range(m):
        private_key = start_key + i
        public_key = generate_pubkey(private_key)
        address = pubkey_to_address(public_key)
        print(f"Baby-step: Private key {hex(private_key)}, Address {address}")
        baby_steps[address].append(private_key)
    
    # Giant-step phase: search using larger steps
    print("Starting giant steps...")
    for j in range(m):
        current_key = start_key + j * m
        public_key = generate_pubkey(current_key)
        address = pubkey_to_address(public_key)
        
        print(f"Giant-step: Private key {hex(current_key)}, Address {address}")
        
        # Check if the address matches the target
        if address == target_address:
            print(f"Found match! Private key: {hex(current_key)} corresponds to the target address: {target_address}")
            return current_key
        
        # Check baby steps for possible matches
        if address in baby_steps:
            for baby_private_key in baby_steps[address]:
                combined_key = current_key + baby_private_key
                print(f"Found match in baby steps! Private key: {hex(combined_key)}")
                return combined_key

    print("No match found in the specified key range.")
    return None

# Example usage
if _name_ == "_main_":
    # Define the target address
    target_address = "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9"  # Target Bitcoin address

    # Define the search range
    start_key = int("40000000000000000", 16)  # Starting key in hex
    end_key = int("7ffffffffffffffff", 16)    # End key in hex
    step_size = 1000000  # Step size (can be adjusted based on memory and resources)

    # Run the BSGS search
    found_key = bsgs_search(target_address, start_key, end_key, step_size)

    if found_key:
        print(f"Private key found: {hex(found_key)}")
    else:
        print("No match found.")