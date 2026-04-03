#!/usr/bin/env python3
"""
Data Encryption Module for Raspberry Pi Cybersecurity Tool

This module provides secure encryption capabilities for the educational
cybersecurity testing tool. It demonstrates proper cryptographic practices
and secure data handling techniques.

Educational Purpose:
- Shows proper encryption implementation
- Demonstrates key derivation best practices
- Illustrates secure data storage techniques
- Teaches cryptographic security principles

Author: Mr.D137
License: MIT (Educational Use)
"""

import json
import os
import sys
from datetime import datetime, timezone
import logging
from typing import Dict, Any, Optional

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.Hash import SHA256
except ImportError:
    print("Error: pycryptodomex library is required. Install with: pip3 install pycryptodomex")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Security constants
PBKDF2_ITERATIONS = 100000  # NIST recommended minimum
SALT_LENGTH = 16           # 128 bits
KEY_LENGTH = 32            # 256 bits for AES-256
NONCE_LENGTH = 16          # 128 bits for GCM
TAG_LENGTH = 16            # 128 bits authentication tag

# Educational disclaimer
EDUCATIONAL_DISCLAIMER = {
    "notice": "COLLECTED FOR CYBERSECURITY EDUCATION AND AUTHORIZED TESTING ONLY",
    "warning": "UNAUTHORIZED USE OF THIS TOOL IS ILLEGAL AND UNETHICAL",
    "purpose": "Educational demonstration of security vulnerabilities",
    "compliance": "Users must comply with all applicable laws and regulations",
    "authorization": "Only use on systems with explicit written permission"
}

class SecureDataHandler:
    """
    Educational secure data handling class demonstrating cryptographic best practices
    """
    
    def __init__(self, storage_path: str = "/mnt/usb_share"):
        self.storage_path = storage_path
        self.device_id = self._get_device_identifier()
        logger.info(f"Initialized SecureDataHandler with device ID: {self.device_id[:8]}...")
    
    def _get_device_identifier(self) -> str:
        """
        Get unique device identifier for key derivation
        
        Educational Note: Using hardware-specific identifiers ensures
        data can only be decrypted on the originating device
        
        Returns:
            str: Unique device identifier
        """
        try:
            # Try to get Raspberry Pi serial number
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('Serial'):
                        serial = line.split(':')[1].strip()
                        if serial and serial != "0000000000000000":
                            return serial
        except (IOError, FileNotFoundError):
            logger.warning("Unable to read Pi serial from /proc/cpuinfo")
        
        try:
            # Fallback to machine ID
            with open('/etc/machine-id', 'r') as f:
                machine_id = f.read().strip()
                if machine_id:
                    return machine_id
        except (IOError, FileNotFoundError):
            logger.warning("Unable to read machine ID")
        
        # Final fallback - generate and store a unique ID
        fallback_id = os.urandom(16).hex()
        logger.warning(f"Using fallback device ID: {fallback_id[:8]}...")
        return fallback_id
    
    def encrypt_data(self, data: Dict[str, Any], password: Optional[str] = None) -> bytes:
        """
        Encrypt data using AES-256-GCM with PBKDF2 key derivation
        
        Educational Notes:
        - AES-256-GCM provides both confidentiality and authenticity
        - PBKDF2 with high iteration count protects against brute force
        - Salt prevents rainbow table attacks
        - Authentication tag prevents tampering
        
        Args:
            data: Dictionary containing data to encrypt
            password: Optional password (uses device ID if not provided)
            
        Returns:
            bytes: Encrypted data with embedded salt, nonce, and tag
        """
        try:
            # Use device ID as password if none provided
            if password is None:
                password = self.device_id
            
            # Add educational metadata
            enhanced_data = {
                **EDUCATIONAL_DISCLAIMER,
                "device_id": self.device_id,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "encryption_info": {
                    "algorithm": "AES-256-GCM",
                    "key_derivation": "PBKDF2-SHA256",
                    "iterations": PBKDF2_ITERATIONS
                },
                "payload": data
            }
            
            # Generate random salt
            salt = get_random_bytes(SALT_LENGTH)
            
            # Derive encryption key using PBKDF2
            key = PBKDF2(
                password=password,
                salt=salt,
                dkLen=KEY_LENGTH,
                count=PBKDF2_ITERATIONS,
                hmac_hash_module=SHA256
            )
            
            # Create AES-GCM cipher
            cipher = AES.new(key, AES.MODE_GCM)
            
            # Encrypt data
            plaintext = json.dumps(enhanced_data, indent=2).encode('utf-8')
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            
            # Combine all components: salt + nonce + tag + ciphertext
            encrypted_blob = salt + cipher.nonce + tag + ciphertext
            
            logger.info(f"Successfully encrypted {len(plaintext)} bytes of data")
            return encrypted_blob
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_blob: bytes, password: Optional[str] = None) -> Dict[str, Any]:
        """
        Decrypt data encrypted with encrypt_data method
        
        Args:
            encrypted_blob: Encrypted data blob
            password: Password for decryption (uses device ID if not provided)
            
        Returns:
            dict: Decrypted data
        """
        try:
            if password is None:
                password = self.device_id
            
            # Extract components from blob
            salt = encrypted_blob[:SALT_LENGTH]
            nonce = encrypted_blob[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
            tag = encrypted_blob[SALT_LENGTH + NONCE_LENGTH:SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH]
            ciphertext = encrypted_blob[SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH:]
            
            # Derive decryption key
            key = PBKDF2(
                password=password,
                salt=salt,
                dkLen=KEY_LENGTH,
                count=PBKDF2_ITERATIONS,
                hmac_hash_module=SHA256
            )
            
            # Create cipher and decrypt
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Parse JSON data
            decrypted_data = json.loads(plaintext.decode('utf-8'))
            
            logger.info("Successfully decrypted data")
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def store_encrypted_data(self, data: Dict[str, Any], filename: str = "collected_data.enc") -> str:
        """
        Encrypt and store data to file
        
        Args:
            data: Data to encrypt and store
            filename: Output filename
            
        Returns:
            str: Path to stored file
        """
        try:
            # Ensure storage directory exists
            os.makedirs(self.storage_path, exist_ok=True)
            
            # Encrypt data
            encrypted_blob = self.encrypt_data(data)
            
            # Write to file
            filepath = os.path.join(self.storage_path, filename)
            with open(filepath, 'wb') as f:
                f.write(encrypted_blob)
            
            logger.info(f"Encrypted data stored to: {filepath}")
            return filepath
            
        except Exception as e:
            logger.error(f"Failed to store encrypted data: {e}")
            raise
    
    def load_encrypted_data(self, filename: str = "collected_data.enc") -> Dict[str, Any]:
        """
        Load and decrypt data from file
        
        Args:
            filename: Input filename
            
        Returns:
            dict: Decrypted data
        """
        try:
            filepath = os.path.join(self.storage_path, filename)
            
            with open(filepath, 'rb') as f:
                encrypted_blob = f.read()
            
            decrypted_data = self.decrypt_data(encrypted_blob)
            
            logger.info(f"Loaded and decrypted data from: {filepath}")
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Failed to load encrypted data: {e}")
            raise

def encrypt_collected_data(data: Dict[str, Any], output_path: str = "/mnt/usb_share/collected_data.enc") -> bool:
    """
    Legacy function for backward compatibility
    
    Args:
        data: Data to encrypt
        output_path: Output file path
        
    Returns:
        bool: Success status
    """
    try:
        handler = SecureDataHandler()
        
        # Extract directory and filename
        directory = os.path.dirname(output_path)
        filename = os.path.basename(output_path)
        
        # Update handler storage path
        handler.storage_path = directory
        
        # Store encrypted data
        handler.store_encrypted_data(data, filename)
        return True
        
    except Exception as e:
        logger.error(f"Legacy encryption function failed: {e}")
        return False

def main():
    """
    Main function for standalone testing and demonstration
    """
    # Sample data for educational demonstration
    sample_data = {
        "demo_mode": True,
        "sample_findings": {
            "browser_data": "Educational sample - no real data collected",
            "system_info": "Demonstration of data structure",
            "wifi_networks": "Sample network information"
        },
        "analysis_notes": "This is educational demonstration data"
    }
    
    try:
        # Initialize handler
        handler = SecureDataHandler(storage_path="./demo_output")
        
        # Demonstrate encryption
        print("=== Educational Encryption Demonstration ===")
        print(f"Device ID: {handler.device_id[:8]}...")
        
        # Encrypt sample data
        encrypted_blob = handler.encrypt_data(sample_data)
        print(f"Encrypted data size: {len(encrypted_blob)} bytes")
        
        # Store to file
        output_file = handler.store_encrypted_data(sample_data, "demo_encrypted.enc")
        print(f"Stored encrypted data to: {output_file}")
        
        # Load and decrypt
        decrypted_data = handler.load_encrypted_data("demo_encrypted.enc")
        print("Successfully decrypted data")
        
        # Show structure (without sensitive content)
        print("\nDecrypted data structure:")
        for key in decrypted_data.keys():
            if key != "payload":
                print(f"  {key}: {type(decrypted_data[key])}")
            else:
                print(f"  {key}: {type(decrypted_data[key])} (contains actual data)")
        
        print("\n=== Demonstration Complete ===")
        
    except Exception as e:
        logger.error(f"Demonstration failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())