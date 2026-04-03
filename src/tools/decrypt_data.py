#!/usr/bin/env python3
"""
Data Decryption Tool for Raspberry Pi Cybersecurity Tool

This tool provides decryption capabilities for data collected by the
educational cybersecurity testing tool. It demonstrates proper
cryptographic practices and secure data handling.

Educational Purpose:
- Shows proper decryption implementation
- Demonstrates secure key handling
- Illustrates data analysis techniques
- Teaches cryptographic security principles

Author: Mr.D137
License: MIT (Educational Use)
"""

import json
import sys
import os
import argparse
from typing import Dict, Any, Optional

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
    from Cryptodome.Hash import SHA256
except ImportError:
    print("Error: pycryptodomex library is required. Install with: pip3 install pycryptodomex")
    sys.exit(1)

# Security constants (must match encryption tool)
PBKDF2_ITERATIONS = 100000
SALT_LENGTH = 16
KEY_LENGTH = 32
NONCE_LENGTH = 16
TAG_LENGTH = 16

class DataDecryptor:
    """
    Educational data decryption class for analyzing collected cybersecurity data
    """
    
    def __init__(self, device_serial: Optional[str] = None):
        self.device_serial = device_serial
    
    def decrypt_data(self, encrypted_blob: bytes, password: str) -> Dict[str, Any]:
        """
        Decrypt data using AES-256-GCM with PBKDF2 key derivation
        
        Educational Notes:
        - Validates authentication tag to ensure data integrity
        - Uses the same parameters as encryption for compatibility
        - Proper error handling for educational analysis
        
        Args:
            encrypted_blob: Encrypted data blob
            password: Decryption password (typically device serial)
            
        Returns:
            dict: Decrypted data structure
        """
        try:
            # Validate minimum blob size
            min_size = SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH
            if len(encrypted_blob) < min_size:
                raise ValueError(f"Encrypted blob too small: {len(encrypted_blob)} < {min_size}")
            
            # Extract components
            salt = encrypted_blob[:SALT_LENGTH]
            nonce = encrypted_blob[SALT_LENGTH:SALT_LENGTH + NONCE_LENGTH]
            tag = encrypted_blob[SALT_LENGTH + NONCE_LENGTH:SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH]
            ciphertext = encrypted_blob[SALT_LENGTH + NONCE_LENGTH + TAG_LENGTH:]
            
            # Derive decryption key using PBKDF2
            key = PBKDF2(
                password=password,
                salt=salt,
                dkLen=KEY_LENGTH,
                count=PBKDF2_ITERATIONS,
                hmac_hash_module=SHA256
            )
            
            # Create cipher and decrypt with authentication
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            # Parse JSON data
            decrypted_data = json.loads(plaintext.decode('utf-8'))
            
            return decrypted_data
            
        except ValueError as e:
            print(f"Authentication failed: {e}")
            print("This may indicate:")
            print("1. Wrong password/device serial")
            print("2. Corrupted data")
            print("3. Tampered encryption blob")
            raise
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in decrypted data: {e}")
            raise
        except Exception as e:
            print(f"Decryption failed: {e}")
            raise
    
    def decrypt_file(self, filepath: str, password: str) -> Dict[str, Any]:
        """
        Decrypt data from file
        
        Args:
            filepath: Path to encrypted file
            password: Decryption password
            
        Returns:
            dict: Decrypted data
        """
        try:
            with open(filepath, 'rb') as f:
                encrypted_blob = f.read()
            
            return self.decrypt_data(encrypted_blob, password)
            
        except FileNotFoundError:
            print(f"File not found: {filepath}")
            raise
        except PermissionError:
            print(f"Permission denied accessing: {filepath}")
            raise
    
    def analyze_data_structure(self, data: Dict[str, Any]) -> None:
        """
        Analyze and display the structure of decrypted data for educational purposes
        
        Args:
            data: Decrypted data dictionary
        """
        print("\n=== Data Structure Analysis ===")
        
        # Show top-level structure
        print(f"Top-level keys: {list(data.keys())}")
        
        # Show educational disclaimer
        if 'notice' in data:
            print(f"\nEducational Notice: {data['notice']}")
        
        # Show collection metadata
        if 'timestamp' in data:
            print(f"Collection Timestamp: {data['timestamp']}")
        
        if 'device_id' in data:
            device_id = data['device_id']
            print(f"Device ID: {device_id[:8]}..." if len(device_id) > 8 else device_id)
        
        # Show encryption information
        if 'encryption_info' in data:
            enc_info = data['encryption_info']
            print(f"\nEncryption Details:")
            for key, value in enc_info.items():
                print(f"  {key}: {value}")
        
        # Analyze payload structure
        if 'payload' in data:
            payload = data['payload']
            print(f"\nPayload Structure:")
            self._analyze_payload_recursive(payload, indent=2)
        
        print("\n=== Analysis Complete ===")
    
    def _analyze_payload_recursive(self, obj: Any, indent: int = 0) -> None:
        """
        Recursively analyze payload structure
        
        Args:
            obj: Object to analyze
            indent: Indentation level
        """
        spaces = " " * indent
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (dict, list)):
                    print(f"{spaces}{key}: {type(value).__name__} ({len(value)} items)")
                    self._analyze_payload_recursive(value, indent + 2)
                else:
                    # Don't show sensitive data, just types and sizes
                    if isinstance(value, str):
                        print(f"{spaces}{key}: string ({len(value)} chars)")
                    else:
                        print(f"{spaces}{key}: {type(value).__name__}")
        elif isinstance(obj, list):
            print(f"{spaces}List with {len(obj)} items:")
            if obj:  # Show first item structure
                self._analyze_payload_recursive(obj[0], indent + 2)

def get_device_serial_interactive() -> str:
    """
    Interactively get device serial from user
    
    Returns:
        str: Device serial number
    """
    print("\nTo decrypt the data, you need the Raspberry Pi's serial number.")
    print("You can find this by running the following command on the Pi:")
    print("  cat /proc/cpuinfo | grep Serial")
    print("\nOr from the bottom of the Pi board (newer models).")
    
    while True:
        serial = input("\nEnter the Pi's serial number: ").strip()
        if serial:
            return serial
        print("Serial number cannot be empty. Please try again.")

def main():
    """
    Main function for the decryption tool
    """
    parser = argparse.ArgumentParser(
        description="Decrypt educational cybersecurity tool data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file collected_data.enc --serial 1000000012345678
  %(prog)s --file demo_data.enc --analyze
  %(prog)s --interactive
        """
    )
    
    parser.add_argument(
        '--file', '-f',
        required=True,
        help='Path to encrypted data file'
    )
    
    parser.add_argument(
        '--serial', '-s',
        help='Raspberry Pi serial number (will prompt if not provided)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file for decrypted JSON (default: stdout)'
    )
    
    parser.add_argument(
        '--analyze', '-a',
        action='store_true',
        help='Analyze and display data structure (recommended for educational use)'
    )
    
    parser.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Interactive mode with guided prompts'
    )
    
    args = parser.parse_args()
    
    try:
        # Get device serial
        if args.serial:
            device_serial = args.serial
        elif args.interactive:
            device_serial = get_device_serial_interactive()
        else:
            device_serial = input("Enter Raspberry Pi serial number: ").strip()
        
        if not device_serial:
            print("Error: Device serial number is required")
            return 1
        
        # Initialize decryptor
        decryptor = DataDecryptor(device_serial)
        
        # Decrypt file
        print(f"Decrypting file: {args.file}")
        decrypted_data = decryptor.decrypt_file(args.file, device_serial)
        print("Decryption successful!")
        
        # Analyze structure if requested
        if args.analyze or args.interactive:
            decryptor.analyze_data_structure(decrypted_data)
        
        # Output data
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(decrypted_data, f, indent=2, default=str)
            print(f"Decrypted data saved to: {args.output}")
        elif not args.analyze:
            # Only print JSON if not in analyze mode
            print("\nDecrypted data:")
            print(json.dumps(decrypted_data, indent=2, default=str))
        
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())