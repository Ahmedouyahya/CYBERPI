#!/usr/bin/env python3
"""
OS Detection Module for Raspberry Pi Cybersecurity Tool

This module provides cross-platform OS detection capabilities for the
educational cybersecurity testing tool. It's designed to demonstrate
how attackers might fingerprint target systems.

Educational Purpose:
- Shows how OS detection works
- Demonstrates system fingerprinting techniques
- Illustrates the importance of system hardening

Author: Mr.D137
License: MIT (Educational Use)
"""

import sys
import platform
import os
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class OSDetector:
    """
    Educational OS detection class demonstrating various fingerprinting techniques
    """
    
    SUPPORTED_OS = {
        'windows': 'Microsoft Windows',
        'macos': 'Apple macOS',
        'linux': 'GNU/Linux',
        'android': 'Google Android',
        'ios': 'Apple iOS'
    }
    
    def __init__(self):
        self.detected_os = None
        self.confidence = 0.0
        self.details = {}
    
    def detect_os(self):
        """
        Main OS detection method using multiple techniques
        
        Returns:
            str: Detected OS identifier
        """
        logger.info("Starting OS detection process...")
        
        # Primary detection using sys.platform
        platform_result = self._detect_by_platform()
        
        # Secondary detection using additional methods
        if platform_result == 'unknown':
            platform_result = self._detect_by_environment()
        
        # Tertiary detection for mobile devices
        if platform_result == 'linux':
            mobile_result = self._detect_mobile_os()
            if mobile_result != 'unknown':
                platform_result = mobile_result
        
        self.detected_os = platform_result
        self._gather_system_details()
        
        logger.info(f"OS detection completed: {self.detected_os}")
        return self.detected_os
    
    def _detect_by_platform(self):
        """Detect OS using sys.platform"""
        if sys.platform.startswith('win'):
            return 'windows'
        elif sys.platform.startswith('darwin'):
            return 'macos'
        elif sys.platform.startswith('linux'):
            return 'linux'
        return 'unknown'
    
    def _detect_by_environment(self):
        """Detect OS using environment variables and file system"""
        # Check for Windows-specific environment variables
        if os.environ.get('WINDIR') or os.environ.get('SYSTEMROOT'):
            return 'windows'
        
        # Check for macOS-specific paths
        if os.path.exists('/System/Library/CoreServices/SystemVersion.plist'):
            return 'macos'
        
        # Check for Android
        if os.path.exists('/system/build.prop'):
            return 'android'
        
        return 'unknown'
    
    def _detect_mobile_os(self):
        """Detect mobile OS on Linux-based systems"""
        try:
            # Check for Android build properties
            if os.path.exists('/system/build.prop'):
                return 'android'
            
            # Check for iOS jailbreak indicators (educational purposes)
            ios_indicators = [
                '/Applications/Cydia.app',
                '/var/lib/cydia',
                '/etc/apt/sources.list.d/cydia.list'
            ]
            
            for indicator in ios_indicators:
                if os.path.exists(indicator):
                    return 'ios'
            
            # Check device tree for iOS (limited access scenario)
            if os.path.exists('/proc/device-tree/model'):
                try:
                    with open('/proc/device-tree/model', 'r') as f:
                        model = f.read().lower()
                        if 'iphone' in model or 'ipad' in model:
                            return 'ios'
                except (IOError, PermissionError):
                    pass
        
        except Exception as e:
            logger.warning(f"Mobile OS detection failed: {e}")
        
        return 'unknown'
    
    def _gather_system_details(self):
        """Gather additional system information for educational analysis"""
        try:
            self.details = {
                'platform': platform.platform(),
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'architecture': platform.architecture()
            }
        except Exception as e:
            logger.warning(f"Failed to gather system details: {e}")
            self.details = {}
    
    def get_detailed_info(self):
        """
        Return detailed information about the detected system
        
        Returns:
            dict: Comprehensive system information
        """
        return {
            'detected_os': self.detected_os,
            'os_name': self.SUPPORTED_OS.get(self.detected_os, 'Unknown OS'),
            'confidence': self.confidence,
            'system_details': self.details,
            'detection_timestamp': time.time()
        }

def detect_os():
    """
    Simple function interface for backward compatibility
    
    Returns:
        str: Detected OS identifier
    """
    detector = OSDetector()
    return detector.detect_os()

def main():
    """Main function for standalone execution"""
    detector = OSDetector()
    detected = detector.detect_os()
    
    print(f"Detected OS: {detected}")
    
    # For educational purposes, show detailed information
    if len(sys.argv) > 1 and sys.argv[1] == '--verbose':
        import json
        detailed_info = detector.get_detailed_info()
        print("\nDetailed System Information:")
        print(json.dumps(detailed_info, indent=2, default=str))

if __name__ == "__main__":
    main()