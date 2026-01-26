# Marauder Firmware

A modular ESP32-S3 based security research device combining WiFi, NFC, LoRa, and Bluetooth capabilities with both offensive and defensive features.

## Overview

This project implements a comprehensive wireless security testing platform built around the ESP32-S3 microcontroller. The firmware provides a plugin-based architecture supporting multiple communication protocols and attack vectors while incorporating defensive mechanisms for network monitoring and threat detection.

## Hardware Requirements

### Core Components
- ESP32-S3-DevKitC-1 development board
- 3.2" SPI TFT touchscreen display (240x320, ILI9341)
- PN532 NFC/RFID module (13.56MHz)

### Power Requirements
- External USB power bank or regulated power supply
- Operating voltage: 3.3V/5V via USB-C

## Features

### Attack Capabilities
- WiFi network scanning and reconnaissance
- Deauthentication attacks (802.11)
- NFC/RFID card reading and cloning
- LoRaWAN network analysis
- Bluetooth Low Energy scanning
- Packet injection and monitoring

### Defense Mechanisms
- Deauthentication attack detection
- Wireless sniffer detection
- Network anomaly monitoring
- Real-time threat alerting
- Attack pattern analysis

## Architecture

The firmware implements a modular plugin system allowing for easy extension and customization. Core modules handle system management, display interface, and power management, while attack modules can be loaded dynamically based on available hardware.

## Project Structure

- `docs/` - Technical documentation and design decisions
- `firmware/` - ESP32-S3 firmware source code
- `hardware/` - Schematics, PCB designs, and 3D models
- `examples/` - Usage examples and test implementations

## Development Status

This project is currently in early development phase. Initial focus is on establishing the core architecture and basic module functionality.

## Legal Notice

This software is intended for authorized security testing and research purposes only. Users are responsible for compliance with applicable laws and regulations in their jurisdiction. The developers assume no liability for misuse of this software.

## License

This project is released under the MIT License. See LICENSE file for details.

## Contributing

Contributions are welcome. Please read the documentation in the `docs/` directory for development guidelines and architecture details.