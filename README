# SwissSec
> Swiss Knife for all your cybersecurity needs

SwissSec is an advanced, hardware-based cybersecurity multitool built on the ESP32-S3. It serves as a secure password vault, a fully compliant FIDO2/WebAuthn authenticator, and a TOTP generator. Featuring biometric authentication, True Random Number Generation (TRNG), AES-GCM encryption, and cutting-edge Post-Quantum Cryptography (ML-DSA), SwissSec provides enterprise-grade security in a portable, self-contained hardware token.

## Key Features

### Advanced Cryptography & FIDO2
*   **FIDO2 & WebAuthn Compliant:** Supports MakeCredential and GetAssertion flows, Resident Passkeys, and the CTAP2 HID protocol.
*   **Post-Quantum Ready:** Implements ML-DSA (44, 65, 87) alongside standard algorithms (ECDSA P-256, Ed25519, RSA-2048).
*   **FIDO2 Extensions:** Supports the `hmac-secret` extension for offline login environments like Windows Hello.
*   **Backwards Compatibility:** Includes support for legacy U2F protocols.
*   **Dynamic Custom AAGUID:** Hardware-derived Authenticator Attestation GUID.

### Secure Vault & Storage
*   **Hardware Password Manager:** Store credentials encrypted with AES-GCM.
*   **TOTP Authenticator:** Generate time-based 6-digit codes via a standard HMAC-SHA1 moving counter.
*   **Protected Storage:** Pure binary and JSON-based EEPROM/SPIFFS storage for FIDO2 keys and passwords.
*   **PBKDF2 Derivation:** Master PIN securely derived using PBKDF2 with strict iteration limits.

### Biometric & Hardware Security
*   **Biometric User Verification (UV):** Fingerprint enrollment and verification tied directly to credential access and FIDO2 assertions.
*   **Anti-Glitching Defenses:** Includes random delays, magic state validation, and multi-byte constraints to thwart physical fault injection attacks.
*   **Brute-Force Protection:** Secure wipe triggered automatically after 10 invalid PIN attempts.
*   **Challenge-Response Fingerprint Protocol:** Cryptographically secure validation between the MCU and the biometric sensor.
*   **TRNG Integration:** Entropy sourced via RF noise for true cryptographic randomness.

### System Architecture
*   **Dual-Interface USB Composite Stack:** Simultaneous HID (FIDO2) and CDC (COM) interfaces.
*   **Dual-Threading:** Seamless background hardware polling decoupled from cryptographic computations.
*   **Interactive Display:** 128x32 OLED rendering pipeline with dynamic text scrolling and user confirmation prompts.
*   **Diagnostic Suite:** Built-in hardware and cryptographic self-test manager.

## Hardware Requirements & Wiring

This project is built for the ESP32-S3 microcontroller. It requires an SSD1306 SPI OLED display and an Adafruit/Synochip optical fingerprint scanner.

### Pinout Configuration

**Fingerprint Scanner (UART):**
*   Green -> GND
*   Orange -> PIN 17 (TX)
*   Yellow -> PIN 16 (RX)
*   White -> 3V3
*   Red -> Not Connected
*   Black -> 3V3

**OLED Display (SSD1306 - SPI):**
*   GND -> GND
*   VCC -> 3V3
*   SCK -> PIN 12
*   SDA -> PIN 11
*   RES -> PIN 13
*   DC -> PIN 9
*   CS -> PIN 10

## Command Line Interface (CLI)

The device exposes a secure serial console (COM/CDC) that utilizes ECDH (Curve25519/X25519) key exchange to establish an AES-encrypted session. 

Available commands upon successful authentication:

*   `help`            - Display the command documentation menu
*   `list`            - List all stored account identifiers
*   `info`            - Show system storage stats and SPIFFS space
*   `create`          - Securely save a new account and password
*   `get`             - Retrieve an existing password by name
*   `delete`          - Permanently wipe a password from storage
*   `list_fido`       - List all saved FIDO2 website names
*   `get_fido`        - Read stored FIDO2 website info and users
*   `delete_fido`     - Wipe a FIDO2 website and all saved keys
*   `totp_add`        - Add a new Base32 TOTP secret
*   `totp_get`        - Generate a 6-digit TOTP code
*   `delete_pin`      - FACTORY RESET (Wipes PIN, Vault, and Fingerprints)
*   `delete_pass`     - Purge vault passwords and passkeys
*   `diagnostics`     - Run automated verification testing suite
*   `set_crypto`      - Set default FIDO2 crypto alg (-7, -8, -257, -48, -49, -50)
*   `register_finger` - Register a new fingerprint for hardware approval

## License

This project is licensed under the MIT License. See the LICENSE file for details.