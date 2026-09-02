# SwissSec

> Swiss Knife for all your cybersecurity needs

SwissSec is an advanced, hardware-based cybersecurity multitool built on the ESP32-S3. It serves as a secure password vault, a fully compliant FIDO2/WebAuthn authenticator, and a TOTP generator. Featuring biometric authentication, True Random Number Generation (TRNG), AES-GCM encryption, and cutting-edge Post-Quantum Cryptography (ML-DSA), SwissSec provides enterprise-grade security in a portable, self-contained hardware token.

---

## Key Features

### Chrome Extension Integration

* **WebSerial Hardware Link:** Establishes an encrypted WebSerial connection directly with the ESP32-S3 board through `dashboard.html` using ECDH P-256 key exchange and AES-GCM encryption.


* **Context Menu Autofill:** Right-click context menu options to autofill saved credentials or automatically generate and save new passwords for the active domain.


* **Live TOTP Dashboard:** Displays dynamic 6-digit TOTP codes with a 30-second progress timer and one-click copy-to-clipboard functionality.


* **Vault & Key Management:** Search, add, and delete stored passwords, FIDO2 passkeys, and TOTP secrets directly from the browser popup.


* **Biometric & Hardware Notifications:** Prompts badge alerts (`TOUCH`) and open popups whenever physical fingerprint approval is required by the ESP32 hardware.


* **Hardware Administration & Diagnostics:** Trigger fingerprint enrollments, change default FIDO2 cryptographic algorithms, or run automated subsystem diagnostics from the settings tab.



### Advanced Cryptography & FIDO2

* **FIDO2 & WebAuthn Compliant:** Supports MakeCredential and GetAssertion flows, Resident Passkeys, and the CTAP2 HID protocol.


* **Post-Quantum Ready:** Implements ML-DSA (44, 65, 87) alongside standard algorithms (ES256, Ed25519, RS256).


* **FIDO2 Extensions:** Supports the `hmac-secret` extension for offline login environments like Windows Hello.


* **Backwards Compatibility:** Includes support for legacy U2F protocols.


* **Dynamic Custom AAGUID:** Hardware-derived Authenticator Attestation GUID.



### Secure Vault & Storage

* **Hardware Password Manager:** Store credentials encrypted with AES-GCM.


* **TOTP Authenticator:** Generate time-based 6-digit codes via a standard HMAC-SHA1 moving counter.


* **Protected Storage:** Pure binary and JSON-based EEPROM/SPIFFS storage for FIDO2 keys and passwords.


* **PBKDF2 Derivation:** Master PIN securely derived using PBKDF2 with strict iteration limits.



### Biometric & Hardware Security

* **Biometric User Verification (UV):** Fingerprint enrollment and verification tied directly to credential access and FIDO2 assertions.


* **Anti-Glitching Defenses:** Includes random delays, magic state validation, and multi-byte constraints to thwart physical fault injection attacks.


* **Brute-Force Protection:** Secure wipe triggered automatically after 10 invalid PIN attempts.


* **Challenge-Response Fingerprint Protocol:** Cryptographically secure validation between the MCU and the biometric sensor.


* **TRNG Integration:** Entropy sourced via RF noise for true cryptographic randomness.



---

## How It Works

1. **Hardware Connection & Handshake:** Opening the terminal establishes a WebSerial serial connection with the ESP32-S3. The extension and hardware execute an ECDH key exchange to encrypt all serial communication with AES-GCM.


2. **Authentication:** The user unlocks the device by submitting the master PIN or verifying a registered fingerprint through the popup interface or hardware sensor.


3. **Password Autofill:** When visiting a website, right-clicking on an input field allows you to select **Autofill Saved Password** or **Generate ESP32 Password & Save**. The extension requests the credential from the ESP32-S3 over the secure tunnel and automatically fills in the password input on the active page.


4. **TOTP Generation:** Opening the TOTP tab retrieves current epoch-synchronized 6-digit codes from the hardware, automatically updating the countdown timer every second.



---

## Chrome Extension Installation

1. Open Google Chrome (or any Chromium-based browser like Brave or Edge).
2. Navigate to `chrome://extensions/` in your address bar.
3. Enable **Developer mode** using the toggle switch in the top-right corner.
4. Click the **Load unpacked** button in the top-left menu.
5. Select the extension directory containing `manifest.json`, `background.js`, `popup.html`, and `dashboard.html`.


6. Click the extension icon in your browser toolbar, then click **Open Hardware Terminal** to connect your ESP32-S3 board over WebSerial.



---

## Hardware Requirements & Wiring

This project is built for the ESP32-S3 microcontroller. It requires an SSD1306 SPI OLED display and an Adafruit/Synochip optical fingerprint scanner.

### Pinout Configuration

**Fingerprint Scanner (UART):**

* Green -> GND


* Orange -> PIN 17 (TX)


* Yellow -> PIN 16 (RX)


* White -> 3V3


* Red -> Not Connected


* Black -> 3V3



**OLED Display (SSD1306 - SPI):**

* GND -> GND


* VCC -> 3V3


* SCK -> PIN 12


* SDA -> PIN 11


* RES -> PIN 13


* DC -> PIN 9


* CS -> PIN 10


---

# Project Todo & Development Roadmap

## Completed Milestones

### Core Cryptography & Security
* [x] **Key Exchange:** Implemented Curve25519/X25519 key exchange protocol.
* [x] **PBKDF2 Integration:** Added Password-Based Key Derivation Function 2 for master PIN handling and storage key derivation.
* [x] **AES-GCM Encryption:** Integrated hardware AES Accelerator for authenticated file encryption (GCM mode).
* [x] **True Random Number Generator (TRNG):** Implemented RF noise-based entropy sourcing for cryptographically secure password generation.
* [x] **Fault Injection Countermeasures:** Added defenses against glitching (random multi-byte constraints, variable execution delays, etc.).
* [x] **Side-Channel Protection:** Implemented constant-time memory comparison for PINs and hashes to prevent timing attacks.
* [x] **Memory Sanitization:** Ensured sensitive data, passwords, and passkeys are securely wiped from RAM immediately after use.
* [x] **Core Architecture & Obfuscation:** Established core system design and code obfuscation routines.
* [x] **Advanced Threat Defenses:** Added comprehensive protections against Serial Port Sniffing, Keylogging, and Fake Prompt (MitM) attacks.

### Hardware & Peripherals
* [x] **Command Prompt Optimization:** Refined command input parsing routines for credential extraction to accelerate operations.
* [x] **Modular Architecture:** Refactored the monolithic codebase into separate, maintainable source files.
* [x] **OLED Notification Interface:** Integrated a dedicated OLED screen and hardware button for asynchronous confirmation workflows (e.g., verifying password transmission).
* [x] **Biometric Authentication:** Restored fingerprint scanner integration with challenge-response verification flows.
* [x] **Emergency Wipe Mechanism:** Implemented secure credential wiping after 10 consecutive failed PIN attempts, including full list deletion.
* [x] **Peripheral Fallbacks:** Included support for alternative physical input (button fallback) and display options (OLED vs. LCD).

### USB & FIDO2 / U2F Integration
* [x] **Dual-Interface USB Stack:** Implemented a USB Composite Stack supporting simultaneous HID and CDC/COM port operation.
* [x] **Host Validation:** Verified device enumeration and stability via Windows Device Manager.
* [x] **FIDO HID Compliance:** Injected the official FIDO HID Report Descriptor and corrected CTAP2 HID framing mechanics.
* [x] **P-256 ECC Support:** Expanded the cryptographic engine to support ECDSA P-256 with dedicated test suites in `SelfTestManager.cpp`.
* [x] **CBOR Parser Engine:** Integrated and tested a robust CBOR parsing engine validated against the official FIDO2 Python library.
* [x] **Resident Passkeys:** Updated storage architecture to manage resident passkey records and credential objects.
* [x] **Session Management:** Implemented transaction timeouts, keepalive signals, and a 500ms channel lockout mechanism for stalled multi-packet transactions.
* [x] **User Verification Routing:** Tied FIDO2 user verification directly to the biometric fingerprint scanner loop.
* [x] **FIDO2 Core Flows:** Fully operational `MakeCredential` and `GetAssertion` pipelines, including authenticator data structuring, signature generation, and authentication.
* [x] **Compatibility & Attestation:** Added FIDO U2F backward compatibility, fixed double-reading edge cases, and implemented attestation signing options.
* [x] **FIDO Management Tools:** Added routines to list registered FIDO2 origins and selectively manage or delete individual credentials.
* [x] **Request Filters:** Implemented strict validation for `excludeList` (preventing duplicate registrations) and `allowList` (rejecting unknown credentials prior to biometric prompts).
* [x] **Asynchronous Cancellation:** Implemented robust handling for the `CTAPHID_CANCEL` (0x91) command.

### Post-Quantum Cryptography (PQC)
* [x] **Dynamic Heap & PQC Integration:** Introduced dynamic heap buffering and architectural support for Post-Quantum algorithms.
* [x] **ML-DSA Implementation:** Integrated working implementations of ML-DSA (44, 65, and 87) within the FIDO2 stack.
* [x] **Performance & Stability Fixes:** Resolved memory exhaustion bugs causing ESP32-S3 lockups during ML-DSA-65/87 registrations and optimized RS256 performance.

### Password Manager & Dashboard
* [x] **Core Refactoring:** Unified and stabilized the password manager architecture.
* [x] **Storage Optimization:** Migrated key storage from JSON format to a high-efficiency binary structure.
* [x] **Dual-Threaded Architecture:** Implemented task offloading and dual-threading to segregate crypto/USB handling from UI tasks.
* [x] **User Interface & Feedback:** Implemented smooth left-to-right text scrolling for long strings on the OLED display and automated screen-clearing timeouts.
* [x] **Web Dashboard:** Developed a comprehensive web-based interface for testing all system capabilities, managing vault statistics, adding new records via popup, and adjusting hardware settings.
* [x] **Security Hardening (Dashboard):** Ensured the dashboard UI prevents third-party scripts from reading or exposing raw plaintext passwords and sensitive data.
* [x] **TOTP Integration:** Added Time-based One-Time Password generation with an enhanced management interface.
* [x] **Autofill & Parsing:** Refined browser integration scripts, registration interception, login detection, and resolved intermittent auto-fill failure bugs.
* [x] **Code Quality:** Comprehensive cleanup of inline documentation, comments, and project licensing for GitHub publication.

## Pending Roadmap & Future Tasks

### Hardware & Protocol Expansion
* [x] **Device Detection:** Implement automatic detection routines to verify when the ESP32-S3 is plugged in for browser plugin communication.
* [x] **Connection Broadcasting:** Broadcast FIDO2 connection status messages when requested by web applications.
* [ ] **Advanced CTAP2 Commands:**
  * [ ] Client PIN (Command `0x06`)
  * [ ] GetNextAssertion (Command `0x08`)
  * [ ] Authenticator Reset (Command `0x07`)
  * [ ] Credential Management API (Command `0x0A`)
  * [ ] Stateless Credentials (Non-Resident Keys support)
* [ ] **CTAP 2.1 Extensions:** Implement support for modern extensions including `largeBlob`, `credProtect`, and `alwaysUv`.
* [ ] **PQC Protocol Alignment:** Align the existing ML-DSA implementation (`algId == -48`) with finalized FIDO Alliance Post-Quantum Cryptography drafts.

### Security Auditing & Hardening
* [x] **Biometric Replay Mitigation:** Implement countermeasures against fingerprint sensor replay attacks.
* [x] **OLED Bus Security:** Secure I2C/SPI communications against bus sniffing and spoofing.
* [x] **Nonce Security:** Ensure strict entropy separation to prevent AES-GCM nonce reuse vulnerabilities.
* [x] **Parser Hardening:** Conduct fuzz testing and defensive hardening for CBOR and WebAuthn packet parsing pipelines against malformed inputs.
* [ ] **Credential Health Audit:** Implement security auditing for `/passwords.json` to flag weak, reused, or compromised passwords.

### Backup, Recovery, & Architecture
* [ ] **Encrypted Backup Solutions:** Architect a secure, user-controlled export/import mechanism for offline backup and recovery.
* [ ] **Technical Documentation:** Draft comprehensive technical documentation covering hardware schematics, firmware structure, and protocol flows.
* [ ] **Mobile Companion Application:** Explore the feasibility of a companion mobile application for credential management.
* [ ] **Browser Extension Security:** Audit the browser extension pipeline against malicious script injections and clickjacking vectors.
* [ ] **Physical Security (PCB):** Design a custom Printed Circuit Board (PCB) integrating physical tamper-mesh layers and environmental sensors.

---

## License

This project is licensed under the GNU GPL License. See the LICENSE file for details.