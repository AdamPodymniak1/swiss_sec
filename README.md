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

## Command Line Interface (CLI)

The device exposes a secure serial console (COM/CDC) that utilizes ECDH (Curve25519/X25519) key exchange to establish an AES-encrypted session.

Available commands upon successful authentication:

* `help`            - Display the command documentation menu


* `list`            - List all stored account identifiers


* `info`            - Show system storage stats and SPIFFS space


* `create`          - Securely save a new account and password


* `get`             - Retrieve an existing password by name


* `delete`          - Permanently wipe a password from storage


* `list_fido`       - List all saved FIDO2 website names


* `get_fido`        - Read stored FIDO2 website info and users


* `delete_fido`     - Wipe a FIDO2 website and all saved keys


* `totp_add`        - Add a new Base32 TOTP secret


* `totp_get`        - Generate a 6-digit TOTP code


* `delete_pin`      - FACTORY RESET (Wipes PIN, Vault, and Fingerprints)


* `delete_pass`     - Purge vault passwords and passkeys


* `diagnostics`     - Run automated verification testing suite


* `set_crypto`      - Set default FIDO2 crypto alg (-7, -8, -257, -48, -49, -50)


* `register_finger` - Register a new fingerprint for hardware approval



---

## License

This project is licensed under the GNU GPL License. See the LICENSE file for details.