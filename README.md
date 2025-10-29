# 🔐 CryptDir Pro v2.10.5
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.7%2B-306998?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)

A high-security, streaming file and folder encryption tool built with Python and Tkinter. Designed by `COLDMAN` for professional-grade security with a user-friendly interface.

This tool is designed to handle directories of any size—from a few files to terabytes—by streaming data in 64KB chunks, ensuring low memory usage even when processing massive files.

*(A screenshot of the main application window)*

---

## ⚡ Key Features

* **AES-256-CTR + HMAC-SHA256:** Uses industry-standard, production-grade authenticated encryption (Encrypt-then-MAC) to protect against both eavesdropping and data-tampering.
* **Secure Key Derivation:** Employs **PBKDF2** with 100,000 iterations to stretch your password, making brute-force attacks extremely difficult.
* **Streaming Encryption:** Processes files in small chunks, allowing it to encrypt/decrypt massive files (50GB+) with minimal RAM usage.
* **"Test Decrypt" Utility:** Safely verifies file integrity and password correctness by checking the HMAC signature *without* decrypting, modifying, or writing any data.
* **Robust Error Handling:**
    * **Atomic Operations:** Uses temporary files (`.encrypting`, `.decrypting`) and atomic `os.replace` calls to ensure your original files are safe, even if the operation is cancelled or fails.
    * **Automatic Backups:** Creates a `.backup_temp` of the original file before processing and automatically restores it if any error occurs.
* **Flexible Processing Modes:**
    * **Folder Mode:** Recursively processes every file in a directory (uses a fast, single-pass scan).
    * **Files Mode:** Allows you to hand-pick specific files for processing.
* **Password Strength Meter:** Provides real-time feedback on your password's strength.
* **Windows Folder Utility:** Includes a button to quickly toggle the "Hidden" and "System" attributes for the target folder.

---

## 🚀 How to Use

This application is **Windows-only**.

### Option 1: Download the .exe (Recommended)

This is the easiest method for most users. No Python or setup required.

1.  Go to the [**Releases Page**](https://github.com/YOUR_USERNAME/YOUR_REPOSITORY/releases) of this repository.
2.  Download the latest `CryptDir_Pro.exe` file.
3.  Place the `.exe` in any folder and double-click to run it.

### Option 2: Run from Python Source

This is for developers or users who prefer to run directly from the source code.

**Requirements:**
* Windows 10 / 11
* Python 3.7+
* Required library: `cryptography`

**Running:**
1.  Install the required library:
    ```sh
    pip install cryptography
    ```
2.  Download the `CryptDir_ProV2.10.5_secure_streaming.py` file.
3.  Run the script from your terminal:
    ```sh
    python CryptDir_ProV2.10.5_secure_streaming.py
    ```

---

## 🛡️ Security Model

Security is the primary focus of this tool. It does not roll its own crypto and relies on the standard `cryptography` library.

* **Cipher:** AES-256 in Counter (CTR) mode. CTR is a streaming mode, making it ideal for files of any size.
* **Authentication:** HMAC with SHA-256. This is applied *after* encryption (Encrypt-then-MAC) to create an authenticated ciphertext. Any modification to the encrypted file will cause the HMAC verification to fail, preventing decryption of corrupt or tampered data.
* **Key Derivation (KDF):** PBKDF2-HMAC-SHA256.
    * **Iterations:** `100,000`
    * **Salt:** A 16-byte random salt is automatically generated (`salt.key`) or can be provided manually.
    * **Output Key:** 64 bytes (32 bytes for the AES encryption key, 32 bytes for the HMAC authentication key).

### Versioned File Format

The tool uses a custom, versioned file format (v2.10) to ensure future compatibility.

| Offset | Length | Description |
| :--- | :--- | :--- |
| `0` | 5 bytes | Magic Bytes (`b'CDPRO'`) |
| `5` | 2 bytes | Version (`b'\x02\x0A'`) |
| `7` | 1 byte | Reserved (`b'\x00'`) |
| `8` | 16 bytes | Initialization Vector (IV) |
| `24` | 8 bytes | Original File Size (Struct `<Q`) |
| `32` | `N` bytes | Encrypted Data |
| `32+N` | 32 bytes | HMAC-SHA256 Tag |

---

## ⚠️ !! CRITICAL WARNING !! ⚠️

This is a powerful encryption tool. Failure to follow instructions **WILL** result in permanent data loss.

1.  **NO RECOVERY:** If you lose your **Password** OR your **`salt.key` file** (if one was generated), your data is **PERMANENTLY AND IRRECOVERABLY LOST.** There is no backdoor.
2.  **BACKUP FIRST:** Always back up your important files to a separate location *before* performing any encryption or decryption.
3.  **DO NOT INTERRUPT:** While the tool has safeguards, forcefully killing the process (e.g., via Task Manager) or a sudden power loss during an operation *may* corrupt the file being processed. Always use the "CANCEL OPERATION" button.

The author (`COLDMAN`) is not responsible for any data loss or damage resulting from the use of this software. **Use at your own risk.**

---

## License

This project is licensed under the MIT License.
