# 🔐 CryptDir Pro v3

![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.9%2B-306998?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)

A streaming file and folder encryption tool built with Python and Tkinter, by `COLDMAN`.

It handles anything from a few files to multi-terabyte folders by processing data in 64KB chunks, so memory use stays low even for very large files.

*(Add a screenshot of the main window here)*

---

## ⚡ Key Features

* **AES-256-CTR + HMAC-SHA256:** Authenticated encryption (Encrypt-then-MAC). Any change to an encrypted file makes verification fail, and nothing is decrypted until the MAC checks out.
* **PBKDF2-HMAC-SHA256 with 600,000 iterations** to stretch your password.
* **Streaming processing:** Large files (50GB+) use minimal RAM.
* **Test Decrypt:** Verifies the password, salt and file integrity by checking the HMAC only. It never modifies or writes any file.
* **Safe, atomic writes:**
  * Output goes to a temporary file (`.encrypting` / `.decrypting`), is flushed to disk with `fsync`, and only then replaces the original with `os.replace`.
  * If you cancel, hit an error, or lose power mid-file, the original stays intact.
  * File timestamps and permissions are preserved.
* **Pre-flight checks:** Free disk space is checked before each file, and already-encrypted files are skipped instead of being encrypted twice.
* **Wrong-password protection:** Decrypt and test runs stop after 3 consecutive HMAC failures, so a wrong password doesn't read your whole folder. One damaged file won't stop the rest of the batch.
* **Stale temp cleanup:** Leftover `.encrypting` / `.decrypting` files older than 24 hours are removed at the start of an encrypt or decrypt run. Test runs never delete anything.
* **Two processing modes:** Entire folder (recursive) or hand-picked files.
* **Skips what it shouldn't touch:** `salt.key`, symlinks, temp files, legacy `.backup_temp` files, and the application itself.
* **Password strength meter,** enforced when encrypting. Decrypt and test accept any password, so older files stay reachable.
* **Windows folder utility:** Toggles the Hidden and System attributes on the target folder.

---

## 🚀 How to Use

### Option 1: Download the .exe

1. Go to the [**Releases Page**](https://github.com/YOUR_USERNAME/YOUR_REPOSITORY/releases).
2. Download the latest `CryptDirPro.exe`.
3. Place it **outside** any folder you plan to encrypt, then double-click to run.

Some antivirus tools flag single-file PyInstaller executables of encryption tools. This is a known false positive. Building with `--onedir` or running from source avoids it.

### Option 2: Run from Python source

**Requirements:** Windows 10/11, Python 3.9+, and the `cryptography` library.

```sh
pip install cryptography
python cryptdir_pro.py
```

### Build your own exe

```sh
pip install pyinstaller cryptography
pyinstaller --onefile --windowed --name CryptDirPro cryptdir_pro.py
```

The result is `dist\CryptDirPro.exe`.

### Typical workflow

1. Click **Browse** and choose a folder (or switch to *Select Specific Files*).
2. Enter a password. For encryption it needs 8+ characters with upper case, lower case and a number.
3. Leave the salt options alone for the default: a random salt is saved as `salt.key` in the folder.
4. Click **ENCRYPT**. To check the result later, use **TEST DECRYPT**. To restore, use **DECRYPT** with the same password.

---

## 🛡️ Security Model

The tool uses the standard `cryptography` library and does not implement its own primitives.

* **Cipher:** AES-256 in CTR mode with a fresh random 16-byte IV per file.
* **Authentication:** HMAC-SHA256 over the header and the ciphertext. It is verified over the whole file **before** any plaintext is written.
* **Key derivation:** PBKDF2-HMAC-SHA256, 600,000 iterations, 64-byte output (32 bytes for AES, 32 bytes for HMAC).
* **Salt:** 16 random bytes stored in `salt.key`, or a manual salt you supply (16+ characters recommended). The salt is not secret, but you need it to decrypt. One salt is shared by every file in a run, and an existing `salt.key` is reused so earlier files stay decryptable.

### File format (v2.11)

| Offset | Length | Description |
| :--- | :--- | :--- |
| `0` | 5 bytes | Magic bytes (`b'CDPRO'`) |
| `5` | 2 bytes | Version (`b'\x02\x0B'`) |
| `7` | 1 byte | Reserved (`b'\x00'`) |
| `8` | 16 bytes | Initialization vector (IV) |
| `24` | 8 bytes | Original file size (`<Q`) |
| `32` | `N` bytes | Encrypted data |
| `32+N` | 32 bytes | HMAC-SHA256 tag (covers header + data) |

Files written by older v2.x builds can still be read. Files from a newer format version are refused.

### Known limitations

* File names, folder structure and file sizes are **not** hidden.
* Every file in a run uses the same salt and key. Don't mix different passwords in one folder: already-encrypted files are skipped, so a second run with a new password leaves them under the old one.
* Cancelling mid-run is safe for the original file, but the batch is only partly processed.

---

## ⚠️ Critical Warning

This is a powerful encryption tool. Mistakes can cause permanent data loss.

1. **No recovery.** If you lose your **password** or your **`salt.key`** (or manual salt), your data is permanently and irrecoverably lost. There is no backdoor. Keep a copy of `salt.key` somewhere other than the encrypted folder.
2. **Back up first.** Copy important files elsewhere before encrypting or decrypting.
3. **Prefer Cancel to killing the process.** The original file is protected by atomic replacement, but a forced kill can leave a `.encrypting` / `.decrypting` temp file behind. It is cleaned up automatically after 24 hours.

The author (`COLDMAN`) is not responsible for data loss or damage resulting from use of this software. **Use at your own risk.**

---

## License

MIT License.
