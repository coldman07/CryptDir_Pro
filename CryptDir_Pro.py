import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk, Listbox, Scrollbar
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
import threading
import queue
import ctypes
import sys
import re
import struct
import time
import shutil

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

SALT_FILENAME = 'salt.key'
BACKUP_EXTENSION = '.backup_temp'
CHUNK_SIZE = 64 * 1024
MIN_PASSWORD_LENGTH = 8
MIN_MANUAL_SALT_LENGTH = 16
PBKDF2_ITERATIONS = 600000

MAGIC_BYTES = b'CDPRO'
VERSION_BYTES = b'\x02\x0B'
RESERVED_BYTE = b'\x00'
FILE_HEADER_PREFIX = MAGIC_BYTES + VERSION_BYTES + RESERVED_BYTE
HEADER_SIZE = 32
MAC_SIZE = 32

LARGE_FILE_WARNING_SIZE = 50 * 1024 * 1024 * 1024

# ----------------------------------------------------------------------
# Core Encryption/Decryption Logic
# ----------------------------------------------------------------------

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password should contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password should contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password should contain at least one number."
    return True, "Password is strong."


def validate_manual_salt(salt_str: str) -> tuple[bool, str]:
    if len(salt_str) < MIN_MANUAL_SALT_LENGTH:
        return False, f"Manual salt must be at least {MIN_MANUAL_SALT_LENGTH} characters long."
    if len(set(salt_str)) < 4:
        return False, "Manual salt has low entropy (too few unique characters)."
    return True, "Manual salt is acceptable."


def is_encrypted_file(file_path) -> bool:
    """Returns whether a file begins with the current CryptDir signature."""
    try:
        with open(file_path, 'rb') as f_in:
            return f_in.read(len(FILE_HEADER_PREFIX)) == FILE_HEADER_PREFIX
    except OSError:
        return False


def ensure_temp_space(file_path, required_bytes: int) -> None:
    """Fail before writing when the destination volume lacks temp-file space."""
    free_bytes = shutil.disk_usage(os.path.dirname(os.path.abspath(file_path))).free
    if free_bytes < required_bytes:
        raise OSError(
            f"Insufficient disk space: need about {required_bytes} bytes, "
            f"but only {free_bytes} bytes are free."
        )


def remove_temp_file(temp_path) -> None:
    try:
        os.remove(temp_path)
    except OSError:
        pass


def should_skip_file(file_path, file_name):
    """Determines if a file should be skipped during processing."""
    if file_name.endswith(BACKUP_EXTENSION):
        return True, "backup file"
    if file_name.endswith(('.encrypting', '.decrypting')):
        return True, "temporary file"
    if os.path.islink(file_path):
        return True, "symbolic link"
    try:
        script_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        if os.path.abspath(file_path) == script_path:
            return True, "application executable"
    except Exception:
        pass
    if file_name == SALT_FILENAME:
        return True, "salt file"
    return False, ""


def _remove_if_stale(file_path, log_callback, min_age_seconds):
    try:
        if time.time() - os.path.getmtime(file_path) < min_age_seconds:
            return
        os.remove(file_path)
        log_callback(f"🧹 Cleaned up stale temp file: {file_path}")
    except FileNotFoundError:
        pass
    except OSError as error:
        log_callback(f"⚠️ Could not remove stale temp file {file_path}: {error}")


def count_encrypted_files(directory_path, file_list=None) -> int:
    """Count existing encrypted inputs before an encryption run."""
    if file_list is not None:
        candidates = file_list
    else:
        candidates = (
            os.path.join(root, name)
            for root, _, names in os.walk(directory_path, followlinks=False)
            for name in names
        )
    count = 0
    for path in candidates:
        if os.path.islink(path):
            continue
        if should_skip_file(path, os.path.basename(path))[0]:
            continue
        if is_encrypted_file(path):
            count += 1
    return count


def encrypt_file(file_path, key, log_callback, stop_event=None):
    encryption_key = key[:32]
    hmac_key = key[32:64]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())

    temp_path = file_path + '.encrypting'

    try:
        if stop_event and stop_event.is_set():
            log_callback(f"⊘ Skipped (cancelled before start): {file_path}")
            return False, 0
            
        if is_encrypted_file(file_path):
            log_callback(f"Skipped (already encrypted): {file_path}")
            return True, 0

        file_size = os.path.getsize(file_path)
        ensure_temp_space(file_path, file_size + HEADER_SIZE + MAC_SIZE)
        
        if file_size > LARGE_FILE_WARNING_SIZE:
             log_callback(f"⚠️ Large file ({file_size // (1024**3)}GB): {file_path}")

        log_callback(f"⏳ Encrypting ({file_size // (1024*1024)}MB): {file_path}")

        with open(file_path, 'rb') as f_in, open(temp_path, 'wb') as f_out:
            header = FILE_HEADER_PREFIX + iv + struct.pack('<Q', file_size)
            f_out.write(header)
            h.update(header)
            
            bytes_processed = 0
            while True:
                if stop_event and stop_event.is_set():
                    raise InterruptedError("Operation cancelled by user")
                
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                encrypted_chunk = encryptor.update(chunk)
                f_out.write(encrypted_chunk)
                h.update(encrypted_chunk)
                
                bytes_processed += len(chunk)
                if bytes_processed % (20 * 1024 * 1024) == 0:
                     log_callback(f"  ... {bytes_processed // (1024*1024)}MB processed")

            final_data = encryptor.finalize()
            if final_data:
                f_out.write(final_data)
                h.update(final_data)
            
            mac_tag = h.finalize()
            f_out.write(mac_tag)
            f_out.flush()
            os.fsync(f_out.fileno())
        
        shutil.copystat(file_path, temp_path)
        os.replace(temp_path, file_path)
            
        log_callback(f"✔ Encrypted: {file_path}")
        return True, file_size
        
    except InterruptedError:
        log_callback(f"⚠️ CANCELLED during encryption: {file_path}")
        log_callback(f"   Original file is unchanged; removing temporary output.")
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        return False, 0
    except PermissionError:
        log_callback(f"✗ Permission denied: {file_path}")
        remove_temp_file(temp_path)
        return False, 0
    except OSError as e:
        log_callback(f"✗ Unable to encrypt {file_path}: {e}")
        remove_temp_file(temp_path)
        return False, 0
    except Exception as e:
        log_callback(f"✗ Error encrypting {file_path}: {e}")
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return False, 0
def decrypt_file(file_path, key, log_callback, stop_event=None, invalid_key_event=None):
    encryption_key = key[:32]
    hmac_key = key[32:64]

    temp_path = file_path + '.decrypting'
    
    try:
        if stop_event and stop_event.is_set():
            log_callback(f"⊘ Skipped (cancelled before start): {file_path}")
            return False, 0
            
        file_size = os.path.getsize(file_path)

        if file_size > LARGE_FILE_WARNING_SIZE:
             log_callback(f"⚠️ Large file ({file_size // (1024**3)}GB): {file_path}")
             log_callback(f"   (Decryption requires two full reads: ~{ (file_size * 2) // (1024**3) }GB I/O)")
        
        log_callback(f"⏳ Decrypting ({file_size // (1024*1024)}MB): {file_path}")
        
        with open(file_path, 'rb') as f_in:
            header = f_in.read(HEADER_SIZE)
            if len(header) != HEADER_SIZE:
                raise ValueError(f"Invalid file format: header too short (expected {HEADER_SIZE} bytes).")
            
            if header[:8] != FILE_HEADER_PREFIX:
                if header[:5] == MAGIC_BYTES:
                    file_version = header[5:7]
                    log_callback(f"  -> ℹ Processing legacy file format (v{file_version[0]}.{file_version[1]}).")
                else:
                    raise ValueError("Invalid file format: not a CryptDir file or corrupted header.")
            
            file_version = header[5:7]
            if file_version > VERSION_BYTES:
                log_callback(f"  -> ⚠️ File version ({file_version[0]}.{file_version[1]}) is NEWER than app version ({VERSION_BYTES[0]}.{VERSION_BYTES[1]}).")
                raise ValueError("File version is too new to decrypt.")
            
            iv = header[8:24]
            expected_size = struct.unpack('<Q', header[24:32])[0]
            
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(header)
            
            encrypted_data_size = file_size - HEADER_SIZE - MAC_SIZE
            
            if encrypted_data_size < 0:
                raise ValueError("Invalid file format: file too small for header + MAC")
            
            bytes_verified = 0
            
            while bytes_verified < encrypted_data_size:
                if stop_event and stop_event.is_set():
                    raise InterruptedError("Operation cancelled by user")
                
                remaining = encrypted_data_size - bytes_verified
                chunk_size = min(CHUNK_SIZE, remaining)
                chunk = f_in.read(chunk_size)
                
                if not chunk:
                    raise ValueError("Unexpected end of file during HMAC verification")
                
                h.update(chunk)
                bytes_verified += len(chunk)
                
                if bytes_verified % (20 * 1024 * 1024) == 0:
                    log_callback(f"  ... verifying {bytes_verified // (1024*1024)}MB")
            
            stored_mac = f_in.read(MAC_SIZE)
            if len(stored_mac) != MAC_SIZE:
                raise ValueError("Invalid file format: MAC tag missing or truncated")
            
            try:
                h.verify(stored_mac)
            except InvalidSignature:
                raise InvalidSignature("HMAC verification failed: wrong password or corrupted file")
            
            log_callback(f"  ✔ HMAC verified successfully")
            
            ensure_temp_space(file_path, expected_size)
            f_in.seek(HEADER_SIZE)
            
            cipher = Cipher(
                algorithms.AES(encryption_key), 
                modes.CTR(iv), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            with open(temp_path, 'wb') as f_out:
                bytes_decrypted = 0
                
                while bytes_decrypted < encrypted_data_size:
                    if stop_event and stop_event.is_set():
                        raise InterruptedError("Operation cancelled by user")
                    
                    remaining = encrypted_data_size - bytes_decrypted
                    chunk_size = min(CHUNK_SIZE, remaining)
                    encrypted_chunk = f_in.read(chunk_size)
                    
                    if not encrypted_chunk:
                        raise ValueError("Unexpected end during decryption")
                    
                    decrypted_chunk = decryptor.update(encrypted_chunk)
                    f_out.write(decrypted_chunk)
                    bytes_decrypted += len(encrypted_chunk)
                    
                    if bytes_decrypted % (20 * 1024 * 1024) == 0:
                        log_callback(f"  ... decrypting {bytes_decrypted // (1024*1024)}MB")
                
                final_data = decryptor.finalize()
                if final_data:
                    f_out.write(final_data)
                f_out.flush()
                os.fsync(f_out.fileno())

            decrypted_size = os.path.getsize(temp_path)
            if decrypted_size != expected_size:
                raise ValueError(
                    f"File integrity check failed: "
                    f"expected {expected_size} bytes, got {decrypted_size}"
                )

        shutil.copystat(file_path, temp_path)
        os.replace(temp_path, file_path)
            
        log_callback(f"✔ Decrypted: {file_path}")
        return True, expected_size

    except InterruptedError:
        log_callback(f"⚠️ CANCELLED during decryption: {file_path}")
        if os.path.exists(temp_path):
            log_callback("   Original file is unchanged; removing temporary output.")
        else:
            log_callback("   Original file is unchanged.")
        if os.path.exists(temp_path): 
            try:
                os.remove(temp_path)
            except OSError:
                pass
        return False, 0
    except (InvalidSignature, ValueError, TypeError, struct.error) as e:
        error_msg = str(e)
        if "HMAC" in error_msg:
            if invalid_key_event is not None:
                invalid_key_event.set()
            log_callback(f"✗ Invalid password or corrupted: {file_path}")
        elif "format" in error_msg:
            log_callback(f"✗ Not a valid CryptDir file: {file_path}")
        elif "integrity" in error_msg:
             log_callback(f"✗ File corrupted (size mismatch): {file_path}")
        else:
            log_callback(f"✗ Corrupted file or error: {file_path} ({e})")

        if os.path.exists(temp_path): 
            os.remove(temp_path)
        return False, 0
    except PermissionError:
        log_callback(f"✗ Permission denied: {file_path}")
        remove_temp_file(temp_path)
        return False, 0
    except OSError as e:
        log_callback(f"✗ Unable to decrypt {file_path}: {e}")
        remove_temp_file(temp_path)
        return False, 0
    except Exception as e:
        log_callback(f"✗ Error decrypting {file_path}: {e}")
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return False, 0
# ----------------------------------------------------------------------
# Test Decrypt Function (HMAC verification only)
# ----------------------------------------------------------------------

def test_decrypt_file(file_path, key, log_callback, stop_event=None, invalid_key_event=None):
    hmac_key = key[32:64]
    
    try:
        file_size = os.path.getsize(file_path)
        
        if file_size < HEADER_SIZE + MAC_SIZE:
            raise ValueError("Invalid format: file too small.")

        if stop_event and stop_event.is_set():
            log_callback(f"⊘ Skipped (cancelled before start): {file_path}")
            return False, 0

        with open(file_path, 'rb') as f_in:
            header = f_in.read(HEADER_SIZE)
            if len(header) != HEADER_SIZE:
                raise ValueError("Invalid format: header too short.")
            
            if header[:8] != FILE_HEADER_PREFIX:
                if header[:5] == MAGIC_BYTES:
                    file_version = header[5:7]
                    log_callback(f"  -> ℹ Processing legacy file format (v{file_version[0]}.{file_version[1]}).")
                else:
                    raise ValueError("Invalid format: not a CryptDir file.")

            file_version = header[5:7]
            if file_version > VERSION_BYTES:
                raise ValueError("File version is too new to verify.")
                
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(header)
            
            encrypted_data_size = file_size - HEADER_SIZE - MAC_SIZE
            
            if encrypted_data_size < 0:
                raise ValueError("Invalid format: file too small for header + MAC")
            
            bytes_verified = 0
            
            while bytes_verified < encrypted_data_size:
                if stop_event and stop_event.is_set():
                    raise InterruptedError("Operation cancelled")
                
                remaining = encrypted_data_size - bytes_verified
                chunk_size = min(CHUNK_SIZE, remaining)
                chunk = f_in.read(chunk_size)
                
                if not chunk:
                    raise ValueError("Unexpected EOF during HMAC verify")
                
                h.update(chunk)
                bytes_verified += len(chunk)
                
                if bytes_verified % (20 * 1024 * 1024) == 0:
                    log_callback(f"  ... verifying {bytes_verified // (1024*1024)}MB")
            
            stored_mac = f_in.read(MAC_SIZE)
            if len(stored_mac) != MAC_SIZE:
                raise ValueError("Invalid format: MAC tag missing")
            
            try:
                h.verify(stored_mac)
            except InvalidSignature as error:
                raise InvalidSignature(
                    "HMAC verification failed: wrong password or corrupted file"
                ) from error
            
            log_callback(f"✔ VERIFIED: {file_path}")
            return True, file_size

    except InterruptedError:
        log_callback(f"⚠️ CANCELLED during verification: {file_path}")
        return False, 0
    except (InvalidSignature, ValueError, TypeError, struct.error) as e:
        error_msg = str(e)
        if "HMAC" in error_msg:
            if invalid_key_event is not None:
                invalid_key_event.set()
            log_callback(f"✗ Invalid password or corrupted: {file_path}")
        else:
            log_callback(f"✗ Corrupted or invalid file: {file_path} ({e})")
        return False, 0
    except PermissionError:
        log_callback(f"✗ Permission denied: {file_path}")
        return False, 0
    except Exception as e:
        log_callback(f"✗ Error testing {file_path}: {e}")
        return False, 0
# ----------------------------------------------------------------------
# Directory/File Processing
# ----------------------------------------------------------------------

def cleanup_orphaned_backups(directory_path, log_callback, min_age_seconds=24 * 60 * 60,
                             file_list=None):
    """Remove only old temp outputs; never touch backups or recent active work."""
    try:
        temp_suffixes = ('.encrypting', '.decrypting')
        if file_list is not None:
            candidates = (path + suffix for path in file_list for suffix in temp_suffixes)
        else:
            candidates = (
                os.path.join(root, name)
                for root, _, names in os.walk(directory_path)
                for name in names
                if name.endswith(temp_suffixes)
            )
        for path in candidates:
            _remove_if_stale(path, log_callback, min_age_seconds)
        return

        for root, _, files in ():
            for file in files:
                # Preserve legacy backups: after a crash they may be the only
                # recoverable copy. Only stale temporary outputs are safe to
                # remove automatically.
                if file.endswith(('.encrypting', '.decrypting')):
                    file_path = os.path.join(root, file)
                    try:
                        if time.time() - os.path.getmtime(file_path) < min_age_seconds:
                            continue
                        os.remove(file_path)
                        log_callback(f"🧹 Cleaned up orphaned temp file: {file_path}")
                    except Exception as e:
                        log_callback(f"⚠️ Could not remove orphaned file {file_path}: {e}")
    except Exception as e:
        log_callback(f"⚠️ Error during orphaned file cleanup: {e}")


def restore_backup(backup_path, original_path, log_callback):
    """Safely restores a backup file."""
    try:
        if os.path.exists(backup_path):
            # Replace the existing original atomically when restoring.
            os.replace(backup_path, original_path)
            log_callback(f"↻ Restored from backup: {original_path}")
    except Exception as restore_error:
        log_callback(f"✗ CRITICAL: Failed to restore {original_path}: {restore_error}")
        log_callback(f"   Backup may still exist at: {backup_path}")


def process_directory(directory_path, key, operation, log_callback, stop_event,
                     progress_callback, invalid_key_event=None):
    """
    Walks a directory and applies the operation to all files.
    Returns: (success_count, fail_count, skip_count, total_bytes_processed)
    """
    success_count = 0
    fail_count = 0
    skip_count = 0
    total_bytes_processed = 0
    consecutive_hmac_failures = 0

    try:
        for root, _, files in os.walk(directory_path):
            for file in files:
                if stop_event.is_set():
                    log_callback("\n⚠ Operation cancelled by user.")
                    return success_count, fail_count, skip_count, total_bytes_processed
                
                file_path = os.path.join(root, file)
                
                should_skip, skip_reason = should_skip_file(file_path, file)
                
                if should_skip:
                    log_callback(f"⊘ Skipped ({skip_reason}): {file_path}")
                    skip_count += 1
                    continue

                if operation == 'encrypt' and is_encrypted_file(file_path):
                    log_callback(f"Skipped (already encrypted): {file_path}")
                    skip_count += 1
                    continue
                
                success = False
                size = 0
                if operation == 'encrypt':
                    success, size = encrypt_file(file_path, key, log_callback, stop_event)
                elif operation == 'decrypt':
                    success, size = decrypt_file(
                        file_path, key, log_callback, stop_event, invalid_key_event
                    )
                elif operation == 'test':
                    success, size = test_decrypt_file(
                        file_path, key, log_callback, stop_event, invalid_key_event
                    )
                
                if success:
                    success_count += 1
                    total_bytes_processed += size
                else:
                    fail_count += 1
                
                progress_callback()
                if invalid_key_event is not None and invalid_key_event.is_set():
                    invalid_key_event.clear()
                    consecutive_hmac_failures += 1
                    if consecutive_hmac_failures >= 3:
                        log_callback("Stopped after 3 consecutive HMAC failures; check the password or salt.")
                        return success_count, fail_count, skip_count, total_bytes_processed
                else:
                    consecutive_hmac_failures = 0
        
        return success_count, fail_count, skip_count, total_bytes_processed
            
    except Exception as e:
        log_callback(f"\n✗ Critical error during directory processing: {e}")
        return success_count, fail_count, skip_count, total_bytes_processed


def process_selected_files(file_list, key, operation, log_callback, stop_event,
                           progress_callback, base_directory=None, invalid_key_event=None):
    """
    Processes a specific list of files.
    Returns: (success_count, fail_count, skip_count, total_bytes_processed)
    """
    success_count = 0
    fail_count = 0
    skip_count = 0
    total_bytes_processed = 0
    consecutive_hmac_failures = 0

    try:
        for file_path in file_list:
            if stop_event.is_set():
                log_callback("\n⚠ Operation cancelled by user.")
                return success_count, fail_count, skip_count, total_bytes_processed
            
            # Validate file is within base directory (path traversal protection)
            if base_directory:
                try:
                    abs_file = os.path.abspath(file_path)
                    abs_base = os.path.abspath(base_directory)
                    if os.path.commonpath((os.path.realpath(abs_file), os.path.realpath(abs_base))) != os.path.realpath(abs_base):
                        log_callback(f"✗ Path traversal attempt blocked: {file_path}")
                        fail_count += 1
                        progress_callback()
                        continue
                except Exception:
                    log_callback(f"✗ Path validation failed: {file_path}")
                    fail_count += 1
                    progress_callback()
                    continue
            
            file_name = os.path.basename(file_path)
            should_skip, skip_reason = should_skip_file(file_path, file_name)
            if should_skip:
                log_callback(f"Skipped ({skip_reason}): {file_path}")
                skip_count += 1
                progress_callback()
                continue

            if operation == 'encrypt' and is_encrypted_file(file_path):
                log_callback(f"Skipped (already encrypted): {file_path}")
                skip_count += 1
                progress_callback()
                continue

            if not os.path.exists(file_path):
                log_callback(f"✗ File not found (skipped): {file_path}")
                fail_count += 1
                progress_callback()
                continue
            
            success = False
            size = 0
            if operation == 'encrypt':
                success, size = encrypt_file(file_path, key, log_callback, stop_event)
            elif operation == 'decrypt':
                success, size = decrypt_file(
                    file_path, key, log_callback, stop_event, invalid_key_event
                )
            elif operation == 'test':
                success, size = test_decrypt_file(
                    file_path, key, log_callback, stop_event, invalid_key_event
                )
            
            if success:
                success_count += 1
                total_bytes_processed += size
            else:
                fail_count += 1
            
            progress_callback()
            if invalid_key_event is not None and invalid_key_event.is_set():
                invalid_key_event.clear()
                consecutive_hmac_failures += 1
                if consecutive_hmac_failures >= 3:
                    log_callback("Stopped after 3 consecutive HMAC failures; check the password or salt.")
                    return success_count, fail_count, skip_count, total_bytes_processed
            else:
                consecutive_hmac_failures = 0
        
        return success_count, fail_count, skip_count, total_bytes_processed
            
    except Exception as e:
        log_callback(f"\n✗ Critical error during file processing: {e}")
        return success_count, fail_count, skip_count, total_bytes_processed
# ----------------------------------------------------------------------
# GUI Application Class
# ----------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("🔐 CryptDir Pro v2.11.0 Enhanced")
        self.geometry("700x900")
        self.minsize(650, 800)
        
        self._is_closing = False
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Variables
        self.directory_path = tk.StringVar()
        self.disable_salt_var = tk.BooleanVar(value=False)
        self.process_mode = tk.StringVar(value="folder")
        self.selected_files = []
        self.stop_event = threading.Event()
        self.invalid_key_event = threading.Event()
        self.processing_thread = None
        self.current_operation = None
        self._ui_queue = queue.Queue()
        self._progress_mode = 'indeterminate'

        # Color Scheme
        self.bg_dark = "#1a1a1a"
        self.bg_medium = "#2d2d2d"
        self.bg_light = "#3d3d3d"
        self.accent_red = "#e74c3c"
        self.accent_green = "#27ae60"
        self.accent_blue = "#3498db"
        self.accent_yellow = "#f39c12"
        self.text_white = "#ecf0f1"
        self.text_gray = "#95a5a6"

        self.setup_ui()
        self.update_process_mode_ui()
        self.after(50, self._drain_ui_queue)

    def setup_ui(self):
        """Sets up the user interface with scrollable content."""
        self.configure(bg=self.bg_dark)
        
        # Header (fixed at top)
        self.create_header()
        
        # Main container with scrollbar
        main_container = tk.Frame(self, bg=self.bg_dark)
        main_container.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Canvas for scrolling
        canvas = tk.Canvas(main_container, bg=self.bg_dark, highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
        
        # Scrollable frame with fixed width
        self.scrollable_frame = tk.Frame(canvas, bg=self.bg_dark)
        
        # Configure canvas scrolling
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        # Create window with proper width constraint
        self.canvas_window = canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Update canvas window width when canvas is resized
        def _on_canvas_configure(event):
            canvas.itemconfig(self.canvas_window, width=event.width)
        canvas.bind("<Configure>", _on_canvas_configure)
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            delta = event.delta
            if delta:
                units = max(1, abs(delta) // 120)
                canvas.yview_scroll(-units if delta > 0 else units, "units")
        def _bind_wheel(event=None):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", lambda wheel_event: canvas.yview_scroll(-1, "units"))
            canvas.bind_all("<Button-5>", lambda wheel_event: canvas.yview_scroll(1, "units"))

        def _unbind_wheel(event=None):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", _bind_wheel)
        canvas.bind("<Leave>", _unbind_wheel)
        
        # Pack canvas and scrollbar
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Create all sections in scrollable frame
        self.create_directory_section(self.scrollable_frame)
        self.create_processing_mode_section(self.scrollable_frame)
        self.create_password_section(self.scrollable_frame)
        self.create_salt_section(self.scrollable_frame)
        self.create_action_buttons(self.scrollable_frame)
        self.create_utility_button(self.scrollable_frame)
        self.create_log_section(self.scrollable_frame)

    def create_header(self):
        """Creates the header section."""
        header_frame = tk.Frame(self, bg=self.bg_dark)
        header_frame.pack(side=tk.TOP, fill=tk.X, padx=20, pady=(15, 10))
        
        logo_canvas = tk.Canvas(header_frame, width=60, height=60, bg=self.bg_dark, 
                               highlightthickness=0)
        logo_canvas.pack(side=tk.LEFT, padx=(0, 15))
        self.draw_lock_icon(logo_canvas)
        
        title_frame = tk.Frame(header_frame, bg=self.bg_dark)
        title_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(title_frame, text="CryptDir Pro", 
                font=("Segoe UI", 24, "bold"), 
                fg=self.text_white, bg=self.bg_dark, anchor="w").pack(anchor="w")
        
        tk.Label(title_frame, text="Professional File Encryption Suite v2.11.0 ~by COLDMAN", 
                font=("Segoe UI", 10), 
                fg=self.text_gray, bg=self.bg_dark, anchor="w").pack(anchor="w")
        
        tk.Frame(self, height=2, bg=self.bg_light).pack(side=tk.TOP, fill=tk.X, padx=20, pady=(0, 15))

    def create_directory_section(self, parent):
        """Creates directory selection section."""
        self.create_section_header(parent, "📁 Directory Selection")
        dir_frame = tk.Frame(parent, bg=self.bg_medium, relief=tk.FLAT, bd=0)
        dir_frame.pack(fill=tk.X, pady=(0, 15), ipady=5, ipadx=5)
        
        self.ent_dir = tk.Entry(dir_frame, textvariable=self.directory_path, state='readonly',
                               readonlybackground=self.bg_medium, fg=self.text_white, 
                               font=("Consolas", 10), insertbackground=self.text_white, 
                               bd=0, relief=tk.FLAT)
        self.ent_dir.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=10, padx=10)
        
        self.btn_browse = tk.Button(dir_frame, text="Browse", command=self.select_directory,
                                    bg=self.accent_blue, fg=self.text_white, 
                                    font=("Segoe UI", 10, "bold"),
                                    activebackground="#2980b9", cursor="hand2",
                                    bd=0, relief=tk.FLAT, padx=20, pady=8)
        self.btn_browse.pack(side=tk.RIGHT, padx=5, pady=5)

    def create_processing_mode_section(self, parent):
        """Creates processing mode selection."""
        self.create_section_header(parent, "🎯 Processing Mode")
        
        self.mode_frame = tk.Frame(parent, bg=self.bg_dark)
        self.mode_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Radiobutton(self.mode_frame, text="Process Entire Folder", 
                      variable=self.process_mode, value="folder",
                      command=self.update_process_mode_ui,
                      fg=self.text_white, bg=self.bg_dark, 
                      selectcolor=self.bg_medium,
                      activebackground=self.bg_dark, activeforeground=self.text_white,
                      cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        tk.Radiobutton(self.mode_frame, text="Select Specific Files...", 
                      variable=self.process_mode, value="files",
                      command=self.update_process_mode_ui,
                      fg=self.text_white, bg=self.bg_dark, 
                      selectcolor=self.bg_medium,
                      activebackground=self.bg_dark, activeforeground=self.text_white,
                      cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        # File selection frame (shown/hidden based on mode)
        self.files_frame = tk.Frame(parent, bg=self.bg_dark)
        
        self.btn_choose_files = tk.Button(self.files_frame, text="Choose Files...", 
                                         command=self.select_files,
                                         bg=self.accent_blue, fg=self.text_white, 
                                         font=("Segoe UI", 9, "bold"),
                                         activebackground="#2980b9", cursor="hand2",
                                         bd=0, relief=tk.FLAT, padx=15, pady=5)
        self.btn_choose_files.pack(fill=tk.X, pady=(0, 5))
        
        # Listbox with scrollbar for selected files
        list_container = tk.Frame(self.files_frame, bg=self.bg_medium)
        list_container.pack(fill=tk.X, expand=True)
        
        self.file_listbox = Listbox(list_container, height=4,
                                    bg=self.bg_medium, fg=self.text_white,
                                    selectbackground=self.accent_blue,
                                    selectforeground=self.text_white,
                                    bd=0, relief=tk.FLAT,
                                    font=("Consolas", 9),
                                    exportselection=False)
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        list_scrollbar = Scrollbar(list_container, orient="vertical",
                                  command=self.file_listbox.yview,
                                  bg=self.bg_light, troughcolor=self.bg_medium,
                                  activebackground=self.accent_blue)
        list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.file_listbox.config(yscrollcommand=list_scrollbar.set)
    def update_process_mode_ui(self):
        """Shows/hides file selection widgets based on mode."""
        if self._is_closing:
            return
        
        mode = self.process_mode.get()
        try:
            if mode == "files":
                if not self.directory_path.get():
                    messagebox.showwarning("Directory Needed", 
                                         "Please select a base directory first before choosing specific files.")
                    self.process_mode.set("folder")
                    return
                self.files_frame.pack(fill=tk.X, pady=(0, 15))
            else:
                self.files_frame.pack_forget()
                if self.selected_files:
                    self.selected_files = []
                    self.file_listbox.delete(0, tk.END)
        except tk.TclError:
            pass

    def select_files(self):
        """Opens file dialog to select specific files."""
        if self._is_closing:
            return
        
        base_dir = self.directory_path.get()
        if not base_dir:
            messagebox.showwarning("Directory Needed", "Please select a base directory first.")
            return
        
        file_paths = filedialog.askopenfilenames(
            title="Select Files to Process",
            initialdir=base_dir
        )
        
        if file_paths:
            self.selected_files = list(file_paths)
            self.file_listbox.delete(0, tk.END)
            self.log_status(f"\n📄 Selected {len(self.selected_files)} specific file(s):")
            for f_path in self.selected_files:
                self.file_listbox.insert(tk.END, os.path.basename(f_path))
                self.log_status(f"   - {f_path}")
        else:
            self.log_status("ℹ File selection cancelled or none chosen.")

    def create_password_section(self, parent):
        """Creates password input section."""
        self.create_section_header(parent, "🔑 Password")
        pass_frame = tk.Frame(parent, bg=self.bg_medium, relief=tk.FLAT, bd=0)
        pass_frame.pack(fill=tk.X, pady=(0, 5), ipady=5, ipadx=5)
        
        self.ent_pass = tk.Entry(pass_frame, show="●", bg=self.bg_medium, fg=self.text_white, 
                                font=("Segoe UI", 11), insertbackground=self.text_white, 
                                bd=0, relief=tk.FLAT)
        self.ent_pass.pack(fill=tk.X, ipady=10, padx=10, pady=5)
        self.ent_pass.focus()
        self.ent_pass.bind('<KeyRelease>', self.on_password_change)
        
        self.pass_strength_label = tk.Label(parent, text="", 
                                           fg=self.text_gray, bg=self.bg_dark, 
                                           font=("Segoe UI", 9), anchor="w")
        self.pass_strength_label.pack(fill=tk.X, pady=(0, 15))
    def create_salt_section(self, parent):
        """Creates salt configuration section."""
        self.create_section_header(parent, "🧂 Salt Configuration")
        
        salt_config_frame = tk.Frame(parent, bg=self.bg_dark)
        salt_config_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.chk_disable_salt = tk.Checkbutton(
            salt_config_frame, 
            text="⚠ Disable Auto-Salting (INSECURE - legacy only)",
            variable=self.disable_salt_var,
            command=self.toggle_salt_options,
            fg=self.accent_red, bg=self.bg_dark, 
            font=("Segoe UI", 9),
            selectcolor=self.bg_dark,
            activebackground=self.bg_dark, 
            activeforeground=self.accent_red,
            cursor="hand2",
            anchor="w"
        )
        self.chk_disable_salt.pack(fill=tk.X, pady=5)
        
        salt_frame = tk.Frame(parent, bg=self.bg_medium, relief=tk.FLAT, bd=0)
        salt_frame.pack(fill=tk.X, pady=(0, 15), ipady=5, ipadx=5)
        
        tk.Label(salt_frame, text="Manual Salt (Optional - keep it safe):", 
                fg=self.text_gray, bg=self.bg_medium, 
                font=("Segoe UI", 9), anchor="w").pack(fill=tk.X, padx=10, pady=(5, 0))
        
        self.ent_salt = tk.Entry(salt_frame, bg=self.bg_light, fg=self.text_white, 
                                font=("Consolas", 10), insertbackground=self.text_white, 
                                bd=0, relief=tk.FLAT)
        self.ent_salt.pack(fill=tk.X, ipady=8, padx=10, pady=(5, 10))
        
        # Salt validation label
        self.salt_strength_label = tk.Label(parent, text="", 
                                           fg=self.text_gray, bg=self.bg_dark, 
                                           font=("Segoe UI", 9), anchor="w")
        self.salt_strength_label.pack(fill=tk.X, pady=(0, 5))
        self.ent_salt.bind('<KeyRelease>', self.on_salt_change)

    def create_action_buttons(self, parent):
        """Creates action buttons section."""
        self.create_section_header(parent, "⚡ Actions")
        
        button_container = tk.Frame(parent, bg=self.bg_dark)
        button_container.pack(fill=tk.X, pady=(0, 10))
        
        button_frame = tk.Frame(button_container, bg=self.bg_dark)
        button_frame.pack()
        
        self.btn_encrypt = tk.Button(
            button_frame, text="🔒 ENCRYPT", 
            command=self.start_encrypt,
            bg=self.accent_red, fg=self.text_white, 
            font=("Segoe UI", 12, "bold"),
            activebackground="#c0392b", cursor="hand2",
            bd=0, relief=tk.FLAT, width=15, height=2
        )
        self.btn_encrypt.pack(side=tk.LEFT, padx=5)
        
        self.btn_decrypt = tk.Button(
            button_frame, text="🔓 DECRYPT", 
            command=self.start_decrypt,
            bg=self.accent_green, fg=self.text_white, 
            font=("Segoe UI", 12, "bold"),
            activebackground="#229954", cursor="hand2",
            bd=0, relief=tk.FLAT, width=15, height=2
        )
        self.btn_decrypt.pack(side=tk.LEFT, padx=5)
        
        self.btn_test_decrypt = tk.Button(
            button_frame, text="🧪 TEST DECRYPT", 
            command=self.start_test_decrypt,
            bg=self.accent_blue, fg=self.text_white, 
            font=("Segoe UI", 12, "bold"),
            activebackground="#2980b9", cursor="hand2",
            bd=0, relief=tk.FLAT, width=15, height=2
        )
        self.btn_test_decrypt.pack(side=tk.LEFT, padx=5)
        
        self.btn_cancel = tk.Button(
            parent, text="⏹ CANCEL OPERATION", 
            command=self.cancel_operation,
            bg=self.accent_yellow, fg=self.bg_dark, 
            font=("Segoe UI", 10, "bold"),
            activebackground="#e67e22", cursor="hand2",
            bd=0, relief=tk.FLAT, state=tk.DISABLED
        )
        self.btn_cancel.pack(fill=tk.X, pady=(5, 10), ipady=8)
        
        self.progress_bar = ttk.Progressbar(parent, mode='indeterminate', style="TProgressbar")
        self.progress_bar_style = ttk.Style()
        self.progress_bar_style.configure("TProgressbar", 
                                         background=self.accent_blue, 
                                         troughcolor=self.bg_medium)

    def create_utility_button(self, parent):
        """Creates utility buttons section."""
        self.btn_toggle_hide = tk.Button(
            parent, text="👁 HIDE/UNHIDE FOLDER", 
            command=self.toggle_folder_visibility,
            bg=self.bg_light, fg=self.text_white, 
            font=("Segoe UI", 10, "bold"),
            activebackground=self.bg_medium, cursor="hand2",
            bd=0, relief=tk.FLAT
        )
        self.btn_toggle_hide.pack(fill=tk.X, pady=(0, 15), ipady=8)
        
    def create_log_section(self, parent):
        """Creates status log section."""
        self.create_section_header(parent, "📋 Status Log", self.bg_dark)
        
        log_frame = tk.Frame(parent, bg=self.bg_medium, relief=tk.FLAT, bd=0)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.status_log = scrolledtext.ScrolledText(
            log_frame, state='disabled', height=10,
            bg=self.bg_dark, fg="#00ff00", 
            font=("Consolas", 9),
            bd=0, relief=tk.FLAT,
            padx=10, pady=10
        )
        self.status_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_status("="*60)
        self.log_status(f"Welcome to {self.title()}")
        self.log_status("Select a directory and enter a password to begin")
        self.log_status("="*60)

    def draw_lock_icon(self, canvas):
        """Draws a lock icon on the canvas."""
        canvas.create_rectangle(18, 30, 42, 50, fill="#e74c3c", outline="#c0392b", width=2)
        canvas.create_arc(20, 15, 40, 35, start=0, extent=180, 
                         outline="#e74c3c", width=4, style=tk.ARC)
        canvas.create_oval(27, 36, 33, 42, fill="#c0392b", outline="")
        canvas.create_rectangle(28, 40, 32, 46, fill="#c0392b", outline="")

    def create_section_header(self, parent, text, bg=None):
        """Creates a consistent section header."""
        if bg is None:
            bg = self.bg_dark
        header = tk.Label(parent, text=text, 
                         font=("Segoe UI", 11, "bold"), 
                         fg=self.text_white, bg=bg, anchor="w")
        header.pack(fill=tk.X, pady=(10, 5))

    def on_password_change(self, event=None):
        """Updates password strength indicator."""
        password = self.ent_pass.get()
        
        if not password:
            self.pass_strength_label.config(text="", fg=self.text_gray)
            return
        
        is_valid, message = validate_password(password)
        
        if is_valid:
            self.pass_strength_label.config(text="✓ Strong password", fg=self.accent_green)
        else:
            self.pass_strength_label.config(text=f"⚠ {message}", fg=self.accent_yellow)

    def on_salt_change(self, event=None):
        """Updates manual salt strength indicator."""
        salt = self.ent_salt.get()
        
        if not salt:
            self.salt_strength_label.config(text="", fg=self.text_gray)
            return
        
        is_valid, message = validate_manual_salt(salt)
        
        if is_valid:
            self.salt_strength_label.config(text="✓ Salt acceptable", fg=self.accent_green)
        else:
            self.salt_strength_label.config(text=f"⚠ {message}", fg=self.accent_yellow)

    def safe_ui_update(self, callback):
        """Queue a callback for execution on Tk's main thread."""
        if not self._is_closing:
            self._ui_queue.put(callback)

    def _drain_ui_queue(self):
        """Run worker callbacks on the Tk main thread."""
        if self._is_closing:
            return
        while True:
            try:
                callback = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                callback()
            except tk.TclError:
                pass
            except Exception as error:
                # Keep draining subsequent callbacks if one UI update fails.
                print(f"UI update callback failed: {error}", file=sys.stderr)
        if not self._is_closing:
            self.after(50, self._drain_ui_queue)
    
    def safe_progress_step(self):
        """
        Safely steps the progress bar from any thread.
        Uses stored _progress_mode to avoid thread-unsafe widget access.
        """
        def _step():
            if self._is_closing or not self.progress_bar.winfo_exists():
                return
            try:
                if self._progress_mode == 'determinate':
                    self.progress_bar.step()
                else:
                    self.progress_bar.step(1) 
            except tk.TclError:
                pass
        self.safe_ui_update(_step)

    def log_status(self, message):
        """Safely logs a message to the status box from any thread."""
        def _log():
            if self._is_closing or not self.status_log.winfo_exists():
                return
            try:
                self.status_log.configure(state='normal')
                self.status_log.insert(tk.END, message + "\n")
                self.status_log.see(tk.END)
                self.status_log.configure(state='disabled')
            except tk.TclError:
                pass
        
        self.safe_ui_update(_log)

    def select_directory(self):
        """Opens a dialog to select a directory."""
        path = filedialog.askdirectory(title="Select Directory to Encrypt/Decrypt")
        if path:
            old_dir = self.directory_path.get()
            self.directory_path.set(path)
            self.log_status(f"\n📁 Selected directory: {path}")
            
            if self.process_mode.get() == "files" and path != old_dir:
                self.selected_files = []
                self.file_listbox.delete(0, tk.END)
                self.log_status("   (File selection cleared due to directory change)")

    def toggle_salt_options(self):
        """Disables or enables the manual salt entry based on the checkbox."""
        if self._is_closing:
            return
            
        try:
            if self.ent_salt.winfo_exists():
                # A disabled generated salt still needs a user-supplied salt
                # so the operation remains decryptable later.
                self.ent_salt.config(state=tk.NORMAL, bg=self.bg_light)
        except tk.TclError:
            pass
    def set_ui_processing(self, is_processing, total_files=0):
        """
        Disables/Enables UI elements during processing.
        Uses determinate progress bar if total_files > 0, else indeterminate.
        """
        def _set():
            if self._is_closing:
                return
                
            try:
                state = tk.DISABLED if is_processing else tk.NORMAL
                cancel_state = tk.NORMAL if is_processing else tk.DISABLED
                
                widgets = [self.btn_browse, self.ent_pass, self.chk_disable_salt,
                          self.btn_encrypt, self.btn_decrypt, self.btn_toggle_hide,
                          self.btn_choose_files, self.btn_test_decrypt]
                
                if hasattr(self, 'mode_frame') and self.mode_frame.winfo_exists():
                    for child in self.mode_frame.winfo_children():
                        widgets.append(child)
                
                for widget in widgets:
                    if widget.winfo_exists():
                        widget.config(state=state)
                
                if self.ent_salt.winfo_exists():
                    salt_state = tk.DISABLED if is_processing else tk.NORMAL
                    salt_bg = self.bg_medium if salt_state == tk.DISABLED else self.bg_light
                    self.ent_salt.config(state=salt_state, bg=salt_bg)
                
                if self.file_listbox.winfo_exists():
                    self.file_listbox.config(state=state)
                
                if self.btn_cancel.winfo_exists():
                    self.btn_cancel.config(state=cancel_state)
                
                if is_processing:
                    if self.current_operation == 'encrypt':
                        self.btn_encrypt.config(text="🔒 ENCRYPTING...")
                    elif self.current_operation == 'decrypt':
                        self.btn_decrypt.config(text="🔓 DECRYPTING...")
                    elif self.current_operation == 'test':
                        self.btn_test_decrypt.config(text="🧪 TESTING...")
                    
                    if self.progress_bar.winfo_exists():
                        if total_files > 0:
                            self._progress_mode = 'determinate'
                            self.progress_bar.config(mode='determinate', maximum=total_files, value=0)
                        else:
                            self._progress_mode = 'indeterminate'
                            self.progress_bar.config(mode='indeterminate')
                            self.progress_bar.start(15)
                            
                        self.progress_bar.pack(fill=tk.X, before=self.btn_toggle_hide, 
                                             pady=(5, 5), ipady=2)
                else:
                    if self.btn_encrypt.winfo_exists():
                        self.btn_encrypt.config(text="🔒 ENCRYPT")
                    if self.btn_decrypt.winfo_exists():
                        self.btn_decrypt.config(text="🔓 DECRYPT")
                    if self.btn_test_decrypt.winfo_exists():
                        self.btn_test_decrypt.config(text="🧪 TEST DECRYPT")
                        
                    if self.progress_bar.winfo_exists():
                        self.progress_bar.stop()
                        self.progress_bar.pack_forget()
                        self.progress_bar.config(mode='indeterminate', value=0)
                        self._progress_mode = 'indeterminate'
                        
            except tk.TclError:
                pass
        
        self.safe_ui_update(_set)

    def check_inputs(self, enforce_strength=False):
        """Validates inputs before processing."""
        directory = self.directory_path.get()
        password = self.ent_pass.get()
        mode = self.process_mode.get()
        manual_salt = self.ent_salt.get()
        disable_salt = self.disable_salt_var.get()
        
        if not directory or not os.path.isdir(directory):
            messagebox.showerror("Input Error", "Please select a valid directory.")
            return False
        
        if not password:
            messagebox.showerror("Input Error", "Please enter a password.")
            return False
        
        if mode == "files" and not self.selected_files:
            messagebox.showerror("Input Error", "Please choose specific files or switch to folder mode.")
            return False
        
        if enforce_strength:
            is_valid, message = validate_password(password)
            if not is_valid:
                messagebox.showerror("Weak Password", message + "\n\nChoose a stronger password.")
                return False
        
        if manual_salt:
            is_valid, message = validate_manual_salt(manual_salt)
            if not is_valid:
                response = messagebox.askyesno(
                    "Weak Salt", 
                    f"{message}\n\nUsing a weak salt significantly reduces security.\n\n"
                    "Do you want to proceed anyway?"
                )
                if not response:
                    return False
        
        if mode == "folder":
            try:
                script_path = None
                if getattr(sys, 'frozen', False):
                    script_path = sys.executable
                elif '__file__' in globals():
                    script_path = os.path.abspath(__file__)
                
                if script_path:
                    script_dir = os.path.dirname(script_path)
                    selected_dir = os.path.abspath(directory)
                    
                    if selected_dir == script_dir or script_dir.startswith(selected_dir + os.sep):
                        messagebox.showerror(
                            "Operation Error", 
                            "Cannot target the directory containing this application!\n\n"
                            "Please choose a different location."
                        )
                        return False
            except Exception as e:
                self.log_status(f"Warning: Could not verify target directory: {e}")
        
        if disable_salt and not manual_salt:
            messagebox.showerror(
                "Salt Required",
                "When auto-salting is disabled, enter the manual salt used for encryption."
            )
            return False

        return True

    def toggle_folder_visibility(self):
        """Hides or unhides the selected folder (Windows only)."""
        if sys.platform != "win32":
            self.log_status("\n⚠ Folder hiding is only supported on Windows.")
            return

        directory = self.directory_path.get()
        if not directory or not os.path.isdir(directory):
            messagebox.showerror("Selection Error", "Please select a valid directory first.")
            return

        try:
            FILE_ATTRIBUTE_HIDDEN = 0x2
            FILE_ATTRIBUTE_SYSTEM = 0x4

            attrs = ctypes.windll.kernel32.GetFileAttributesW(directory)
            
            if attrs == -1:
                last_error = ctypes.windll.kernel32.GetLastError()
                self.log_status(f"\n✗ Error getting attributes (Code: {last_error})")
                messagebox.showerror(
                    "Attribute Error", 
                    f"Could not get folder attributes (Error: {last_error})\n"
                    "Check permissions or path."
                )
                return

            is_hidden = bool(attrs & FILE_ATTRIBUTE_HIDDEN)
            
            if is_hidden:
                new_attrs_set = attrs & ~FILE_ATTRIBUTE_HIDDEN & ~FILE_ATTRIBUTE_SYSTEM
                result = ctypes.windll.kernel32.SetFileAttributesW(directory, new_attrs_set)
            else:
                new_attrs_set = attrs | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
                result = ctypes.windll.kernel32.SetFileAttributesW(directory, new_attrs_set)

            if not result:
                last_error = ctypes.windll.kernel32.GetLastError()
                self.log_status(f"\n✗ Failed to change attributes (Code: {last_error})")
                messagebox.showerror(
                    "Attribute Error", 
                    f"Failed to set folder attributes (Error: {last_error})\n"
                    "Try running as administrator."
                )
                return

            final_attrs = ctypes.windll.kernel32.GetFileAttributesW(directory)
            if final_attrs == -1:
                self.log_status(f"\n✗ Could not verify new attributes after change.")
                return

            is_now_hidden = bool(final_attrs & FILE_ATTRIBUTE_HIDDEN)

            if is_hidden and not is_now_hidden:
                self.log_status(f"\n👁 Folder made VISIBLE: {directory}")
                messagebox.showinfo("Success", "Folder is now visible.")
            elif not is_hidden and is_now_hidden:
                self.log_status(f"\n🙈 Folder HIDDEN: {directory}")
                messagebox.showinfo("Success", "Folder is now hidden.")
            elif is_hidden and is_now_hidden:
                self.log_status(f"\n✗ FAILED to make folder visible (still hidden).")
                messagebox.showerror("Error", "Could not make folder visible.\nCheck permissions or run as administrator.")
            elif not is_hidden and not is_now_hidden:
                self.log_status(f"\n✗ FAILED to hide folder (still visible).")
                messagebox.showerror("Error", "Could not hide folder.\nCheck permissions or run as administrator.")

        except Exception as e:
            self.log_status(f"\n✗ Error changing folder attributes: {e}")
            messagebox.showerror("Unexpected Error", f"Could not change folder attributes.\n{e}")

    def start_encrypt(self):
        """Starts the encryption process in a new thread."""
        if not self.check_inputs(enforce_strength=True):
            return
        
        directory = self.directory_path.get()
        password = self.ent_pass.get()
        disable_salt = self.disable_salt_var.get()
        manual_salt = self.ent_salt.get()
        mode = self.process_mode.get()
        
        total_files = 0
        if mode == "folder":
            target_desc = f"all processable files in:\n{directory}"
        else:
            total_files = len(self.selected_files)
            target_desc = f"{total_files} selected file(s)"
            if total_files == 0:
                self.log_status("ℹ No files found to encrypt.")
                messagebox.showinfo("Operation", "No files to encrypt.")
                return
            
        self.log_status(f"\nℹ Encrypting {target_desc}")
        
        confirm_msg = f"This will encrypt {target_desc}\n\n"
        
        if disable_salt and not manual_salt:
            confirm_msg += "⚠ Auto-salting is disabled; the supplied manual salt will be used.\n\n"
        elif manual_salt:
            confirm_msg += "ℹ Using MANUAL salt. Remember it for decryption!\n\n"
        else:
            confirm_msg += f"ℹ A '{SALT_FILENAME}' file will be created. Keep it safe!\n\n"
        
        confirm_msg += "✓ Output is written to a temporary file before replacement.\n\nContinue?"

        if not messagebox.askyesno("Confirm Encryption", confirm_msg):
            self.log_status("🛑 Encryption cancelled by user.")
            return

        self.log_status("\n" + "="*60)
        self.log_status("🔒 Starting encryption...")
        self.log_status("="*60)
        
        self.current_operation = 'encrypt'
        self.set_ui_processing(True, total_files)
        self.stop_event.clear()

        self.processing_thread = threading.Thread(
            target=self.run_encrypt,
            args=(directory, password, disable_salt, manual_salt, mode),
            daemon=True
        )
        self.processing_thread.start()
    def run_encrypt(self, directory, password, disable_salt, manual_salt, mode):
        """The actual encryption logic that runs in the thread."""
        start_time = time.time()
        try:
            salt = b''
            salt_path = os.path.join(directory, SALT_FILENAME)
            
            if disable_salt and not manual_salt:
                raise ValueError("Manual salt is required when auto-salting is disabled.")
            elif manual_salt:
                salt = manual_salt.encode('utf-8')
                self.log_status("🧂 Using provided manual salt.")
            else:
                try:
                    if os.path.exists(salt_path):
                        with open(salt_path, 'rb') as f:
                            salt = f.read()
                        if len(salt) != 16:
                            self.log_status(f"Invalid salt file length: {len(salt)} bytes; expected 16.")
                            self.safe_ui_update(lambda: self.set_ui_processing(False))
                            return
                        self.log_status(f"Reusing existing salt file: {salt_path}")
                    else:
                        salt = os.urandom(16)
                        with open(salt_path, 'wb') as f:
                            f.write(salt)
                        self.log_status(f"💾 Salt file saved: {salt_path}")
                except PermissionError:
                    self.log_status(f"\n✗ FATAL: Permission denied writing salt file.")
                    self.safe_ui_update(lambda: self.set_ui_processing(False))
                    return
                except Exception as e:
                    self.log_status(f"\n✗ FATAL: Error writing salt file: {e}")
                    self.safe_ui_update(lambda: self.set_ui_processing(False))
                    return

            key = generate_key(password, salt)
            
            self.log_status("\n📄 Processing files...")
            
            existing_encrypted = count_encrypted_files(
                directory, self.selected_files if mode != "folder" else None
            )
            if existing_encrypted:
                self.log_status(
                    f"WARNING: {existing_encrypted} already-encrypted file(s) found. "
                    "They will be skipped; mixed passwords/salts in this folder may still exist."
                )
            cleanup_orphaned_backups(
                directory, self.log_status,
                file_list=self.selected_files if mode != "folder" else None
            )
            if mode == "folder":
                stats = process_directory(
                    directory, key, 'encrypt', self.log_status,
                    self.stop_event, self.safe_progress_step
                )
            else:
                stats = process_selected_files(
                    self.selected_files, key, 'encrypt', self.log_status,
                    self.stop_event, self.safe_progress_step, directory
                )
            
            success, fail, skip, total_bytes = stats
            
            if not self.stop_event.is_set():
                end_time = time.time()
                elapsed = end_time - start_time
                
                if total_bytes < 1024**2:
                    size_str = f"{total_bytes / 1024.0:.2f} KB"
                elif total_bytes < 1024**3:
                    size_str = f"{total_bytes / (1024.0**2):.2f} MB"
                else:
                    size_str = f"{total_bytes / (1024.0**3):.2f} GB"
                
                speed = total_bytes / elapsed if elapsed > 0 else 0
                if speed < 1024**2:
                    speed_str = f"{speed / 1024.0:.2f} KB/s"
                else:
                    speed_str = f"{speed / (1024.0**2):.2f} MB/s"

                self.log_status(f"\n{'='*60}")
                self.log_status("✓ Encryption Complete!")
                self.log_status(f"📊 Success: {success} | Failed: {fail} | Skipped: {skip}")
                self.log_status(f"💾 Total data processed: {size_str}")
                self.log_status(f"⏱️ Time elapsed: {elapsed:.2f} seconds")
                self.log_status(f"⚡ Average speed: {speed_str}")
                self.log_status(f"{'='*60}")
            
        except Exception as e:
            self.log_status(f"\n✗ Unexpected error during encryption: {e}")
            import traceback
            self.log_status(traceback.format_exc())
        finally:
            self.safe_ui_update(lambda: self.set_ui_processing(False))

    def start_decrypt(self):
        """Starts the decryption process in a new thread."""
        if not self.check_inputs():
            return
        
        directory = self.directory_path.get()
        password = self.ent_pass.get()
        disable_salt = self.disable_salt_var.get()
        manual_salt = self.ent_salt.get()
        mode = self.process_mode.get()

        total_files = 0
        if mode == "folder":
            target_desc = f"all processable files in:\n{directory}"
        else:
            total_files = len(self.selected_files)
            target_desc = f"{total_files} selected file(s)"
            if total_files == 0:
                self.log_status("ℹ No files found to decrypt.")
                messagebox.showinfo("Operation", "No files to decrypt.")
                return
            
        self.log_status(f"\nℹ Decrypting {target_desc}")
        
        confirm_msg = f"This will attempt to decrypt {target_desc}\n\n"
        
        if disable_salt:
            confirm_msg += "⚠ WARNING: Attempting decryption with auto-salting disabled.\n"
            confirm_msg += "You MUST provide the exact same manual salt used during encryption.\n\n"
        elif manual_salt:
            confirm_msg += "ℹ Using MANUAL salt.\n\n"
        else:
            confirm_msg += f"ℹ Requires '{SALT_FILENAME}' in the directory.\n\n"
        
        confirm_msg += "✓ Output is written to a temporary file before replacement.\n\nContinue?"

        if not messagebox.askyesno("Confirm Decryption", confirm_msg):
            self.log_status("🛑 Decryption cancelled by user.")
            return

        self.log_status("\n" + "="*60)
        self.log_status("🔓 Starting decryption...")
        self.log_status("="*60)
        
        self.current_operation = 'decrypt'
        self.set_ui_processing(True, total_files)
        self.stop_event.clear()
        self.invalid_key_event.clear()

        self.processing_thread = threading.Thread(
            target=self.run_decrypt,
            args=(directory, password, disable_salt, manual_salt, mode),
            daemon=True
        )
        self.processing_thread.start()

    def run_decrypt(self, directory, password, disable_salt, manual_salt, mode):
        """The actual decryption logic that runs in the thread."""
        start_time = time.time()
        try:
            salt = b''
            salt_path = os.path.join(directory, SALT_FILENAME)

            if disable_salt and not manual_salt:
                self.log_status("✗ FATAL: Cannot decrypt with auto-salting disabled unless manual salt is provided.")
                self.log_status("   Please enable 'Manual Salt' and enter the salt used during encryption.")
                self.safe_ui_update(lambda: self.set_ui_processing(False))
                return
            elif manual_salt:
                salt = manual_salt.encode('utf-8')
                self.log_status("🧂 Using provided manual salt.")
            else:
                try:
                    with open(salt_path, 'rb') as f:
                        salt = f.read()
                    if len(salt) != 16:
                        self.log_status(f"✗ FATAL: Salt file has invalid length ({len(salt)} bytes, expected 16).")
                        self.safe_ui_update(lambda: self.set_ui_processing(False))
                        return
                    self.log_status(f"💾 Salt file loaded: {salt_path}")
                except FileNotFoundError:
                    self.log_status(f"\n✗ FATAL: '{SALT_FILENAME}' not found.")
                    self.log_status("Cannot decrypt without salt file (or manual salt).")
                    self.safe_ui_update(lambda: self.set_ui_processing(False))
                    return
                except PermissionError:
                    self.log_status(f"\n✗ FATAL: Permission denied reading salt file.")
                    self.safe_ui_update(lambda: self.set_ui_processing(False))
                    return
                except Exception as e:
                    self.log_status(f"\n✗ FATAL: Error reading '{SALT_FILENAME}': {e}")
                    self.safe_ui_update(lambda: self.set_ui_processing(False))
                    return

            key = generate_key(password, salt)
            
            self.log_status("\n📄 Processing files...")
            
            cleanup_orphaned_backups(
                directory, self.log_status,
                file_list=self.selected_files if mode != "folder" else None
            )
            if mode == "folder":
                stats = process_directory(
                    directory, key, 'decrypt', self.log_status,
                    self.stop_event, self.safe_progress_step, self.invalid_key_event
                )
            else:
                stats = process_selected_files(
                    self.selected_files, key, 'decrypt', self.log_status,
                    self.stop_event, self.safe_progress_step, directory,
                    self.invalid_key_event
                )
            
            success, fail, skip, total_bytes = stats
            
            if not self.stop_event.is_set():
                end_time = time.time()
                elapsed = end_time - start_time
                
                if total_bytes < 1024**2:
                    size_str = f"{total_bytes / 1024.0:.2f} KB"
                elif total_bytes < 1024**3:
                    size_str = f"{total_bytes / (1024.0**2):.2f} MB"
                else:
                    size_str = f"{total_bytes / (1024.0**3):.2f} GB"
                
                speed = total_bytes / elapsed if elapsed > 0 else 0
                if speed < 1024**2:
                    speed_str = f"{speed / 1024.0:.2f} KB/s"
                else:
                    speed_str = f"{speed / (1024.0**2):.2f} MB/s"

                self.log_status(f"\n{'='*60}")
                self.log_status("✓ Decryption Complete!")
                self.log_status(f"📊 Success: {success} | Failed: {fail} | Skipped: {skip}")
                self.log_status(f"💾 Total data processed: {size_str}")
                self.log_status(f"⏱️ Time elapsed: {elapsed:.2f} seconds")
                self.log_status(f"⚡ Average speed: {speed_str}")
                self.log_status(f"{'='*60}")
                
        except Exception as e:
            self.log_status(f"\n✗ Unexpected error during decryption: {e}")
            import traceback
            self.log_status(traceback.format_exc())
        finally:
            self.safe_ui_update(lambda: self.set_ui_processing(False))

    def start_test_decrypt(self):
        """Starts the HMAC verification process in a new thread."""
        if not self.check_inputs():
            return
        
        directory = self.directory_path.get()
        password = self.ent_pass.get()
        disable_salt = self.disable_salt_var.get()
        manual_salt = self.ent_salt.get()
        mode = self.process_mode.get()

        total_files = 0
        if mode == "folder":
            target_desc = f"all processable files in:\n{directory}"
        else:
            total_files = len(self.selected_files)
            target_desc = f"{total_files} selected file(s)"
            if total_files == 0:
                self.log_status("ℹ No files found to test.")
                messagebox.showinfo("Operation", "No files to test.")
                return
            
        self.log_status(f"\nℹ Testing {target_desc}")
        
        confirm_msg = f"This will TEST (verify) {target_desc}\n\n"
        confirm_msg += "No files will be modified or decrypted.\n\n"
        
        if disable_salt:
            confirm_msg += "⚠ Attempting test with auto-salting disabled.\n"
            confirm_msg += "You MUST provide the exact same manual salt used during encryption.\n\n"
        elif manual_salt:
            confirm_msg += "ℹ Using MANUAL salt.\n\n"
        else:
            confirm_msg += f"ℹ Requires '{SALT_FILENAME}' in the directory.\n\n"
        
        confirm_msg += "Continue?"

        if not messagebox.askyesno("Confirm Test Decryption", confirm_msg):
            self.log_status("🛑 Test cancelled by user.")
            return

        self.log_status("\n" + "="*60)
        self.log_status("🧪 Starting test verification...")
        self.log_status("="*60)
        
        self.current_operation = 'test'
        self.set_ui_processing(True, total_files)
        self.stop_event.clear()
        self.invalid_key_event.clear()

        self.processing_thread = threading.Thread(
            target=self.run_test_decrypt,
            args=(directory, password, disable_salt, manual_salt, mode),
            daemon=True
        )
        self.processing_thread.start()
    def run_test_decrypt(self, directory, password, disable_salt, manual_salt, mode):
        """The actual HMAC verification logic that runs in the thread."""
        start_time = time.time()
        try:
            salt = b''
            salt_path = os.path.join(directory, SALT_FILENAME)

            if disable_salt and not manual_salt:
                self.log_status("✗ FATAL: Cannot test with auto-salting disabled unless manual salt is provided.")
                self.log_status("   Please enable 'Manual Salt' and enter the salt used during encryption.")
                self.safe_ui_update(lambda: self.set_ui_processing(False))
                return
            elif manual_salt:
                salt = manual_salt.encode('utf-8')
                self.log_status("🧂 Using provided manual salt.")
            else:
                try:
                    with open(salt_path, 'rb') as f:
                        salt = f.read()
                    if len(salt) != 16:
                        self.log_status(f"✗ FATAL: Salt file has invalid length ({len(salt)} bytes, expected 16).")
                        self.safe_ui_update(lambda: self.set_ui_processing(False))
                        return
                    self.log_status(f"💾 Salt file loaded: {salt_path}")
                except FileNotFoundError:
                    self.log_status(f"\n✗ FATAL: '{SALT_FILENAME}' not found.")
                    self.log_status("Cannot test without salt file (or manual salt).")
                    self.safe_ui_update(lambda: self.set_ui_processing(False))
                    return
                except PermissionError:
                    self.log_status(f"\n✗ FATAL: Permission denied reading salt file.")
                    self.safe_ui_update(lambda: self.set_ui_processing(False))
                    return
                except Exception as e:
                    self.log_status(f"\n✗ FATAL: Error reading '{SALT_FILENAME}': {e}")
                    self.safe_ui_update(lambda: self.set_ui_processing(False))
                    return

            key = generate_key(password, salt)
            
            self.log_status("\n📄 Processing files...")
            
            if mode == "folder":
                stats = process_directory(
                    directory, key, 'test', self.log_status,
                    self.stop_event, self.safe_progress_step, self.invalid_key_event
                )
            else:
                stats = process_selected_files(
                    self.selected_files, key, 'test', self.log_status,
                    self.stop_event, self.safe_progress_step, directory,
                    self.invalid_key_event
                )
            
            success, fail, skip, total_bytes = stats
            
            if not self.stop_event.is_set():
                end_time = time.time()
                elapsed = end_time - start_time
                
                size_str = f"{total_bytes / (1024.0**2):.2f} MB"
                if total_bytes > 1024**3:
                    size_str = f"{total_bytes / (1024.0**3):.2f} GB"

                speed = total_bytes / elapsed if elapsed > 0 else 0
                speed_str = f"{speed / (1024.0**2):.2f} MB/s"

                self.log_status(f"\n{'='*60}")
                self.log_status("✓ Test Complete!")
                self.log_status(f"📊 Verified: {success} | Failed/Corrupt: {fail} | Skipped: {skip}")
                self.log_status(f"💾 Total data verified: {size_str}")
                self.log_status(f"⏱️ Time elapsed: {elapsed:.2f} seconds")
                self.log_status(f"⚡ Average speed: {speed_str}")
                self.log_status(f"{'='*60}")
                
        except Exception as e:
            self.log_status(f"\n✗ Unexpected error during test: {e}")
            import traceback
            self.log_status(traceback.format_exc())
        finally:
            self.safe_ui_update(lambda: self.set_ui_processing(False))
    def cancel_operation(self):
        """Sets an event to stop the processing thread with warning."""
        if self.processing_thread and self.processing_thread.is_alive():
            response = messagebox.askyesno(
                "⚠️ Cancel Operation Warning",
                "The current file is written to a temporary file and replaced only after completion.\n\n"
                "Cancelling will stop after the current chunk and remove temporary output.\n\n"
                "Are you sure you want to cancel?",
                icon='warning'
            )
            
            if response:
                self.log_status("\n⚠️ CANCEL CONFIRMED - Stopping operation...")
                self.log_status("Cancellation requested; the original file remains unchanged.")
                self.stop_event.set()
                
                def _disable_cancel():
                    if not self._is_closing and self.btn_cancel.winfo_exists():
                        try:
                            self.btn_cancel.config(state=tk.DISABLED, text="⏹ STOPPING...")
                        except tk.TclError:
                            pass
                self.safe_ui_update(_disable_cancel)
            else:
                self.log_status("\n✓ Cancel operation aborted - continuing process...")

    def on_closing(self):
        """Handle window close event, ensuring thread safety."""
        if self.processing_thread and self.processing_thread.is_alive():
            response = messagebox.askyesno(
                "Exit Confirmation",
                "An operation is currently in progress.\n"
                "Stopping now might leave some files partially processed.\n\n"
                "Are you sure you want to exit?"
            )
            
            if response:
                self.log_status("\n🛑 Exit requested. Sending cancel signal...")
                self._is_closing = True
                self.stop_event.set()
                
                self.processing_thread.join(timeout=2)
                self.destroy()
            return
        
        self._is_closing = True
        self.destroy()

# ----------------------------------------------------------------------
# Main Entry Point
# ----------------------------------------------------------------------
def main():
    """Main entry point for the application."""
    # Set DPI awareness on Windows
    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    
    # Create and run application
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
