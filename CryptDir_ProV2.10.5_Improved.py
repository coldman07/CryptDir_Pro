import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk, Listbox, Scrollbar
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature  # CORRECTED IMPORT
from pathlib import Path
import threading
import ctypes
import sys
import shutil
import hashlib
import re
import struct
import time

# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

SALT_FILENAME = 'salt.key'
BACKUP_EXTENSION = '.backup_temp'
CHUNK_SIZE = 64 * 1024  # 64KB chunks for large file handling
MIN_PASSWORD_LENGTH = 8

# ADDED: Version-aware file header
MAGIC_BYTES = b'CDPRO'      # 5-byte file identifier
VERSION_BYTES = b'\x02\x0A'  # v2.10 (Major 2, Minor 10)
RESERVED_BYTE = b'\x00'     # 1 byte reserved
FILE_HEADER_PREFIX = MAGIC_BYTES + VERSION_BYTES + RESERVED_BYTE # 8-byte total prefix

LARGE_FILE_WARNING_SIZE = 50 * 1024 * 1024 * 1024 # 50 GB

# ----------------------------------------------------------------------
# Core Encryption/Decryption Logic
# ----------------------------------------------------------------------

def generate_key(password: str, salt: bytes) -> bytes:
    """
    Generates a 64-byte key for AES-256-CTR (32 bytes) + HMAC-SHA256 (32 bytes).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,  # 32 bytes for AES key, 32 bytes for HMAC key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())  # Return 64 raw bytes


def validate_password(password: str) -> tuple[bool, str]:
    """Validates password strength. Returns (is_valid, message)."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
    
    if not re.search(r'[A-Z]', password):
        return False, "Password should contain at least one uppercase letter."
    
    if not re.search(r'[a-z]', password):
        return False, "Password should contain at least one lowercase letter."
    
    if not re.search(r'[0-9]', password):
        return False, "Password should contain at least one number."
    
    return True, "Password is strong."


def encrypt_file(file_path, key, log_callback, stop_event=None):
    """
    Securely encrypts a file (any size) using AES-256-CTR streaming
    and authenticates with HMAC-SHA256.
    
    File format: [ 8-byte HEADER_PREFIX ] [ 16-byte IV ] [ 8-byte original_size ] [ encrypted_data ] [ 32-byte HMAC ]
    Returns: (success: bool, bytes_processed: int)
    """
    encryption_key = key[:32]
    hmac_key = key[32:64]
    
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())

    backup_path = file_path + BACKUP_EXTENSION
    temp_path = file_path + '.encrypting'

    try:
        # ADDED: Check for stop event before starting file operations
        if stop_event and stop_event.is_set():
            log_callback(f"⊘ Skipped (cancelled before start): {file_path}")
            return False, 0
            
        shutil.copy2(file_path, backup_path)
        
        file_size = os.path.getsize(file_path)
        
        if file_size > LARGE_FILE_WARNING_SIZE:
             log_callback(f"⚠️ Large file ({file_size // (1024**3)}GB): {file_path}")

        log_callback(f"⏳ Encrypting ({file_size // (1024*1024)}MB): {file_path}")

        with open(file_path, 'rb') as f_in, open(temp_path, 'wb') as f_out:
            # UPDATED: Use new versioned header
            header = FILE_HEADER_PREFIX + iv + struct.pack('<Q', file_size)
            f_out.write(header)
            h.update(header)
            
            bytes_processed = 0
            while True:
                # Check for cancellation every chunk
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
            if final_data:  # Only write if there's data
                f_out.write(final_data)
                h.update(final_data)
            
            mac_tag = h.finalize()
            f_out.write(mac_tag)
        
        os.replace(temp_path, file_path)
        
        try:
            os.remove(backup_path)
        except OSError:
            pass
            
        log_callback(f"✔ Encrypted: {file_path}")
        return True, file_size
        
    except InterruptedError:
        log_callback(f"⚠️ CANCELLED during encryption: {file_path}")
        log_callback(f"   File is likely CORRUPTED - restoring backup...")
        restore_backup(backup_path, file_path, log_callback)
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        return False, 0
    except PermissionError:
        log_callback(f"✗ Permission denied: {file_path}")
        restore_backup(backup_path, file_path, log_callback)
        return False, 0
    except Exception as e:
        log_callback(f"✗ Error encrypting {file_path}: {e}")
        restore_backup(backup_path, file_path, log_callback)
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return False, 0


def decrypt_file(file_path, key, log_callback, stop_event=None):
    """
    Securely decrypts a file using streaming with two-pass HMAC verification.
    Returns: (success: bool, bytes_processed: int)
    """
    encryption_key = key[:32]
    hmac_key = key[32:64]

    backup_path = file_path + BACKUP_EXTENSION
    temp_path = file_path + '.decrypting'
    
    try:
        # ADDED: Check for stop event before starting file operations
        if stop_event and stop_event.is_set():
            log_callback(f"⊘ Skipped (cancelled before start): {file_path}")
            return False, 0
            
        shutil.copy2(file_path, backup_path)
        
        file_size = os.path.getsize(file_path)

        if file_size > LARGE_FILE_WARNING_SIZE:
             log_callback(f"⚠️ Large file ({file_size // (1024**3)}GB): {file_path}")
             log_callback(f"   (Decryption requires two full reads: ~{ (file_size * 2) // (1024**3) }GB I/O)")
        
        log_callback(f"⏳ Decrypting ({file_size // (1024*1024)}MB): {file_path}")
        
        with open(file_path, 'rb') as f_in:
            header = f_in.read(32)
            if len(header) != 32:
                raise ValueError("Invalid file format: header too short.")
            
            # UPDATED: Check 5-byte magic prefix instead of full 8 bytes
            magic_prefix = header[:5]
            if magic_prefix != MAGIC_BYTES:
                raise ValueError("Invalid file format: not a CryptDir file.")
            
            # Optional: Check version
            file_version = header[5:7]
            if file_version > VERSION_BYTES:
                log_callback(f"  -> ⚠️ File version ({file_version[0]}.{file_version[1]}) is NEWER than app version ({VERSION_BYTES[0]}.{VERSION_BYTES[1]}).")
                raise ValueError("File version is too new to decrypt.")
            elif file_version < VERSION_BYTES:
                 log_callback(f"  -> ℹ Processing older file format (v{file_version[0]}.{file_version[1]}).")
                 
            iv = header[8:24]
            expected_size = struct.unpack('<Q', header[24:32])[0]
            
            # PASS 1: Verify HMAC by streaming
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(header)
            
            encrypted_data_size = file_size - 32 - 32
            
            bytes_verified = 0
            
            while bytes_verified < encrypted_data_size:
                # Check for cancellation every chunk
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
            
            stored_mac = f_in.read(32)
            if len(stored_mac) != 32:
                raise ValueError("Invalid file format: MAC tag missing or truncated")
            
            try:
                h.verify(stored_mac)
            except InvalidSignature: # CORRECTED EXCEPTION
                raise InvalidSignature("HMAC verification failed: wrong password or corrupted file")
            
            log_callback(f"  ✔ HMAC verified successfully")
            
            # PASS 2: Decrypt
            f_in.seek(32)
            
            cipher = Cipher(
                algorithms.AES(encryption_key), 
                modes.CTR(iv), 
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            with open(temp_path, 'wb') as f_out:
                bytes_decrypted = 0
                
                while bytes_decrypted < encrypted_data_size:
                    # Check for cancellation every chunk
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
                if final_data:  # Only write if there's data
                    f_out.write(final_data)

            decrypted_size = os.path.getsize(temp_path)
            if decrypted_size != expected_size:
                raise ValueError(
                    f"File integrity check failed: "
                    f"expected {expected_size} bytes, got {decrypted_size}"
                )

        os.replace(temp_path, file_path)
        
        try:
            os.remove(backup_path)
        except OSError:
            pass
            
        log_callback(f"✔ Decrypted: {file_path}")
        return True, expected_size

    except InterruptedError:
        log_callback(f"⚠️ CANCELLED during decryption: {file_path}")
        log_callback(f"   File restoration in progress...")
        restore_backup(backup_path, file_path, log_callback)
        if os.path.exists(temp_path): 
            try:
                os.remove(temp_path)
            except OSError:
                pass
        return False, 0
    except (InvalidSignature, ValueError, TypeError, struct.error) as e: # CORRECTED EXCEPTION
        error_msg = str(e)
        if "HMAC" in error_msg:
            log_callback(f"✗ Invalid password or corrupted: {file_path}")
        elif "format" in error_msg:
            log_callback(f"✗ Not a valid CryptDir file: {file_path}")
        elif "integrity" in error_msg:
             log_callback(f"✗ File corrupted (size mismatch): {file_path}")
        else:
            log_callback(f"✗ Corrupted file or error: {file_path} ({e})")

        restore_backup(backup_path, file_path, log_callback)
        if os.path.exists(temp_path): 
            os.remove(temp_path)
        return False, 0
    except PermissionError:
        log_callback(f"✗ Permission denied: {file_path}")
        restore_backup(backup_path, file_path, log_callback)
        return False, 0
    except Exception as e:
        log_callback(f"✗ Error decrypting {file_path}: {e}")
        restore_backup(backup_path, file_path, log_callback)
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return False, 0


# ----------------------------------------------------------------------
# ADDED: Test Decrypt Function (Recommendation #6)
# ----------------------------------------------------------------------

def test_decrypt_file(file_path, key, log_callback, stop_event=None):
    """
    Verifies a file's HMAC signature without decrypting or modifying it.
    This is Pass 1 of the decryption process only.
    Returns: (success: bool, bytes_processed: int)
    """
    hmac_key = key[32:64]
    
    try:
        file_size = os.path.getsize(file_path)
        
        if file_size < 64: # 32-byte header + 32-byte MAC
            raise ValueError("Invalid format: file too small.")

        # Check for stop event before opening
        if stop_event and stop_event.is_set():
            log_callback(f"⊘ Skipped (cancelled before start): {file_path}")
            return False, 0

        with open(file_path, 'rb') as f_in:
            header = f_in.read(32)
            if len(header) != 32:
                raise ValueError("Invalid format: header too short.")
            
            if header[:5] != MAGIC_BYTES: # Check 5-byte magic
                raise ValueError("Invalid format: not a CryptDir file.")
                
            # PASS 1: Verify HMAC
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(header)
            
            encrypted_data_size = file_size - 32 - 32
            
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
            
            stored_mac = f_in.read(32)
            if len(stored_mac) != 32:
                raise ValueError("Invalid format: MAC tag missing")
            
            h.verify(stored_mac) # Raises InvalidSignature on failure
            
            log_callback(f"✔ VERIFIED: {file_path}")
            return True, file_size

    except InterruptedError:
        log_callback(f"⚠️ CANCELLED during verification: {file_path}")
        return False, 0
    except (InvalidSignature, ValueError, TypeError, struct.error) as e:
        error_msg = str(e)
        if "HMAC" in error_msg:
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

def restore_backup(backup_path, original_path, log_callback):
    """Safely restores a backup file."""
    try:
        if os.path.exists(backup_path):
            shutil.move(backup_path, original_path)
            log_callback(f"↻ Restored from backup: {original_path}")
    except Exception as restore_error:
        log_callback(f"✗ CRITICAL: Failed to restore {original_path}: {restore_error}")
        log_callback(f"   Backup may still exist at: {backup_path}")


def should_skip_file(file_path, file_name, directory_path, disable_salt, manual_salt):
    """Determines if a file should be skipped during processing.
    
    Returns: (should_skip, reason)
    """
    if file_name.endswith(BACKUP_EXTENSION):
        return True, "backup file"
    
    if file_name.endswith(('.encrypting', '.decrypting')):
        return True, "temporary file"
    
    try:
        script_path = None
        if getattr(sys, 'frozen', False):
            script_path = sys.executable
        elif '__file__' in globals():
            script_path = os.path.abspath(__file__)
        
        if script_path and os.path.abspath(file_path) == script_path:
            return True, "application executable"
    except Exception:
        pass
    
    if file_name == SALT_FILENAME:
        if not disable_salt and not manual_salt:
            return True, "salt file (auto-generated)"
        return False, ""
    
    return False, ""


def process_directory(directory_path, key, operation, log_callback, stop_event, 
                     disable_salt, manual_salt, progress_callback):
    """
    Walks a directory and applies the operation to all files.
    Returns: (success_count, fail_count, skip_count, total_bytes_processed)
    """
    success_count = 0
    fail_count = 0
    skip_count = 0
    total_bytes_processed = 0
    
    try:
        for root, _, files in os.walk(directory_path):
            for file in files:
                if stop_event.is_set():
                    log_callback("\n⚠ Operation cancelled by user.")
                    return success_count, fail_count, skip_count, total_bytes_processed
                
                file_path = os.path.join(root, file)
                
                should_skip, skip_reason = should_skip_file(
                    file_path, file, directory_path, disable_salt, manual_salt
                )
                
                if should_skip:
                    log_callback(f"⊘ Skipped ({skip_reason}): {file_path}")
                    skip_count += 1
                    continue
                
                success = False
                size = 0
                if operation == 'encrypt':
                    success, size = encrypt_file(file_path, key, log_callback, stop_event)
                elif operation == 'decrypt':
                    success, size = decrypt_file(file_path, key, log_callback, stop_event)
                # ADDED: Handle 'test' operation
                elif operation == 'test':
                    success, size = test_decrypt_file(file_path, key, log_callback, stop_event)
                
                if success:
                    success_count += 1
                    total_bytes_processed += size
                else:
                    fail_count += 1
                
                # UPDATED: Progress callback is now indeterminate for folder mode
                # but we call it to keep the UI responsive and step the indeterminate bar
                progress_callback()
        
        return success_count, fail_count, skip_count, total_bytes_processed
            
    except Exception as e:
        log_callback(f"\n✗ Critical error during directory processing: {e}")
        return success_count, fail_count, skip_count, total_bytes_processed


def process_selected_files(file_list, key, operation, log_callback, stop_event, progress_callback):
    """
    Processes a specific list of files.
    Returns: (success_count, fail_count, skip_count, total_bytes_processed)
    """
    success_count = 0
    fail_count = 0
    skip_count = 0
    total_bytes_processed = 0
    
    try:
        for file_path in file_list:
            if stop_event.is_set():
                log_callback("\n⚠ Operation cancelled by user.")
                return success_count, fail_count, skip_count, total_bytes_processed
            
            if not os.path.exists(file_path):
                log_callback(f"✗ File not found (skipped): {file_path}")
                fail_count += 1
                progress_callback() # Step progress bar even for failures
                continue
            
            success = False
            size = 0
            if operation == 'encrypt':
                success, size = encrypt_file(file_path, key, log_callback, stop_event)
            elif operation == 'decrypt':
                success, size = decrypt_file(file_path, key, log_callback, stop_event)
            # ADDED: Handle 'test' operation
            elif operation == 'test':
                success, size = test_decrypt_file(file_path, key, log_callback, stop_event)
            
            if success:
                success_count += 1
                total_bytes_processed += size
            else:
                fail_count += 1
            
            # UPDATED: This will step the determinate progress bar
            progress_callback()
        
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

        self.title("🔐 CryptDir Pro v2.10.5 Enhanced")
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
        self.processing_thread = None
        self.current_operation = None

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
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
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
        
        tk.Label(title_frame, text="Professional File Encryption Suite v2.10.5 ~by COLDMAN", 
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
            text="⚠ Disable Salting (INSECURE - legacy only)",
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
        
        tk.Label(salt_frame, text="Manual Salt (Optional - keep it secret!):", 
                fg=self.text_gray, bg=self.bg_medium, 
                font=("Segoe UI", 9), anchor="w").pack(fill=tk.X, padx=10, pady=(5, 0))
        
        self.ent_salt = tk.Entry(salt_frame, bg=self.bg_light, fg=self.text_white, 
                                font=("Consolas", 10), insertbackground=self.text_white, 
                                bd=0, relief=tk.FLAT)
        self.ent_salt.pack(fill=tk.X, ipady=8, padx=10, pady=(5, 10))

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
        
        # ADDED: Test Decrypt button
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
        
        # NOTE: No sys.platform check added here per "Windows-only" user constraint.
        
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
        
        # Initial log messages
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

    def safe_ui_update(self, callback):
        """Safely schedules UI update if window still exists."""
        if not self._is_closing and self.winfo_exists():
            try:
                self.after(0, callback)
            except tk.TclError:
                pass
    
    def safe_progress_step(self):
        """
        Safely steps the progress bar from any thread.
        Steps determinate bar, or just pings indeterminate bar.
        """
        def _step():
            if self._is_closing or not self.progress_bar.winfo_exists():
                return
            try:
                if self.progress_bar['mode'] == 'determinate':
                    self.progress_bar.step()
                else:
                    # For indeterminate, 'step' just keeps it moving
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
            
            # Clear file selection if directory changed
            if self.process_mode.get() == "files" and path != old_dir:
                self.selected_files = []
                self.file_listbox.delete(0, tk.END)
                self.log_status("   (File selection cleared due to directory change)")

    def toggle_salt_options(self):
        """Disables or enables the manual salt entry based on the checkbox."""
        if self._is_closing:
            return
            
        is_disabled = self.disable_salt_var.get()
        new_state = tk.DISABLED if is_disabled else tk.NORMAL
        bg_color = self.bg_medium if is_disabled else self.bg_light
        
        if is_disabled:
            self.ent_salt.delete(0, tk.END)
        
        try:
            if self.ent_salt.winfo_exists():
                self.ent_salt.config(state=new_state, bg=bg_color)
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
                
                # Update main control widgets
                widgets = [self.btn_browse, self.ent_pass, self.chk_disable_salt,
                          self.btn_encrypt, self.btn_decrypt, self.btn_toggle_hide,
                          self.btn_choose_files, self.btn_test_decrypt] # Added test button
                
                # Add radio buttons
                if hasattr(self, 'mode_frame') and self.mode_frame.winfo_exists():
                    for child in self.mode_frame.winfo_children():
                        widgets.append(child)
                
                for widget in widgets:
                    if widget.winfo_exists():
                        widget.config(state=state)
                
                # Special handling for salt entry
                if self.ent_salt.winfo_exists():
                    salt_state = tk.DISABLED if (is_processing or self.disable_salt_var.get()) else tk.NORMAL
                    salt_bg = self.bg_medium if salt_state == tk.DISABLED else self.bg_light
                    self.ent_salt.config(state=salt_state, bg=salt_bg)
                
                # File listbox
                if self.file_listbox.winfo_exists():
                    self.file_listbox.config(state=state)
                
                # Cancel button
                if self.btn_cancel.winfo_exists():
                    self.btn_cancel.config(state=cancel_state)
                
                # Progress bar
                if is_processing:
                    if self.current_operation == 'encrypt':
                        self.btn_encrypt.config(text="🔒 ENCRYPTING...")
                    elif self.current_operation == 'decrypt':
                        self.btn_decrypt.config(text="🔓 DECRYPTING...")
                    elif self.current_operation == 'test':
                        self.btn_test_decrypt.config(text="🧪 TESTING...")
                    
                    if self.progress_bar.winfo_exists():
                        # UPDATED: Use determinate for files mode, indeterminate for folder mode
                        if total_files > 0:
                            self.progress_bar.config(mode='determinate', maximum=total_files, value=0)
                        else:
                            self.progress_bar.config(mode='indeterminate')
                            self.progress_bar.start(15) # Start indeterminate animation
                            
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
                        self.progress_bar.stop() # Stop indeterminate animation
                        self.progress_bar.pack_forget()
                        self.progress_bar.config(mode='indeterminate', value=0)
                        
            except tk.TclError:
                pass
        
        self.safe_ui_update(_set)

    def check_inputs(self):
        """Validates inputs before processing."""
        directory = self.directory_path.get()
        password = self.ent_pass.get()
        mode = self.process_mode.get()
        
        # Validate directory
        if not directory or not os.path.isdir(directory):
            messagebox.showerror("Input Error", "Please select a valid directory.")
            return False
        
        # Validate password exists
        if not password:
            messagebox.showerror("Input Error", "Please enter a password.")
            return False
        
        # Validate file selection for files mode
        if mode == "files" and not self.selected_files:
            messagebox.showerror("Input Error", "Please choose specific files or switch to folder mode.")
            return False
        
        # Validate password strength (with option to proceed)
        is_valid, message = validate_password(password)
        if not is_valid:
            response = messagebox.askyesno(
                "Weak Password", 
                f"{message}\n\nUsing a weak password significantly reduces security.\n\n"
                "Do you want to proceed anyway?"
            )
            if not response:
                return False
        
        # Check for self-encryption (folder mode only)
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
        
        return True

    # REMOVED: _get_process_file_count (no longer needed for single-pass scan)

    def toggle_folder_visibility(self):
        """Hides or unhides the selected folder (Windows only)."""
        if sys.platform != "win32":
            self.log_status("\n⚠ Folder hiding is only supported on Windows.")
            # This check is sufficient given the "Windows-only" constraint.
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
        if not self.check_inputs():
            return
        
        directory = self.directory_path.get()
        password = self.ent_pass.get()
        disable_salt = self.disable_salt_var.get()
        manual_salt = self.ent_salt.get()
        mode = self.process_mode.get()
        
        # UPDATED: Only count files for "files" mode
        total_files = 0
        if mode == "folder":
            target_desc = f"all processable files in:\n{directory}"
        else:  # files mode
            total_files = len(self.selected_files)
            target_desc = f"{total_files} selected file(s)"
            if total_files == 0:
                self.log_status("ℹ No files found to encrypt.")
                messagebox.showinfo("Operation", "No files to encrypt.")
                return
            
        self.log_status(f"\nℹ Encrypting {target_desc}")
        
        # Build confirmation message
        confirm_msg = f"This will encrypt {target_desc}\n\n"
        
        if disable_salt:
            confirm_msg += "⚠ WARNING: Salting DISABLED (insecure).\n\n"
        elif manual_salt:
            confirm_msg += "ℹ Using MANUAL salt. Remember it for decryption!\n\n"
        else:
            confirm_msg += f"ℹ A '{SALT_FILENAME}' file will be created. Keep it safe!\n\n"
        
        confirm_msg += "✓ Files will be backed up during encryption.\n\nContinue?"

        if not messagebox.askyesno("Confirm Encryption", confirm_msg):
            self.log_status("🛑 Encryption cancelled by user.")
            return

        self.log_status("\n" + "="*60)
        self.log_status("🔒 Starting encryption...")
        self.log_status("="*60)
        
        self.current_operation = 'encrypt'
        self.set_ui_processing(True, total_files) # Pass total_files for progress bar
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
            
            if disable_salt:
                salt = b'no_salt_used_insecure'
                self.log_status("⚠ WARNING: Salting is disabled (insecure).")
            elif manual_salt:
                salt = manual_salt.encode('utf-8')
                self.log_status("🧂 Using provided manual salt.")
            else:
                salt = os.urandom(16)
                try:
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
            
            if mode == "folder":
                stats = process_directory(
                    directory, key, 'encrypt', self.log_status,
                    self.stop_event, disable_salt, bool(manual_salt),
                    self.safe_progress_step
                )
            else:  # files mode
                stats = process_selected_files(
                    self.selected_files, key, 'encrypt', self.log_status,
                    self.stop_event, self.safe_progress_step
                )
            
            success, fail, skip, total_bytes = stats
            
            if not self.stop_event.is_set():
                end_time = time.time()
                elapsed = end_time - start_time
                
                # Format bytes
                if total_bytes < 1024**2:
                    size_str = f"{total_bytes / 1024.0:.2f} KB"
                elif total_bytes < 1024**3:
                    size_str = f"{total_bytes / (1024.0**2):.2f} MB"
                else:
                    size_str = f"{total_bytes / (1024.0**3):.2f} GB"
                
                # Format speed
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

        # UPDATED: Only count files for "files" mode
        total_files = 0
        if mode == "folder":
            target_desc = f"all processable files in:\n{directory}"
        else:  # files mode
            total_files = len(self.selected_files)
            target_desc = f"{total_files} selected file(s)"
            if total_files == 0:
                self.log_status("ℹ No files found to decrypt.")
                messagebox.showinfo("Operation", "No files to decrypt.")
                return
            
        self.log_status(f"\nℹ Decrypting {target_desc}")
        
        # Build confirmation message
        confirm_msg = f"This will attempt to decrypt {target_desc}\n\n"
        
        if disable_salt:
            confirm_msg += "⚠ WARNING: Attempting decryption with salting disabled.\n\n"
        elif manual_salt:
            confirm_msg += "ℹ Using MANUAL salt.\n\n"
        else:
            confirm_msg += f"ℹ Requires '{SALT_FILENAME}' in the directory.\n\n"
        
        confirm_msg += "✓ Files will be backed up during decryption.\n\nContinue?"

        if not messagebox.askyesno("Confirm Decryption", confirm_msg):
            self.log_status("🛑 Decryption cancelled by user.")
            return

        self.log_status("\n" + "="*60)
        self.log_status("🔓 Starting decryption...")
        self.log_status("="*60)
        
        self.current_operation = 'decrypt'
        self.set_ui_processing(True, total_files)
        self.stop_event.clear()

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

            if disable_salt:
                salt = b'no_salt_used_insecure'
                self.log_status("⚠ Attempting decryption with salting disabled.")
            elif manual_salt:
                salt = manual_salt.encode('utf-8')
                self.log_status("🧂 Using provided manual salt.")
            else:
                try:
                    with open(salt_path, 'rb') as f:
                        salt = f.read()
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
            
            if mode == "folder":
                stats = process_directory(
                    directory, key, 'decrypt', self.log_status,
                    self.stop_event, disable_salt, bool(manual_salt),
                    self.safe_progress_step
                )
            else:  # files mode
                stats = process_selected_files(
                    self.selected_files, key, 'decrypt', self.log_status,
                    self.stop_event, self.safe_progress_step
                )
            
            success, fail, skip, total_bytes = stats
            
            if not self.stop_event.is_set():
                end_time = time.time()
                elapsed = end_time - start_time
                
                # Format bytes
                if total_bytes < 1024**2:
                    size_str = f"{total_bytes / 1024.0:.2f} KB"
                elif total_bytes < 1024**3:
                    size_str = f"{total_bytes / (1024.0**2):.2f} MB"
                else:
                    size_str = f"{total_bytes / (1024.0**3):.2f} GB"
                
                # Format speed
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

    # ----------------------------------------------------------------------
    # ADDED: Test Decrypt Methods (Recommendation #6)
    # ----------------------------------------------------------------------

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
        else:  # files mode
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
            confirm_msg += "⚠ Attempting test with salting disabled.\n\n"
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

            if disable_salt:
                salt = b'no_salt_used_insecure'
                self.log_status("⚠ Attempting test with salting disabled.")
            elif manual_salt:
                salt = manual_salt.encode('utf-8')
                self.log_status("🧂 Using provided manual salt.")
            else:
                try:
                    with open(salt_path, 'rb') as f:
                        salt = f.read()
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
                    self.stop_event, disable_salt, bool(manual_salt),
                    self.safe_progress_step
                )
            else:  # files mode
                stats = process_selected_files(
                    self.selected_files, key, 'test', self.log_status,
                    self.stop_event, self.safe_progress_step
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

    # ----------------------------------------------------------------------
    # Window Closing / Cancellation
    # ----------------------------------------------------------------------

    def cancel_operation(self):
        """Sets an event to stop the processing thread with warning."""
        if self.processing_thread and self.processing_thread.is_alive():
            response = messagebox.askyesno(
                "⚠️ Cancel Operation Warning",
                "CRITICAL WARNING:\n\n"
                "Cancelling now may leave files in an UNREADABLE state!\n\n"
                "Files currently being processed may become corrupted and permanently unrecoverable. "
                "Backup files (.backup_temp) will remain if interruption occurs.\n\n"
                "It is STRONGLY RECOMMENDED to let the operation complete.\n\n"
                "Are you absolutely sure you want to cancel?",
                icon='warning'
            )
            
            if response:
                self.log_status("\n⚠️ CANCEL CONFIRMED - Stopping operation...")
                self.log_status("⚠️ WARNING: Files being processed may be corrupted!")
                self.stop_event.set()
                
                # Disable cancel button immediately to prevent multiple clicks
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
                
                # Give thread a moment to respond
                self.after(300, self._force_destroy)
            return
        
        self._is_closing = True
        self.destroy()

    def _force_destroy(self):
        """Forces window destruction after brief wait."""
        if self.winfo_exists():
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