import os
import sys
import subprocess
import random
import time
import math
import collections
import re
import sqlite3
import io
from datetime import datetime

# ==========================================
# 1. BAGIAN AUTO-INSTALLER
# ==========================================
def install_dependencies():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    req_file = os.path.join(base_dir, 'requirements.txt')
    
    # Tambahkan pandas dan openpyxl untuk fitur Excel
    required_packages = ['flask', 'PyPDF2', 'pandas', 'openpyxl', 'pycryptodome']
    
    missing = []
    for pkg in required_packages:
        try:
            if pkg == 'PyPDF2': import PyPDF2
            elif pkg == 'openpyxl': import openpyxl
            elif pkg == 'pycryptodome': from Crypto.Cipher import AES
            else: __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"⚠️  Library belum lengkap ({', '.join(missing)}). Sedang menginstall otomatis...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
            print("✅ Instalasi Selesai! Melanjutkan program...\n")
        except subprocess.CalledProcessError:
            print("❌ Gagal menginstall library.")
            sys.exit(1)

install_dependencies()

import pandas as pd 
from flask import Flask, render_template, request, jsonify, send_from_directory, send_file
from werkzeug.utils import secure_filename
from PyPDF2 import PdfReader
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ==========================================
# 2. KONFIGURASI & DATABASE
# ==========================================
app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['RESULTS_FOLDER'] = os.path.join(BASE_DIR, 'results')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.secret_key = 'kuncirahasiaskripsi_gabungan' 

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULTS_FOLDER'], exist_ok=True)

DB_NAME = 'encryption_history.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            method TEXT,
            key_length INTEGER,
            final_key TEXT,
            fitness REAL,
            time_taken REAL,
            entropy REAL,
            p_value REAL,
            enc_filename TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_to_history(data):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            INSERT INTO history 
            (filename, method, key_length, final_key, fitness, time_taken, entropy, p_value, enc_filename)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['filename'],
            data['method'],
            data['key_length'],
            data['final_key'],
            data['fitness'],
            data['time_taken'],
            data['entropy'],
            data['p_value'],
            data['enc_filename']
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving to DB: {e}")

init_db()

# ==========================================
# 3. UTILITIES
# ==========================================
class PRNG:
    def __init__(self, seed):
        self.seed = int(seed)
        self.random = random.Random(self.seed)
    
    def next(self):
        # PERBAIKAN UTAMA: Range 32-126 (Printable ASCII)
        # Menghindari karakter kontrol (0-31) yang menyebabkan error Excel
        # dan karakter hilang di database.
        return self.random.randint(32, 126)

    def randint(self, a, b):
        """Helper untuk menghasilkan angka random dalam range a-b (inklusif)"""
        return self.random.randint(a, b)

class EvaluationUtils:
    @staticmethod
    def calculate_entropy(data_bytes):
        if not data_bytes: return 0
        entropy = 0
        length = len(data_bytes)
        counter = collections.Counter(data_bytes)
        for count in counter.values():
            p_x = count / length
            entropy += - p_x * math.log2(p_x)
        return entropy

    @staticmethod
    def monobit_frequency_test(key_str):
        try: key_bytes = key_str.encode('latin-1')
        except: key_bytes = key_str.encode('utf-8')
        binary_str = ''.join(format(b, '08b') for b in key_bytes)
        n = len(binary_str)
        if n == 0: return {'ones':0, 'zeros':0, 'p_value':0, 'status':"Error"}
        sn = binary_str.count('1') - binary_str.count('0')
        s_obs = abs(sn) / math.sqrt(n)
        p_value = math.erfc(s_obs / math.sqrt(2))
        return {
            'ones': binary_str.count('1'), 'zeros': binary_str.count('0'),
            'p_value': p_value,
            'status': "Lulus (Acak)" if p_value >= 0.01 else "Gagal"
        }

# S-Box dan R-Con dipindahkan ke level module agar bisa diakses global
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
R_CON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def _prepare_key(key_str):
    """Memastikan kunci sesuai panjang AES (16, 24, atau 32 bytes)"""
    try: key_bytes = key_str.encode('latin-1')
    except: key_bytes = key_str.encode('utf-8')
    if len(key_bytes) <= 16: return key_bytes.ljust(16, b'\0')
    if len(key_bytes) <= 24: return key_bytes.ljust(24, b'\0')
    return key_bytes.ljust(32, b'\0')[:32]

def _expand_key(key_bytes):
    """Internal function to generate round keys list"""
    def sub_word(word): return bytes([S_BOX[b] for b in word])
    def rot_word(word): return word[1:] + word[:1]

    nk = len(key_bytes) // 4
    if nk not in (4, 6, 8): return [], 0, ""
    rounds = {4: 10, 6: 12, 8: 14}[nk]
    aes_ver = {4: "AES-128", 6: "AES-192", 8: "AES-256"}[nk]
    w = [key_bytes[i:i+4] for i in range(0, len(key_bytes), 4)]

    for i in range(nk, 4 * (rounds + 1)):
        temp = w[i-1]
        if i % nk == 0:
            temp = bytes([a ^ b for a, b in zip(sub_word(rot_word(temp)), [R_CON[i // nk], 0, 0, 0])])
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        w.append(bytes([a ^ b for a, b in zip(w[i-nk], temp)]))
    
    # Convert to list of 16-byte round keys
    round_keys = [b''.join(w[i*4:(i+1)*4]) for i in range(rounds + 1)]
    return round_keys, rounds, aes_ver

class AESUtils:
    # --- AES CORE OPERATIONS (Static for reuse) ---
    @staticmethod
    def sub_bytes(s): return [S_BOX[b] for b in s]
    
    @staticmethod
    def shift_rows(s):
        return [
            s[0], s[1], s[2], s[3],
            s[5], s[6], s[7], s[4],
            s[10], s[11], s[8], s[9],
            s[15], s[12], s[13], s[14]
        ]

    @staticmethod
    def add_round_key(s, rk): return [a ^ b for a, b in zip(s, rk)]
    
    @staticmethod
    def gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi: a ^= 0x1B
            b >>= 1
        return p

    @staticmethod
    def mix_columns(s):
        new_s = [0]*16
        for c in range(4):
            col = [s[c], s[c+4], s[c+8], s[c+12]]
            new_s[c]    = AESUtils.gmul(col[0],2)^AESUtils.gmul(col[1],3)^AESUtils.gmul(col[2],1)^AESUtils.gmul(col[3],1)
            new_s[c+4]  = AESUtils.gmul(col[0],1)^AESUtils.gmul(col[1],2)^AESUtils.gmul(col[2],3)^AESUtils.gmul(col[3],1)
            new_s[c+8]  = AESUtils.gmul(col[0],1)^AESUtils.gmul(col[1],1)^AESUtils.gmul(col[2],2)^AESUtils.gmul(col[3],3)
            new_s[c+12] = AESUtils.gmul(col[0],3)^AESUtils.gmul(col[1],1)^AESUtils.gmul(col[2],1)^AESUtils.gmul(col[3],2)
        return new_s

    @staticmethod
    def encrypt_file_custom(file_path, key_list_str):
        """Enkripsi Manual menggunakan Round Keys dari GA (Gen 1-11)"""
        # 1. Prepare Keys
        round_keys = []
        for k in key_list_str:
            kb = _prepare_key(k)
            round_keys.append(kb[:16]) # Force 16 bytes
        
        # Ensure 11 keys (Round 0-10)
        while len(round_keys) < 11: round_keys.append(round_keys[-1])
        round_keys = round_keys[:11]

        try:
            with open(file_path, 'rb') as f: plaintext_bytes = bytearray(f.read())
            
            start_time = time.perf_counter()
            
            # Manual Padding (PKCS7)
            pad_len = 16 - (len(plaintext_bytes) % 16)
            plaintext_bytes.extend([pad_len] * pad_len)
            
            ciphertext_bytes = bytearray()
            
            # Process Blocks
            for i in range(0, len(plaintext_bytes), 16):
                state = list(plaintext_bytes[i:i+16])
                
                state = AESUtils.add_round_key(state, round_keys[0])
                for r in range(1, 10):
                    state = AESUtils.sub_bytes(state)
                    state = AESUtils.shift_rows(state)
                    state = AESUtils.mix_columns(state)
                    state = AESUtils.add_round_key(state, round_keys[r])
                
                state = AESUtils.sub_bytes(state)
                state = AESUtils.shift_rows(state)
                state = AESUtils.add_round_key(state, round_keys[10])
                
                ciphertext_bytes.extend(state)
                
            encryption_time = time.perf_counter() - start_time
            
            filename = os.path.basename(file_path)
            enc_filename = filename + ".enc"
            enc_path = os.path.join(app.config['RESULTS_FOLDER'], enc_filename)
            with open(enc_path, 'wb') as f: f.write(ciphertext_bytes)
            
            # Logs
            ascii_preview = ciphertext_bytes[:500].decode('latin-1', errors='replace')
            entropy_val = EvaluationUtils.calculate_entropy(ciphertext_bytes)
            
            # Calculate stats for the last key to ensure p_value exists for frontend
            last_key = key_list_str[-1] if key_list_str else ""
            key_stats = EvaluationUtils.monobit_frequency_test(last_key)
            key_stats['status'] = 'Custom GA Keys'

            key_schedule_html = AESUtils.generate_round_keys_html(None, custom_keys=round_keys, custom_keys_str=key_list_str)
            sim_html = AESUtils.simulate_aes_block_html(plaintext_bytes[:16], None, len(plaintext_bytes), custom_keys=round_keys)
            
            return {
                'success': True, 'enc_filename': enc_filename, 'ascii_preview': ascii_preview,
                'metrics': {'time_taken_sec': f"{encryption_time:.6f}", 'entropy': f"{entropy_val:.5f}", 'key_stats': key_stats},
                'simulation_html': key_schedule_html + sim_html
            }
        except Exception as e: return {'success': False, 'error': str(e)}

    @staticmethod
    def generate_round_keys_html(key_bytes, custom_keys=None, custom_keys_str=None):
        if custom_keys:
            round_keys = custom_keys
            rounds = len(round_keys) - 1
            aes_ver = "Custom GA Keys"
        else:
            round_keys, rounds, aes_ver = _expand_key(key_bytes)
            if not round_keys: return ""
        
        html = [f"<div class='mt-3 mb-2'><strong>>> AES Key Schedule ({aes_ver} - {rounds} Rounds)</strong></div>"]
        html.append("<div class='table-responsive' style='max-height: 300px; overflow-y: auto;'>")
        html.append("<table class='table table-sm table-bordered table-striped mb-0' style='font-size: 0.8em; font-family: monospace; text-align: center;'>")
        
        if custom_keys_str:
            html.append("<thead class='table-dark'><tr><th>Round</th><th>Round Key (Text)</th><th>Round Key (Hex)</th><th>Bits</th></tr></thead><tbody>")
            for r, (round_key, rk_str) in enumerate(zip(round_keys, custom_keys_str)):
                safe_str = rk_str.replace('<', '&lt;').replace('>', '&gt;')
                disp_str = safe_str[:16] # Hanya 16 byte pertama yang digunakan sebagai state
                html.append(f"<tr><td>{r}</td><td>{disp_str}</td><td>{round_key.hex().upper()}</td><td>{len(round_key)*8}</td></tr>")
        else:
            html.append("<thead class='table-dark'><tr><th>Round</th><th>Round Key (Hex)</th><th>Bits</th></tr></thead><tbody>")
            for r, round_key in enumerate(round_keys):
                html.append(f"<tr><td>{r}</td><td>{round_key.hex().upper()}</td><td>{len(round_key)*8}</td></tr>")
                
        html.append("</tbody></table></div>")
        return "".join(html)

    @staticmethod
    def simulate_aes_block_html(plaintext_block, key_bytes, total_len=0, custom_keys=None):
        """Simulasi visualisasi proses AES untuk 1 blok (16 bytes)"""
        if custom_keys:
            round_keys = custom_keys
            rounds = len(round_keys) - 1
        else:
            round_keys, rounds, _ = _expand_key(key_bytes)
            if not round_keys: return ""

        state = list(plaintext_block)

        def format_grid(st, title, color="bg-light"):
            h = [f"<div class='col-md-3 mb-2'><div class='card'><div class='card-header py-1 small fw-bold {color}'>{title}</div><div class='card-body p-1'><table class='table table-bordered table-sm mb-0' style='font-size:0.65em; text-align:center'>"]
            for r in range(4):
                h.append("<tr>")
                for c in range(4):
                    # Displaying in row-major for readability: index = r*4 + c
                    val = st[r*4 + c] # Simple mapping
                    h.append(f"<td>{val:02X}</td>")
                h.append("</tr>")
            h.append("</table></div></div></div>")
            return "".join(h)

        # --- LOGGING ---
        count_info = f" (Blok 1 dari {total_len // 16:,} Total Blok)" if total_len > 0 else " (Blok Pertama - 16 Bytes)"
        html = [f"<div class='mt-4 mb-2'><strong>>>> Simulasi Proses Enkripsi{count_info}</strong></div>"]
        if total_len > 16:
            html.append(f"<div class='alert alert-light border py-1 small text-muted'>ℹ️ Catatan: Karena keterbatasan tampilan log, hanya blok pertama (16 byte) yang divisualisasikan. Total ukuran data terenkripsi: {total_len:,} bytes.</div>")
        
        html.append("<div class='row mb-3'>")
        html.append(format_grid(state, "Input (Plaintext)", "bg-secondary text-white"))
        
        state = AESUtils.add_round_key(state, round_keys[0])
        html.append(format_grid(state, "Round 0 (AddRoundKey)"))
        html.append("</div>")
        
        for r in range(1, rounds):
            html.append("<div class='row mb-3'>")
            state = AESUtils.sub_bytes(state)
            html.append(format_grid(state, f"R{r}: SubBytes", "bg-info bg-opacity-25"))
            state = AESUtils.shift_rows(state)
            html.append(format_grid(state, f"R{r}: ShiftRows", "bg-info bg-opacity-25"))
            state = AESUtils.mix_columns(state)
            html.append(format_grid(state, f"R{r}: MixColumns", "bg-info bg-opacity-25"))
            state = AESUtils.add_round_key(state, round_keys[r])
            html.append(format_grid(state, f"R{r}: AddRoundKey", "bg-info bg-opacity-25"))
            html.append("</div>")
        
        html.append("<div class='row mb-3'>")
        state = AESUtils.sub_bytes(state)
        html.append(format_grid(state, f"R{rounds}: SubBytes", "bg-warning bg-opacity-25"))
        state = AESUtils.shift_rows(state)
        html.append(format_grid(state, f"R{rounds}: ShiftRows", "bg-warning bg-opacity-25"))
        state = AESUtils.add_round_key(state, round_keys[rounds])
        html.append(format_grid(state, f"R{rounds}: AddRoundKey", "bg-warning bg-opacity-25"))
        
        html.append(format_grid(state, "Output (Ciphertext)", "bg-success text-white"))
        html.append("</div>")
        
        return "".join(html)

    @staticmethod
    def encrypt_file_aes(file_path, key_str):
        try:
            with open(file_path, 'rb') as f: plaintext_bytes = bytearray(f.read())
            
            key_bytes = _prepare_key(key_str)
            
            start_time = time.perf_counter()
            
            # AES ECB Mode (AES Murni - Tanpa IV, Tanpa Chaining)
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            padded_data = pad(plaintext_bytes, AES.block_size)
            ciphertext_bytes = cipher.encrypt(padded_data)
            
            final_data = ciphertext_bytes
            
            encryption_time = time.perf_counter() - start_time
            
            filename = os.path.basename(file_path)
            enc_filename = filename + ".enc"
            enc_path = os.path.join(app.config['RESULTS_FOLDER'], enc_filename)
            
            with open(enc_path, 'wb') as f: f.write(final_data)
            
            # Internal Check
            cipher_dec = AES.new(key_bytes, AES.MODE_ECB)
            decrypted_bytes = unpad(cipher_dec.decrypt(ciphertext_bytes), AES.block_size)
            
            with open(os.path.join(app.config['RESULTS_FOLDER'], "INTERNAL_CHECK_" + filename), 'wb') as f:
                f.write(decrypted_bytes)

            ascii_preview = final_data[:500].decode('latin-1', errors='replace')
            entropy_val = EvaluationUtils.calculate_entropy(final_data)
            key_stats = EvaluationUtils.monobit_frequency_test(key_str)
            
            # Generate Key Schedule HTML
            key_schedule_html = AESUtils.generate_round_keys_html(key_bytes)
            
            # Generate Simulation HTML for the first block
            first_block = padded_data[:16]
            sim_html = AESUtils.simulate_aes_block_html(first_block, key_bytes, len(padded_data))

            return {
                'success': True, 'enc_filename': enc_filename, 'ascii_preview': ascii_preview,
                'metrics': {'time_taken_sec': f"{encryption_time:.6f}", 'entropy': f"{entropy_val:.5f}", 'key_stats': key_stats},
                'simulation_html': key_schedule_html + sim_html
            }
        except Exception as e: return {'success': False, 'error': str(e)}

    @staticmethod
    def decrypt_file_aes(file_path, key_str):
        try:
            with open(file_path, 'rb') as f: file_content = f.read()
            
            key_bytes = _prepare_key(key_str)
            
            # ECB tidak memiliki IV, seluruh file adalah ciphertext
            ciphertext = file_content
            
            start_time = time.perf_counter()
            
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            plain_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            decrypt_time = time.perf_counter() - start_time
            
            original_name = os.path.basename(file_path).replace('.enc', '')
            if not original_name.lower().endswith('.pdf'): original_name += '.pdf'
            dec_filename = "HASIL_DEKRIPSI_" + original_name
            with open(os.path.join(app.config['RESULTS_FOLDER'], dec_filename), 'wb') as f: f.write(plain_bytes)
            return {'success': True, 'dec_filename': dec_filename, 'time_taken': f"{decrypt_time:.6f}"}
        except Exception as e: return {'success': False, 'error': str(e)}

class GeneticUtils:
    @staticmethod
    def format_matrix_html(population, title):
        if not population: return ""
        chrom_len = len(population[0])
        # Hanya render judul jika title tidak kosong
        html = [f"<div class='mt-3 mb-2'><strong>>> {title}</strong></div>"] if title else []
        html.append("<div class='table-responsive' style='overflow-x: auto; white-space: nowrap; border: 1px solid #ccc;'>")
        html.append("<table class='table table-sm table-bordered table-striped mb-0' style='font-size: 0.75em; text-align: center; font-family: monospace;'>")
        html.append("<thead class='table-dark'><tr>")
        html.append("<th style='position: sticky; left: 0; z-index: 1;'>Individu</th>") 
        for g in range(chrom_len): html.append(f"<th>G{g+1}</th>")
        html.append("</tr></thead><tbody>")
        for i, chrom in enumerate(population):
            html.append("<tr>")
            html.append(f"<td class='fw-bold bg-light' style='position: sticky; left: 0;'>Kromosom {i+1}</td>")
            for gene in chrom: html.append(f"<td>{gene}</td>")
            html.append("</tr>")
        html.append("</tbody></table></div>")
        return "".join(html)

    @staticmethod
    def text_to_ascii(text):
        return [ord(char) for char in text]

    @staticmethod
    def ascii_to_text(ascii_list):
        # Filter hanya karakter valid 32-126 agar konsisten
        return ''.join(chr(code) for code in ascii_list if 32 <= code <= 126)

    @staticmethod
    def calculate_ascii_sum(text):
        return sum(ord(char) for char in text)

    @staticmethod
    def process_file_binary(file_path, key_str, ga_keys=None):
        return AESUtils.encrypt_file_aes(file_path, key_str)

    @staticmethod
    def manual_decryption(file_path, key_str):
        return AESUtils.decrypt_file_aes(file_path, key_str)

    @staticmethod
    def generate_key_from_metadata(file_path, key_length=32):
        try:
            stat = os.stat(file_path)
            content_text = ""
            with open(file_path, 'rb') as f: raw_bytes = f.read() 
            binary_preview = raw_bytes.hex().upper() 

            if file_path.lower().endswith('.pdf'):
                try:
                    reader = PdfReader(file_path)
                    for page in reader.pages:
                        text = page.extract_text()
                        if text: content_text += text + "\n"
                except Exception as e: return {'error': f'PDF Error: {str(e)}'}
            else: return {'error': 'Bukan PDF'}

            size_kb = stat.st_size / 1024
            metadata = {
                'filename': os.path.basename(file_path),
                'size': f"{size_kb:.2f} KB",
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            }

            data = {}
            patterns = [
                (r"Name:\s*(.*?)\s*DOB:", 'Name'), (r"DOB:\s*(.*?)\s*Age:", 'DOB'),
                (r"Age:\s*(.*?)\s*Sex:", 'Age'), (r"Sex:\s*(.*?)\s*SSN:", 'Sex'),
                (r"SSN:\s*(.*?)\s*Hospital ID:", 'SSN'), (r"Hospital ID:\s*(.*?)\s*Patient Lifestyle", 'Hospital ID'),
                (r"Recorded Date:\s*(\d{2}/\d{2}/\d{4})", 'Recorded Date'),
                (r"Doctor Name:\s*(.*?)\s*Doctor Unique ID:", 'Doctor Name'),
                (r"Doctor Unique ID:\s*([A-Z0-9]+)", 'Doctor Unique ID')
            ]
            for pat, key in patterns:
                match = re.search(pat, content_text, re.DOTALL | re.IGNORECASE)
                if match: data[key] = match.group(1)

            raw_string = "".join(data.values() if data else [])
            # Filter hanya alphanum untuk metadata key awal
            raw_key = "".join(ch for ch in raw_string if ch.isalnum())
            if len(raw_key) < 5: raw_key = "".join(ch for ch in content_text if ch.isalnum())

            final_key = raw_key[:key_length]
            while len(final_key) < key_length: final_key += "X"

            return {'metadata': metadata, 'generated_key': final_key, 'plaintext_sample': binary_preview}
        except Exception as e: return {'error': str(e)}

    # --- GA & HYBRID ---
    @staticmethod
    def fitness_function(chromosome, target_key_ascii):
        total_diff = sum(abs(target_key_ascii[i] - chromosome[i]) for i in range(len(target_key_ascii)))
        return 100000 / (total_diff + 1)

    @staticmethod
    def tournament_selection(population, fitness_scores, base_seed, debug=False):
        selected = []
        debug_html = [] 
        temp_seed = base_seed + int(sum(fitness_scores))
        
        # Ambil panjang kromosom untuk membuat header tabel (G1, G2...)
        chrom_len = len(population[0]) if population else 0

        for i in range(2): # Loop 2 kali untuk mencari 2 Induk
            pengacak = PRNG(temp_seed)
            tournament_indices = [pengacak.randint(0, len(population) - 1) for _ in range(3)]
            tournament_fitness = [fitness_scores[idx] for idx in tournament_indices]
            
            # Cari pemenang
            best_val = max(tournament_fitness)
            best_local_idx = tournament_fitness.index(best_val)
            best_pop_idx = tournament_indices[best_local_idx]
            winner_chrom = population[best_pop_idx]
            
            selected.append(winner_chrom)
            
            # --- FITUR LOG SIMULASI TABEL ---
            if debug:
                # 1. Judul Induk
                debug_html.append(f"<div class='mt-3 mb-1 fw-bold text-primary'>Induk {i+1}</div>")
                
                # 2. Tabel Kandidat (Format Full seperti Populasi Awal)
                debug_html.append("<div class='table-responsive mb-2'>")
                debug_html.append("<table class='table table-bordered table-sm table-striped mb-0' style='font-size: 0.7em; text-align: center; font-family: monospace;'>")
                
                # Header Tabel (Kandidat | G1 | G2 | ... | Fitness)
                debug_html.append("<thead class='table-dark'><tr>")
                debug_html.append("<th>Kandidat</th>")
                for g in range(chrom_len):
                    debug_html.append(f"<th>G{g+1}</th>")
                debug_html.append("<th>Fitness</th>")
                debug_html.append("</tr></thead><tbody>")
                
                # Baris Data untuk 3 Kandidat
                for idx, fit in zip(tournament_indices, tournament_fitness):
                    # Highlight baris jika ini pemenang
                    row_style = "table-info fw-bold" if idx == best_pop_idx else ""
                    
                    debug_html.append(f"<tr class='{row_style}'>")
                    debug_html.append(f"<td class='text-nowrap'>Kromosom {idx+1}</td>")
                    for gene in population[idx]:
                        debug_html.append(f"<td>{gene}</td>")
                    debug_html.append(f"<td class='fw-bold text-danger'>{fit:.0f}</td>")
                    debug_html.append("</tr>")
                
                debug_html.append("</tbody></table></div>")
                
                # 3. Tabel Pemenang (Dipisah agar jelas seperti permintaan)
                debug_html.append(f"<div class='mb-1 fw-bold text-success'>Pemenang Induk {i+1}</div>")
                debug_html.append("<div class='table-responsive mb-4'>")
                debug_html.append("<table class='table table-bordered table-sm' style='font-size: 0.7em; text-align: center; font-family: monospace; border: 2px solid #198754;'>")
                
                # Header Pemenang
                debug_html.append("<thead class='table-success'><tr>")
                debug_html.append("<th>Pemenang</th>")
                for g in range(chrom_len):
                    debug_html.append(f"<th>G{g+1}</th>")
                debug_html.append("<th>Fitness</th>")
                debug_html.append("</tr></thead><tbody>")
                
                # Baris Pemenang
                debug_html.append("<tr>")
                debug_html.append(f"<td class='fw-bold'>Kromosom {best_pop_idx+1}</td>")
                for gene in winner_chrom:
                    debug_html.append(f"<td>{gene}</td>")
                debug_html.append(f"<td class='fw-bold'>{best_val:.0f}</td>")
                debug_html.append("</tr>")
                
                debug_html.append("</tbody></table></div>")

            temp_seed += 1
            
        if debug: return selected, "".join(debug_html)
        return selected

    @staticmethod
    def two_point_crossover(parent1, parent2, crossover_rate, base_seed, chrom_len, debug=False):
        child1, child2 = parent1.copy(), parent2.copy()
        pengacak = PRNG(base_seed + sum(parent1) + sum(parent2))
        
        # Variabel untuk visualisasi
        swap_indices = []
        occurred = False
        
        # Probabilitas Crossover (Hardcoded 80% di kode asli Anda)
        if pengacak.randint(0, 99) < 80: 
            occurred = True
            point1, point2 = pengacak.randint(0, chrom_len - 1), pengacak.randint(0, chrom_len - 1)
            if point1 > point2: point1, point2 = point2, point1
            
            # Hitung jumlah gen yang akan ditukar berdasarkan parameter crossover_rate
            crossover_count = min(crossover_rate, point2 - point1 + 1)
            
            # Lakukan Pertukaran
            for i in range(point1, point1 + crossover_count):
                if i < chrom_len: 
                    child1[i], child2[i] = parent2[i], parent1[i]
                    swap_indices.append(i) # Simpan indeks yang ditukar untuk highlight warna

        # --- LOGIKA VISUALISASI HTML ---
        debug_html = ""
        if debug:
            color_swap = "#fff3cd" # Warna Kuning untuk area tukar
            color_base = "#ffffff"
            
            debug_html += f"<div class='mt-3 mb-1 fw-bold text-primary'>Simulasi Crossover (Induk 1 & 2)</div>"
            if not occurred:
                debug_html += "<div class='alert alert-warning py-1 small'>Crossover tidak terjadi (Probabilitas < 80%)</div>"
            
            debug_html += "<div class='table-responsive mb-4'>"
            debug_html += "<table class='table table-bordered table-sm mb-0' style='font-size: 0.7em; text-align: center; font-family: monospace;'>"
            
            # Header G1, G2...
            debug_html += "<thead class='table-dark'><tr><th>Status</th>"
            for g in range(chrom_len): debug_html += f"<th>G{g+1}</th>"
            debug_html += "</tr></thead><tbody>"

            # Baris Induk 1
            debug_html += "<tr><td class='fw-bold'>Induk 1</td>"
            for i, gene in enumerate(parent1):
                bg = "background-color:#ffe69c; fw-bold" if i in swap_indices else ""
                debug_html += f"<td style='{bg}'>{gene}</td>"
            debug_html += "</tr>"

            # Baris Induk 2
            debug_html += "<tr><td class='fw-bold'>Induk 2</td>"
            for i, gene in enumerate(parent2):
                bg = "background-color:#ffe69c; fw-bold" if i in swap_indices else ""
                debug_html += f"<td style='{bg}'>{gene}</td>"
            debug_html += "</tr>"
            
            # Pemisah Visual
            debug_html += "<tr><td colspan='" + str(chrom_len + 1) + "' class='bg-secondary text-white small py-0'>⬇️ HASIL PERTUKARAN GEN ⬇️</td></tr>"

            # Baris Anak 1
            debug_html += "<tr><td class='fw-bold text-success'>Child 1</td>"
            for i, gene in enumerate(child1):
                # Highlight jika gen ini berasal dari Induk 2 (hasil swap)
                bg = "background-color:#d1e7dd; color:#0f5132; fw-bold" if i in swap_indices else ""
                debug_html += f"<td style='{bg}'>{gene}</td>"
            debug_html += "</tr>"

            # Baris Anak 2
            debug_html += "<tr><td class='fw-bold text-success'>Child 2</td>"
            for i, gene in enumerate(child2):
                # Highlight jika gen ini berasal dari Induk 1 (hasil swap)
                bg = "background-color:#d1e7dd; color:#0f5132; fw-bold" if i in swap_indices else ""
                debug_html += f"<td style='{bg}'>{gene}</td>"
            debug_html += "</tr>"

            debug_html += "</tbody></table></div>"

        if debug: return child1, child2, debug_html
        return child1, child2
    
    @staticmethod
    def hybrid_mutation(chromosome, mutation_rate, base_seed, chrom_len, debug=False):
        mutated = chromosome.copy()
        pengacak = PRNG(base_seed + sum(chromosome))
        
        # 1. Inversion Mutation
        start_pos, end_pos = pengacak.randint(0, chrom_len - 1), pengacak.randint(0, chrom_len - 1)
        if start_pos > end_pos: start_pos, end_pos = end_pos, start_pos
        
        # Lakukan pembalikan
        mutated[start_pos:end_pos + 1] = mutated[start_pos:end_pos + 1][::-1]
        
        # Simpan indeks inversion untuk visualisasi
        inversion_indices = list(range(start_pos, end_pos + 1))
        
        # 2. Random Resetting Mutation
        mutation_indices = []
        for _ in range(mutation_rate):
            idx = pengacak.randint(0, chrom_len - 1)
            mutated[idx] = pengacak.next()
            mutation_indices.append(idx) # Simpan indeks mutasi random

        # --- LOGIKA VISUALISASI HTML ---
        debug_html = ""
        if debug:
            debug_html += "<div class='table-responsive mb-2'>"
            debug_html += "<table class='table table-bordered table-sm mb-0' style='font-size: 0.7em; text-align: center; font-family: monospace;'>"
            
            # Header
            debug_html += "<thead class='table-dark'><tr><th>Status</th>"
            for g in range(chrom_len): debug_html += f"<th>G{g+1}</th>"
            debug_html += "</tr></thead><tbody>"

            # Baris Sebelum Mutasi (Original)
            debug_html += "<tr><td class='text-muted'>Sebelum</td>"
            for gene in chromosome:
                debug_html += f"<td class='text-muted'>{gene}</td>"
            debug_html += "</tr>"

            # Baris Sesudah Mutasi (Result)
            debug_html += "<tr><td class='fw-bold text-danger'>Sesudah</td>"
            for i, gene in enumerate(mutated):
                style = ""
                # Prioritas visual: Random Resetting (Merah) > Inversion (Biru Muda)
                if i in mutation_indices:
                    style = "background-color:#f8d7da; color:#842029; fw-bold border:2px solid red;"
                elif i in inversion_indices:
                    style = "background-color:#cfe2ff; color:#084298;"
                
                debug_html += f"<td style='{style}'>{gene}</td>"
            debug_html += "</tr>"
            
            debug_html += "</tbody></table></div>"
            debug_html += "<div class='small text-muted mb-3'>Legenda: <span class='badge bg-primary bg-opacity-25 text-primary border'>Biru = Inversion</span> <span class='badge bg-danger bg-opacity-25 text-danger border'>Merah = Random Resetting</span></div>"

        if debug: return mutated, debug_html
        return mutated

    @staticmethod
    def run_genetic_algorithm_murni(target_key, filename, params):
        return GeneticUtils._run_optimization_logic(target_key, filename, params, mode='ga')

    @staticmethod
    def _run_optimization_logic(target_key, filename, params, mode):
        logs = []
        target_ascii = GeneticUtils.text_to_ascii(target_key)
        chrom_len = len(target_ascii)
        
        # [FIX 1] Gunakan Waktu sebagai Seed agar acakan selalu berubah setiap kali Run
        import time
        
        # MODIFIKASI: Cek apakah ada fixed_seed untuk keperluan perbandingan jurnal (Apple-to-Apple)
        if 'fixed_seed' in params and params['fixed_seed']:
            base_seed = int(params['fixed_seed'])
        else:
            # TIPS: Ubah ini menjadi angka tetap (misal: 12345) jika ingin membandingkan GA vs Hybrid secara adil
            base_seed = int(time.time())
            
        prng = PRNG(base_seed)
        
        # Inisialisasi Populasi
        population = [[prng.next() for _ in range(chrom_len)] for _ in range(32)]
        best_hist, global_best = [], []
        max_fit = 0 # Menyimpan Fitness Tertinggi Sepanjang Masa (Rekor)

        # --- 1. HEADER LOG ---
        logs.append(f"<div class='alert alert-info py-1 mb-2 small'><strong>[INIT]</strong> Mode: {mode.upper()} | Target: '{target_key}' | <strong>Seed: {base_seed}</strong></div>")
        
        # Variabel sementara untuk menyimpan log baris Gen 1
        first_gen_log = "" 

        # Variabel untuk menghitung rata-rata waktu per generasi
        total_gen_duration = 0
        gen_count_real = 0
        all_gen_bests = [] # Menyimpan semua kunci terbaik tiap generasi untuk dicari top 11 nya

        for gen in range(int(params['max_gen'])):
            gen_start_time = time.perf_counter()

            # Hitung Fitness untuk semua individu di generasi ini
            fitness_scores = [GeneticUtils.fitness_function(c, target_ascii) for c in population]
            
            # Cari Juara di Generasi INI (Current Best)
            current_max = max(fitness_scores)
            current_avg = sum(fitness_scores) / len(fitness_scores)
            
            best_idx = fitness_scores.index(current_max)
            current_best_chrom = population[best_idx]
            current_best_text = GeneticUtils.ascii_to_text(current_best_chrom)
            
            # Cek apakah Juara Generasi ini memecahkan Rekor Dunia (Global Best)
            is_new_record = False
            if current_max > max_fit:
                max_fit = current_max
                global_best = current_best_chrom
                is_new_record = True
            
            # Jika ini Generasi 0, set global best awal
            if gen == 0: global_best = current_best_chrom
            
            best_hist.append(max_fit)
            
            # Simpan kunci terbaik generasi ini beserta fitness-nya (Kecuali Gen 0 / Populasi Awal)
            if gen > 0:
                all_gen_bests.append((current_max, current_best_text))

            # --- 2. LOG DETAIL GEN 0 (TABEL POPULASI AWAL) ---
            if gen == 0: 
                logs.append(GeneticUtils.format_matrix_html(population, "Populasi Awal"))

            # Cek Solusi Sempurna (Menggunakan Current Best)
            if current_best_chrom == target_ascii: 
                logs.append(f"<div class='alert alert-success mt-2'><strong>🎯 SOLUSI DITEMUKAN!</strong> (Gen {gen+1})</div>")
            # [MODIFIKASI] Target berhenti jika kunci mencapai keseimbangan bit yang nyaris sempurna
            binary_str = ''.join(format(b, '08b') for b in current_best_chrom)
            balance_penalty = abs(binary_str.count('1') - binary_str.count('0'))
            
            if balance_penalty <= 2 and gen >= 5: 
                logs.append(f"<div class='alert alert-success mt-2'><strong>🎯 KUNCI DENGAN KEACAKAN (P-VALUE) OPTIMAL DITEMUKAN!</strong> (Gen {gen+1})</div>")
                global_best = current_best_chrom
                max_fit = current_max
                
                # Hitung waktu untuk generasi terakhir ini sebelum break
                gen_end_time = time.perf_counter()
                total_gen_duration += (gen_end_time - gen_start_time)
                gen_count_real += 1
                break

            # --- 3. LOG EVOLUSI (MONITORING BARIS GEN) ---
            safe_text = current_best_text.replace('<', '&lt;').replace('>', '&gt;')
            
            row_style = "border-left: 3px solid #0d6efd; background-color: #f0f8ff;" if is_new_record else "background-color: #fcfcfc;"
            icon = "🏆" if is_new_record else "♻️"
            fit_class = "text-primary fw-bold" if is_new_record else "text-muted"

            log_row = (
                f"<div class='d-flex justify-content-between small border-bottom py-1' style='{row_style}'>"
                f"<span style='width:60px;'>Gen {gen+1}</span>"
                f"<span class='{fit_class}' style='width:80px;' title='Fitness Generasi Ini'>{icon} {current_max:.0f}</span>"
                f"<span class='text-muted' style='width:90px;' title='Rata-rata'>Avg: {current_avg:.0f}</span>"
                f"<span class='font-monospace text-dark text-end' style='width:150px; overflow:hidden; text-overflow:ellipsis;'>{safe_text}</span>"
                f"</div>"
            )
            
            # Jika Gen 1 (index 0), simpan dulu ke variabel, JANGAN di-append ke logs sekarang.
            if gen == 0:
                first_gen_log = log_row
            else:
                # Gen 2 dst langsung ditampilkan
                logs.append(log_row)

            # --- PROSES REPRODUKSI (LOOP UTAMA) ---
            new_pop = [global_best] 
            debug_sel, debug_cross, debug_mut = [], [], []

            selection_sim_html = "" 
            crossover_sim_html = "" 
            mutation_sim_html = "" 

            while len(new_pop) < 32:
                loop_seed = base_seed + gen + len(new_pop)
                
                # 1. SELECTION
                if gen == 0 and len(new_pop) == 1:
                    p, sel_html = GeneticUtils.tournament_selection(population, fitness_scores, loop_seed, debug=True)
                    selection_sim_html = sel_html
                else:
                    p = GeneticUtils.tournament_selection(population, fitness_scores, loop_seed, debug=False)

                # 2. CROSSOVER
                if gen == 0 and len(new_pop) == 1:
                    c1, c2, cross_html = GeneticUtils.two_point_crossover(p[0], p[1], int(params['cross_rate']), loop_seed, chrom_len, debug=True)
                    crossover_sim_html = cross_html
                else:
                    c1, c2 = GeneticUtils.two_point_crossover(p[0], p[1], int(params['cross_rate']), loop_seed, chrom_len, debug=False)

                # 3. MUTATION
                if gen == 0 and len(new_pop) == 1:
                    m1, mut_log1 = GeneticUtils.hybrid_mutation(c1, int(params['mut_rate']), loop_seed, chrom_len, debug=True)
                    m2, mut_log2 = GeneticUtils.hybrid_mutation(c2, int(params['mut_rate']), loop_seed, chrom_len, debug=True)
                    
                    mutation_sim_html = (
                        f"<div class='fw-bold text-primary mb-1'>Simulasi Mutasi Child 1</div>{mut_log1}"
                        f"<div class='fw-bold text-primary mb-1'>Simulasi Mutasi Child 2</div>{mut_log2}"
                    )
                else:
                    m1 = GeneticUtils.hybrid_mutation(c1, int(params['mut_rate']), loop_seed, chrom_len)
                    m2 = GeneticUtils.hybrid_mutation(c2, int(params['mut_rate']), loop_seed, chrom_len)

                # Kumpulkan data debug hanya untuk Gen 0 (tapi tidak semua ditampilkan nanti)
                if gen == 0:
                    debug_sel.extend(p)
                    debug_cross.extend([c1, c2])
                    debug_mut.extend([m1, m2])

                new_pop.extend([m1, m2])
            
            if gen == 0:
                # --- MENYUSUN TAMPILAN LOG KHUSUS GEN 0 ---
                
                # 1. TAHAP SELECTION (Hanya Header & Simulasi, TANPA TABEL FULL)
                logs.append("<div class='mt-4 mb-2'><strong>>> Tahap 1: Selection</strong></div>")
                if selection_sim_html:
                    logs.append(f"<div class='card card-body bg-light border p-2 mb-3'>{selection_sim_html}</div>")
                # [DIHAPUS] logs.append(GeneticUtils.format_matrix_html(debug_sel[:32], "")) 

                # 2. TAHAP CROSSOVER (Hanya Header & Simulasi, TANPA TABEL FULL)
                logs.append("<div class='mt-4 mb-2'><strong>>> Tahap 2: Crossover</strong></div>")
                if crossover_sim_html:
                    logs.append(f"<div class='card card-body bg-light border p-2 mb-3'>{crossover_sim_html}</div>")
                # [DIHAPUS] logs.append(GeneticUtils.format_matrix_html(debug_cross[:32], ""))
                
                # 3. TAHAP MUTATION (Header, Simulasi, DAN TABEL FULL)
                logs.append("<div class='mt-4 mb-2'><strong>>> Tahap 3: Mutation</strong></div>")
                if mutation_sim_html:
                    logs.append(f"<div class='card card-body bg-light border p-2 mb-3'>{mutation_sim_html}</div>")
                
                # [DIPERTAHANKAN] Menampilkan Tabel Full (32 Kromosom) Hasil Mutasi
                logs.append(GeneticUtils.format_matrix_html(debug_mut[:32], "Hasil Populasi Baru (Setelah Mutasi)")) 
                
                logs.append("<div class='mt-3 mb-2 fw-bold text-primary border-bottom'>=== MULAI EVOLUSI ===</div>")

                # Header Kolom Evolusi
                logs.append(
                    "<div class='d-flex justify-content-between small border-bottom py-1 mb-1 fw-bold bg-dark text-white'>"
                    "<span style='width:60px;'>Gen</span>"
                    "<span style='width:80px;'>Max Fit</span>"
                    "<span style='width:90px;'>Avg Fit</span>"
                    "<span class='text-end' style='width:150px;'>Kunci Terbaik</span>"
                    "</div>"
                )

                logs.append(first_gen_log)

            population = new_pop[:32]
            
            # Hitung waktu selesai generasi ini
            gen_end_time = time.perf_counter()
            total_gen_duration += (gen_end_time - gen_start_time)
            gen_count_real += 1

        # Hitung dan tampilkan rata-rata waktu per generasi
        avg_gen_time = total_gen_duration / gen_count_real if gen_count_real > 0 else 0
        logs.append(f"<div class='alert alert-secondary py-1 small mt-2'>⏱️ Rata-rata waktu per generasi: <strong>{avg_gen_time:.6f} detik</strong></div>")

        final_key = GeneticUtils.ascii_to_text(global_best)
        best_fitness = max_fit

        # --- 5. LOG HASIL AKHIR ---
        # Menggunakan standard AES encryption agar file dapat didekripsi dengan kunci final.
        enc_result = GeneticUtils.process_file_binary(os.path.join(app.config['UPLOAD_FOLDER'], filename), final_key)
        
        # [ADD] Tampilkan Simulasi AES jika ada
        if 'simulation_html' in enc_result:
            logs.append(enc_result['simulation_html'])

        # Sanitasi untuk tampilan HTML
        safe_key = final_key.replace('<', '&lt;').replace('>', '&gt;')
        # Sanitasi khusus untuk value input (agar tanda kutip tidak merusak HTML)
        safe_key_attr = final_key.replace('"', '&quot;')
        
        # Buat ID unik agar tombol copy tidak bingung jika ada banyak log
        unique_id = f"finalKey_{int(time.time())}_{random.randint(100, 999)}"
        
        logs.append(f"""
        <div class='alert alert-light border mt-3'>
            <h6 class='alert-heading fw-bold'><i class='fas fa-flag-checkered'></i> HASIL AKHIR</h6>
            <hr>
            <div class='row align-items-center mb-2'>
                <div class='col-4'>Kunci Final:</div>
                <div class='col-8'>
                    <div class="input-group input-group-sm">
                        <input type="text" id="{unique_id}" class="form-control font-monospace fw-bold" 
                               value="{safe_key_attr}" readonly 
                               style="background-color: #fff; border: 1px solid #ced4da; color: #0d6efd;">
                        <button class="btn btn-outline-primary" type="button" 
                                onclick="copyFromInput('{unique_id}')" title="Salin Kunci">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
            </div>
            <div class='row'>
                <div class='col-4'>Fitness Max:</div>
                <div class='col-8'>{best_fitness:.2f}</div>
            </div>
        </div>
        """)
        
        return {
            'logs': logs, 'final_key': final_key, 'best_fitness': best_fitness,
            'fitness_history': best_hist,
            'match_percent': (sum(1 for i in range(chrom_len) if GeneticUtils.text_to_ascii(final_key)[i] == target_ascii[i])/chrom_len)*100,
            'enc_filename': enc_result.get('enc_filename'), 'metrics': enc_result.get('metrics')
        }

# ==========================================
# 4. RUTE UTAMA & EXCEL
# ==========================================
@app.route('/')
def index(): return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files: return jsonify({'error': 'No file'})
    file = request.files['file']
    if file.filename == '': return jsonify({'error': 'No file'})
    filename = secure_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)
    return jsonify(GeneticUtils.generate_key_from_metadata(path, int(request.form.get('key_length', 32))))

@app.route('/run_optimization', methods=['POST'])
def run_optimization():
    data = request.json
    mode = data.get('mode', 'ga')
    
    if mode == 'aes_only':
        target_key = data.get('target_key')
        filename = data.get('filename')
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        enc_result = AESUtils.encrypt_file_aes(file_path, target_key)
        
        logs = [
            f"<div class='alert alert-info py-1 mb-2 small'><strong>[INIT]</strong> Mode: TANPA OPTIMASI (AES SAJA) | Kunci: '{target_key}'</div>",
            "<div class='alert alert-success mt-2'><strong>🎯 ENKRIPSI SELESAI!</strong></div>"
        ]
        
        if 'simulation_html' in enc_result:
            logs.append(enc_result['simulation_html'])
            
        safe_key = target_key.replace('<', '&lt;').replace('>', '&gt;')
        safe_key_attr = target_key.replace('"', '&quot;')
        unique_id = f"finalKey_{int(time.time())}_{random.randint(100, 999)}"
        
        logs.append(f"""
        <div class='alert alert-light border mt-3'>
            <h6 class='alert-heading fw-bold'><i class='fas fa-flag-checkered'></i> HASIL AKHIR</h6>
            <hr>
            <div class='row align-items-center mb-2'>
                <div class='col-4'>Kunci Final:</div>
                <div class='col-8'>
                    <div class="input-group input-group-sm">
                        <input type="text" id="{unique_id}" class="form-control font-monospace fw-bold" 
                               value="{safe_key_attr}" readonly 
                               style="background-color: #fff; border: 1px solid #ced4da; color: #0d6efd;">
                        <button class="btn btn-outline-primary" type="button" 
                                onclick="copyFromInput('{unique_id}')" title="Salin Kunci">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                </div>
            </div>
            <div class='row'>
                <div class='col-4'>Akurasi Kunci:</div>
                <div class='col-8'>100.00% (Metadata Original)</div>
            </div>
        </div>
        """)
        
        result = {
            'logs': logs,
            'final_key': target_key,
            'best_fitness': 0,
            'fitness_history': [],
            'match_percent': 100.0,
            'enc_filename': enc_result.get('enc_filename'),
            'metrics': enc_result.get('metrics')
        }
        method_name = "AES"
    else:
        result = GeneticUtils.run_genetic_algorithm_murni(data.get('target_key'), data.get('filename'), data)
        method_name = "GA+AES"

    fitness_val = result.get('best_fitness')

    save_to_history({
        'filename': data.get('filename'), 'method': method_name,
        'key_length': len(data.get('target_key')), 'final_key': result.get('final_key'),
        'fitness': fitness_val, 'time_taken': result['metrics'].get('time_taken_sec'),
        'entropy': result['metrics'].get('entropy'), 'p_value': result['metrics'].get('key_stats', {}).get('p_value', 0),
        'enc_filename': result.get('enc_filename')
    })
    return jsonify(result)

@app.route('/get_history', methods=['GET'])
def get_history():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        # Filter agar data internal tidak muncul di tabel UI
        rows = conn.execute("SELECT * FROM history WHERE method NOT IN ('GA Murni [Internal]', 'ga+aes [Internal]') ORDER BY id DESC").fetchall()
        conn.close()
        
        history_data = []
        for row in rows:
            r_dict = dict(row)
            # Ubah null/NaN/"-" menjadi angka 0 agar fungsi matematika di frontend tidak menghasilkan NaN
            fit_val = r_dict.get('fitness')
            if fit_val is None or pd.isna(fit_val) or str(fit_val).strip().lower() in ['nan', 'none', '', '-']:
                r_dict['fitness'] = 0
            history_data.append(r_dict)
            
        return jsonify(history_data)
    except Exception as e: return jsonify({'error': str(e)})

@app.route('/delete_history_item/<int:item_id>', methods=['POST'])
def delete_history_item(item_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute("DELETE FROM history WHERE id = ?", (item_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)})

@app.route('/clear_history', methods=['POST'])
def clear_history():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute("DELETE FROM history")
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)})

# --- FUNGSI PEMBERSIH UNTUK EXCEL (HANDLING DATA LAMA YANG RUSAK) ---
def clean_illegal_chars(val):
    """Menghapus karakter kontrol (ASCII 0-31) kecuali Tab/LF/CR agar Excel tidak error."""
    if isinstance(val, str):
        # Regex menghapus ASCII 0-31 (Hex 00-1F) dan 127 (DEL)
        return re.sub(r'[\x00-\x1F\x7F]', '', val)
    return val

@app.route('/download_excel')
def download_excel():
    """Mengunduh history ke Excel dengan sanitasi data agar tidak error."""
    try:
        conn = sqlite3.connect(DB_NAME)
        df = pd.read_sql_query("SELECT * FROM history", conn)
        conn.close()

        if df.empty: return "Tidak ada data.", 404

        # TERAPKAN SANITASI KE SELURUH DATA AGAR TIDAK CRASH
        # Perbaikan kompatibilitas: Pandas baru menggunakan map, lama menggunakan applymap
        if hasattr(df, 'map'):
            df = df.map(clean_illegal_chars)
        else:
            df = df.applymap(clean_illegal_chars)

        # Bersihkan string "NaN" sisa dari database lama agar terganti sempurna oleh fillna("-")
        df.replace(["NaN", "nan", "NAN", "None", "none", ""], None, inplace=True)

        # Ubah key_length ke numeric untuk sorting
        df['key_length'] = pd.to_numeric(df['key_length'], errors='coerce')

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Ambil semua data GA (termasuk Internal) untuk referensi perbandingan di sheet Hybrid
            df_ga_all = df[df['method'].str.contains(r"ga\+aes|GA Murni", case=False, na=False)].copy()

            # 1. Sheet GA + AES (Hanya GA Manual, exclude Internal)
            # Filter keluar yang method-nya Internal agar tidak muncul di sheet Excel
            df_ga_clean = df_ga_all[~df_ga_all['method'].isin(["GA Murni [Internal]", "ga+aes [Internal]"])]

            if not df_ga_clean.empty:
                cols_std = ['filename', 'method', 'key_length', 'fitness', 'time_taken', 'entropy', 'p_value', 'timestamp']
                cols_exist = [c for c in cols_std if c in df_ga_clean.columns]
                df_ga_std = df_ga_clean[cols_exist]
                df_ga_std.sort_values(by='key_length', ascending=True).fillna("-").to_excel(writer, sheet_name='GA + AES', index=False)
            
            # 2. Sheet Hybrid GA + SA (Format Perbandingan Side-by-Side)
            df_hybrid_raw = df[df['method'].str.contains("Hybrid", case=False, na=False)].copy()
            
            if not df_hybrid_raw.empty:
                # Siapkan Data GA sebagai Referensi (Gunakan df_ga_all agar mencakup GA Internal)
                if not df_ga_all.empty:
                    # Sort descending by timestamp agar yang diambil adalah run terakhir (terbaru)
                    df_ga_ref = df_ga_all.sort_values('timestamp', ascending=False).drop_duplicates(subset=['filename', 'key_length'])
                    df_ga_ref = df_ga_ref[['filename', 'key_length', 'fitness', 'time_taken', 'entropy', 'p_value']]
                    df_ga_ref.columns = ['filename', 'key_length', 'fitness ga', 'time_taken ga', 'entropy ga', 'p_value ga']
                else:
                    df_ga_ref = pd.DataFrame(columns=['filename', 'key_length', 'fitness ga', 'time_taken ga', 'entropy ga', 'p_value ga'])

                # Siapkan Data Hybrid
                df_hybrid_comp = df_hybrid_raw.copy()
                rename_map = {'fitness': 'fitness ga+sa', 'time_taken': 'time_taken ga+sa', 'entropy': 'entropy ga+sa', 'p_value': 'p_value ga+sa'}
                df_hybrid_comp.rename(columns=rename_map, inplace=True)
                
                # Merge (Left Join) Hybrid dengan GA Reference
                df_merged = pd.merge(df_hybrid_comp, df_ga_ref, on=['filename', 'key_length'], how='left')
                
                # Susun Urutan Kolom Sesuai Permintaan
                desired_order = ['filename', 'method', 'key_length', 'fitness ga', 'fitness ga+sa', 'time_taken ga', 'time_taken ga+sa', 'entropy ga', 'entropy ga+sa', 'p_value ga', 'p_value ga+sa', 'timestamp']
                final_cols = [c for c in desired_order if c in df_merged.columns]
                df_final = df_merged[final_cols]
                
                df_final.sort_values(by='key_length', ascending=True).fillna("-").to_excel(writer, sheet_name='Hybrid GA + SA', index=False)
            
            # 3. Sheet Khusus AES
            df_aes = df[df['method'].str.lower().isin(["aes", "aes saja"])].copy()
            
            if not df_aes.empty:
                cols_std = ['filename', 'method', 'key_length', 'fitness', 'time_taken', 'entropy', 'p_value', 'timestamp']
                cols_exist = [c for c in cols_std if c in df_aes.columns]
                df_aes_std = df_aes[cols_exist]
                df_aes_std.sort_values(by='key_length', ascending=True).fillna("-").to_excel(writer, sheet_name='AES', index=False)
            
            # Fallback jika kosong
            if df_ga_clean.empty and df_hybrid_raw.empty and df_aes.empty:
                df.sort_values(by='key_length', ascending=True).fillna("-").to_excel(writer, sheet_name='Semua Data', index=False)

        output.seek(0)
        return send_file(output, download_name='riwayat_enkripsi.xlsx', as_attachment=True, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
    except Exception as e: return f"Error Excel: {str(e)}", 500

@app.route('/decrypt_manual', methods=['POST'])
def decrypt_manual():
    file = request.files['file_enc']
    filename = secure_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)
    return jsonify(GeneticUtils.manual_decryption(path, request.form.get('key_input')))

@app.route('/download_result/<path:filename>')
def download_result(filename):
    return send_from_directory(app.config['RESULTS_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    print("🚀 SISTEM BERJALAN: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)