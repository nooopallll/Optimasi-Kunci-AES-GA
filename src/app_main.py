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
import json
import hashlib
import tempfile
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from datetime import datetime

# ==========================================
# 1. BAGIAN AUTO-INSTALLER
# ==========================================
def install_dependencies():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    required_packages = ['flask', 'PyPDF2', 'pandas', 'openpyxl', 'pycryptodome', 'Pillow']
    
    missing = []
    for pkg in required_packages:
        try:
            if pkg == 'PyPDF2': import PyPDF2
            elif pkg == 'openpyxl': import openpyxl
            elif pkg == 'pycryptodome': from Crypto.Cipher import AES
            elif pkg == 'Pillow': from PIL import Image
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
from PIL import Image
from PIL.PngImagePlugin import PngInfo
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

POPULATION_SIZE = 50
CHROMOSOME_MODE = 'hex'  # 'hex' atau 'binary' — ganti untuk beralih mode
CHROM_LEN = 32 if CHROMOSOME_MODE == 'hex' else 128
W_ENT = 1/3
W_AVA = 1/3
W_BIT = 1/3
MAX_FITNESS = 100000

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
    # Penambahan Kolom Baru secara Aman (Jika Belum Ada)
    for col, col_type in [('avalanche', 'REAL'), ('corr_plain', 'REAL'), ('corr_cipher', 'REAL'), 
                          ('npcr', 'REAL'), ('uaci', 'REAL'), ('time_decryption', 'REAL'),
                          ('pixel_histogram', 'TEXT'), ('fitness_distribution', 'TEXT'),
                          ('fitness_history', 'TEXT'), ('avg_history', 'TEXT'),
                          ('logs', 'TEXT'), ('simulation_html', 'TEXT'), ('key_stats', 'TEXT')]:
        try: c.execute(f"ALTER TABLE history ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError: pass 
    c.execute('''
        CREATE TABLE IF NOT EXISTS ga_steps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            history_id INTEGER NOT NULL,
            ga_steps TEXT,
            FOREIGN KEY (history_id) REFERENCES history(id)
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
            (filename, method, key_length, final_key, fitness, time_taken, entropy, p_value, 
            enc_filename, avalanche, corr_plain, corr_cipher, npcr, uaci, time_decryption,
            pixel_histogram, fitness_distribution, fitness_history, avg_history,
            logs, simulation_html, key_stats)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['filename'], data['method'], data['key_length'], data['final_key'],
            data['fitness'], data['time_taken'], data['entropy'], data['p_value'],
            data['enc_filename'], data.get('avalanche', 0.0), data.get('corr_plain'), 
            data.get('corr_cipher'), data.get('npcr', 0.0), data.get('uaci', 0.0), 
            data.get('time_decryption', 0.0),
            json.dumps(data.get('pixel_histogram')) if data.get('pixel_histogram') else None,
            json.dumps(data.get('fitness_distribution')) if data.get('fitness_distribution') else None,
            json.dumps(data.get('fitness_history')) if data.get('fitness_history') else None,
            json.dumps(data.get('avg_history')) if data.get('avg_history') else None,
            json.dumps(data.get('logs')) if data.get('logs') else None,
            data.get('simulation_html') or None,
            json.dumps(data.get('key_stats')) if data.get('key_stats') else None
        ))
        conn.commit()
        history_id = c.lastrowid
        conn.close()
        return history_id
    except Exception as e:
        print(f"Error saving to DB: {e}")
        return None

def save_ga_steps(history_id, ga_steps_data):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('INSERT INTO ga_steps (history_id, ga_steps) VALUES (?, ?)',
                  (history_id, json.dumps(ga_steps_data)))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving GA steps: {e}")

init_db()

# ==========================================
# 3. UTILITIES
# ==========================================
class PRNG:
    def __init__(self, seed):
        self.seed = int(seed)
        self.random = random.Random(self.seed)
    
    def next(self):
        return self.random.randint(32, 126)

    def randint(self, a, b):
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
    def calculate_avalanche_effect(ciphertext1_bytes, ciphertext2_bytes):
        min_len = min(len(ciphertext1_bytes), len(ciphertext2_bytes))
        if not min_len: return 0.0
            
        diff_bits = (int.from_bytes(ciphertext1_bytes[:min_len], 'big')
                     ^ int.from_bytes(ciphertext2_bytes[:min_len], 'big')).bit_count()

        total_bits = min_len * 8
        if total_bits > 0:
            return (diff_bits / total_bits) * 100
        return 0.0

    @staticmethod
    def calculate_npcr_uaci(cipher1_bytes, cipher2_bytes):
        min_len = min(len(cipher1_bytes), len(cipher2_bytes))
        if min_len == 0: return 0.0, 0.0
        
        diff_count = 0
        sum_diff = 0
        
        for i in range(min_len):
            if cipher1_bytes[i] != cipher2_bytes[i]:
                diff_count += 1
            sum_diff += abs(cipher1_bytes[i] - cipher2_bytes[i])
            
        npcr = (diff_count / min_len) * 100
        uaci = (sum_diff / (255 * min_len)) * 100
        
        return npcr, uaci

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

    @staticmethod
    def calculate_pixel_correlation(img, direction='horizontal', samples=3000):
        gray_img = img.convert('L') 
        width, height = gray_img.size
        pixels = gray_img.load()

        x_vals = []
        y_vals = []

        if width < 2 or height < 2: return 0.0

        for _ in range(samples):
            x = random.randint(0, width - 2)
            y = random.randint(0, height - 2)

            val1 = pixels[x, y]
            if direction == 'horizontal':
                val2 = pixels[x + 1, y]
            elif direction == 'vertical':
                val2 = pixels[x, y + 1]
            elif direction == 'diagonal':
                val2 = pixels[x + 1, y + 1]
            else:
                val2 = pixels[x + 1, y]

            x_vals.append(val1)
            y_vals.append(val2)

        n = len(x_vals)
        if n == 0: return 0.0

        mean_x = sum(x_vals) / n
        mean_y = sum(y_vals) / n

        var_x = sum((xi - mean_x) ** 2 for xi in x_vals) / n
        var_y = sum((yi - mean_y) ** 2 for yi in y_vals) / n

        if var_x == 0 or var_y == 0: return 0.0

        cov_xy = sum((x_vals[i] - mean_x) * (y_vals[i] - mean_y) for i in range(n)) / n
        correlation = cov_xy / math.sqrt(var_x * var_y)

        return correlation

    @staticmethod
    def calculate_byte_correlation(plain_bytes, cipher_bytes):
        min_len = min(len(plain_bytes), len(cipher_bytes))
        if min_len == 0: return 0.0
        sample_n = min(3000, min_len)
        if min_len > sample_n:
            indices = sorted(random.sample(range(min_len), sample_n))
        else:
            indices = range(min_len)
        x = [plain_bytes[i] for i in indices]
        y = [cipher_bytes[i] for i in indices]
        n = len(x)
        if n == 0: return 0.0
        mean_x = sum(x) / n
        mean_y = sum(y) / n
        var_x = sum((xi - mean_x) ** 2 for xi in x) / n
        var_y = sum((yi - mean_y) ** 2 for yi in y) / n
        if var_x == 0 or var_y == 0: return 0.0
        cov_xy = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n)) / n
        return cov_xy / math.sqrt(var_x * var_y)

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
    key_str = key_str.replace(' ', '')
    try: key_bytes = key_str.encode('latin-1')
    except: key_bytes = key_str.encode('utf-8')
    if len(key_bytes) == 32 and len(key_str) == 32 and all(c in '0123456789abcdefABCDEF' for c in key_str):
        try: return bytes.fromhex(key_str)
        except ValueError: pass
    if len(key_bytes) <= 16: return key_bytes.ljust(16, b'\0')
    if len(key_bytes) <= 24: return key_bytes.ljust(24, b'\0')
    return key_bytes.ljust(32, b'\0')[:32]

def _expand_key(key_bytes):
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
    
    round_keys = [b''.join(w[i*4:(i+1)*4]) for i in range(rounds + 1)]
    return round_keys, rounds, aes_ver

class AESUtils:
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
    def format_hexdump(data, max_bytes=256):
        chunk = bytes(data[:max_bytes])
        lines = []
        for offset in range(0, len(chunk), 16):
            row = chunk[offset:offset + 16]
            hex_part = ' '.join(f'{b:02X}' for b in row)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)
            lines.append(f'{offset:08X}  {hex_part:<47}  |{ascii_part}|')
        return '\n'.join(lines)

    @staticmethod
    def build_cipher_preview(data, is_image, enc_filename, max_bytes=256):
        total = len(data)
        shown = 0 if is_image else min(total, max_bytes)
        return {
            'is_image': bool(is_image),
            'enc_filename': enc_filename,
            'total_bytes': total,
            'total_blocks': total // AES.block_size,
            'shown_bytes': shown,
            'truncated': shown < total,
            'hexdump': AESUtils.format_hexdump(data, shown) if shown else ''
        }

    @staticmethod
    def encrypt_file_aes(file_path, key_str):
        try:
            is_image = file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.webp', '.tiff'))
            
            if is_image:
                img = Image.open(file_path).convert('RGB')
                try: img = img.resize((256, 256), Image.Resampling.LANCZOS)
                except AttributeError: img = img.resize((256, 256), Image.LANCZOS)
                orig_w, orig_h = img.size
                plaintext_bytes = bytearray(img.tobytes())
            else:
                with open(file_path, 'rb') as f: plaintext_bytes = f.read()
            
            key_bytes = _prepare_key(key_str)
            
            # 1. Hitung Waktu Enkripsi
            start_time = time.perf_counter()
            cipher = AES.new(key_bytes, AES.MODE_CBC)
            padded_data = pad(plaintext_bytes, AES.block_size)
            ciphertext_bytes = cipher.encrypt(padded_data)
            iv = cipher.iv
            final_data = iv + ciphertext_bytes
            encryption_time = time.perf_counter() - start_time
            
            # 2. Hitung Waktu Dekripsi (Simulasi In-Memory)
            dec_start_time = time.perf_counter()
            cipher_dec = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
            unpad(cipher_dec.decrypt(ciphertext_bytes), AES.block_size)
            decryption_time = time.perf_counter() - dec_start_time
            
            # Analisis Diferensial (Avalanche, NPCR, UACI)
            avalanche_percentage = 0.0
            npcr_val = 0.0
            uaci_val = 0.0
            correlation_data = None
            
            if plaintext_bytes:
                modified_plaintext = bytearray(plaintext_bytes)
                bit_to_flip_index = 0 if is_image else len(modified_plaintext) // 2
                modified_plaintext[bit_to_flip_index] ^= 0x01 

                cipher2 = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
                padded_modified = pad(bytes(modified_plaintext), AES.block_size)
                ciphertext2 = cipher2.encrypt(padded_modified)

                avalanche_percentage = EvaluationUtils.calculate_avalanche_effect(ciphertext_bytes, ciphertext2)
                data_only_1 = ciphertext_bytes[16:]
                data_only_2 = ciphertext2[16:]
                
                if is_image:
                    npcr_val, uaci_val = EvaluationUtils.calculate_npcr_uaci(ciphertext_bytes, ciphertext2)
            
            filename = os.path.basename(file_path)

            if is_image:
                total_bytes = len(final_data)
                new_h = math.ceil(total_bytes / (orig_w * 3))
                final_bytes = bytes(final_data).ljust(orig_w * new_h * 3, b'\0')
                enc_img = Image.frombytes('RGB', (orig_w, new_h), final_bytes)
                
                meta = PngInfo()
                meta.add_text("orig_w", str(orig_w))
                meta.add_text("orig_h", str(orig_h))
                meta.add_text("cipher_len", str(total_bytes))
                
                enc_filename = os.path.splitext(filename)[0] + "_enc.png"
                enc_path = os.path.join(app.config['RESULTS_FOLDER'], enc_filename)
                enc_img.save(enc_path, "PNG", pnginfo=meta)
                ascii_preview = "Data gambar dienkripsi ke berkas PNG (Mode CBC)."
                
                corr_h_plain = EvaluationUtils.calculate_pixel_correlation(img, 'horizontal', 3000)
                corr_h_cipher = EvaluationUtils.calculate_pixel_correlation(enc_img, 'horizontal', 3000)
                correlation_data = {'plain_h': f"{corr_h_plain:.4f}", 'cipher_h': f"{corr_h_cipher:.4f}"}

                plain_hist = [0] * 256
                for b in plaintext_bytes:
                    plain_hist[b] += 1
                cipher_hist = [0] * 256
                for b in ciphertext_bytes:
                    cipher_hist[b] += 1
                pixel_histogram_data = {'plain': plain_hist, 'cipher': cipher_hist}
            else:
                enc_filename = f"{filename}.enc"
                enc_path = os.path.join(app.config['RESULTS_FOLDER'], enc_filename)
                with open(enc_path, 'wb') as f: f.write(final_data)
                ascii_preview = final_data[:500].decode('latin-1', errors='replace')

                corr_val = EvaluationUtils.calculate_byte_correlation(plaintext_bytes, ciphertext_bytes)
                correlation_data = {'plain_h': f"{corr_val:.4f}", 'cipher_h': f"{corr_val:.4f}"}

                plain_hist = [0] * 256
                for b in plaintext_bytes:
                    plain_hist[b] += 1
                cipher_hist = [0] * 256
                for b in ciphertext_bytes:
                    cipher_hist[b] += 1
                pixel_histogram_data = {'plain': plain_hist, 'cipher': cipher_hist}
            
            entropy_val = EvaluationUtils.calculate_entropy(final_data)
            key_stats = EvaluationUtils.monobit_frequency_test(key_str)
            
            key_schedule_html = AESUtils.generate_round_keys_html(key_bytes)
            first_block = padded_data[:16]
            sim_html = AESUtils.simulate_aes_block_html(first_block, key_bytes, len(padded_data))

            return {
                'success': True, 'enc_filename': enc_filename, 'ascii_preview': ascii_preview,
                'preview': AESUtils.build_cipher_preview(final_data, is_image, enc_filename),
                'metrics': {
                    'time_taken_sec': f"{encryption_time:.6f}", 
                    'time_decryption_sec': f"{decryption_time:.6f}",
                    'entropy': f"{entropy_val:.5f}", 
                    'key_stats': key_stats,
                    'avalanche': f"{avalanche_percentage:.2f}%", 
                    'correlation': correlation_data,
                    'npcr': f"{npcr_val:.4f}",
                    'uaci': f"{uaci_val:.4f}",
                    'pixel_histogram': pixel_histogram_data
                },
                'simulation_html': key_schedule_html + sim_html
            }
        except Exception as e: return {'success': False, 'error': str(e)}

    @staticmethod
    def decrypt_file_aes(file_path, key_str):
        try:
            key_bytes = _prepare_key(key_str)
            start_time = time.perf_counter()

            is_enc_image = False
            img_meta = {}
            if file_path.lower().endswith('.png'):
                try:
                    with Image.open(file_path) as img_src:
                        img_src.load()
                        if 'cipher_len' in img_src.text:
                            is_enc_image = True
                            img_meta['w'] = int(img_src.text['orig_w'])
                            img_meta['h'] = int(img_src.text['orig_h'])
                            img_meta['len'] = int(img_src.text['cipher_len'])
                except: pass
            
            if is_enc_image:
                img = Image.open(file_path).convert('RGB')
                raw_bytes = img.tobytes()[:img_meta['len']]
                
                iv = raw_bytes[:16]
                ciphertext = raw_bytes[16:]
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
                plain_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
                
                dec_img = Image.frombytes('RGB', (img_meta['w'], img_meta['h']), plain_bytes)
                original_name = os.path.basename(file_path).replace('_enc.png', '_dec.png')
                if original_name == os.path.basename(file_path): original_name = "dec_" + original_name
                dec_filename = "HASIL_DEKRIPSI_" + original_name
                dec_img.save(os.path.join(app.config['RESULTS_FOLDER'], dec_filename))
                decrypt_time = time.perf_counter() - start_time
            else:
                with open(file_path, 'rb') as f: file_content = f.read()
                iv = file_content[:16]
                ciphertext = file_content[16:]
                
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv)
                plain_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
                
                decrypt_time = time.perf_counter() - start_time
                original_name = os.path.basename(file_path).replace('.enc', '')
                if not original_name.lower().endswith(('.pdf', '.txt', '.png', '.jpg', '.jpeg')): original_name += '.pdf'
                
                if '_enc' in file_path.lower() and not file_path.lower().endswith('.png'):
                    original_name = original_name.replace('_enc', '')
                
                dec_filename = f"HASIL_DEKRIPSI_{original_name}"
                with open(os.path.join(app.config['RESULTS_FOLDER'], dec_filename), 'wb') as f: f.write(plain_bytes)
                
            return {'success': True, 'dec_filename': dec_filename, 'time_taken': f"{decrypt_time:.6f}"}
        except Exception as e: return {'success': False, 'error': str(e)}

    @staticmethod
    def generate_round_keys_html(key_bytes):
        round_keys, rounds, aes_ver = _expand_key(key_bytes)
        if not round_keys: return ""
        
        html = [f"<div class='mt-3 mb-2'><strong>>> AES Key Schedule ({aes_ver} - {rounds} Rounds)</strong></div>"]
        html.append("<div class='table-responsive' style='max-height: 300px; overflow-y: auto;'>")
        html.append("<table class='table table-sm table-bordered table-striped mb-0' style='font-size: 0.8em; font-family: monospace; text-align: center;'>")
        html.append("<thead class='table-dark'><tr><th>Round</th><th>Round Key (Hex)</th><th>Bits</th></tr></thead><tbody>")
        for r, round_key in enumerate(round_keys):
            html.append(f"<tr><td>{r}</td><td>{round_key.hex().upper()}</td><td>{len(round_key)*8}</td></tr>")
        html.append("</tbody></table></div>")
        return "".join(html)

    @staticmethod
    def simulate_aes_block_html(plaintext_block, key_bytes, total_len=0):
        round_keys, rounds, _ = _expand_key(key_bytes)
        if not round_keys: return ""

        state = list(plaintext_block)

        def format_grid(st, title, color="bg-light"):
            h = [f"<div class='col-md-3 mb-2'><div class='card'><div class='card-header py-1 small fw-bold {color}'>{title}</div><div class='card-body p-1'><table class='table table-bordered table-sm mb-0' style='font-size:0.65em; text-align:center'>"]
            for r in range(4):
                h.append("<tr>")
                for c in range(4):
                    h.append(f"<td>{st[r*4 + c]:02X}</td>")
                h.append("</tr>")
            h.append("</table></div></div></div>")
            return "".join(h)

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
    def simulate_aes_block_data(plaintext_block, key_bytes):
        round_keys, rounds, aes_ver = _expand_key(key_bytes)
        if not round_keys: return aes_ver, rounds, [], []

        state = list(plaintext_block)
        steps = [{'tahap': 'Input (Plaintext)', 'state': list(state)}]

        state = AESUtils.add_round_key(state, round_keys[0])
        steps.append({'tahap': 'Round 0: AddRoundKey', 'state': list(state)})

        for r in range(1, rounds):
            state = AESUtils.sub_bytes(state)
            steps.append({'tahap': f'Round {r}: SubBytes', 'state': list(state)})
            state = AESUtils.shift_rows(state)
            steps.append({'tahap': f'Round {r}: ShiftRows', 'state': list(state)})
            state = AESUtils.mix_columns(state)
            steps.append({'tahap': f'Round {r}: MixColumns', 'state': list(state)})
            state = AESUtils.add_round_key(state, round_keys[r])
            steps.append({'tahap': f'Round {r}: AddRoundKey', 'state': list(state)})

        state = AESUtils.sub_bytes(state)
        steps.append({'tahap': f'Round {rounds}: SubBytes', 'state': list(state)})
        state = AESUtils.shift_rows(state)
        steps.append({'tahap': f'Round {rounds}: ShiftRows', 'state': list(state)})
        state = AESUtils.add_round_key(state, round_keys[rounds])
        steps.append({'tahap': f'Round {rounds}: AddRoundKey', 'state': list(state)})

        steps.append({'tahap': 'Output (Ciphertext)', 'state': list(state)})

        rk_data = [{'round': r, 'key_hex': rk.hex().upper()} for r, rk in enumerate(round_keys)]
        return aes_ver, rounds, rk_data, steps

PDF_METADATA_PATTERNS = [
    (r"Name:\s*(.*?)\s*DOB:", 'Name'), (r"DOB:\s*(.*?)\s*Age:", 'DOB'),
    (r"Age:\s*(.*?)\s*Sex:", 'Age'), (r"Sex:\s*(.*?)\s*SSN:", 'Sex'),
    (r"SSN:\s*(.*?)\s*Hospital ID:", 'SSN'),
    (r"Hospital ID:\s*(.*?)\s*Patient Lifestyle", 'Hospital ID'),
    (r"Recorded Date:\s*(\d{2}/\d{2}/\d{4})", 'Recorded Date'),
    (r"Doctor Name:\s*(.*?)\s*Doctor Unique ID:", 'Doctor Name'),
    (r"Doctor Unique ID:\s*([A-Z0-9]+)", 'Doctor Unique ID')
]

class GeneticUtils:
    @staticmethod
    def _display_cols(chrom_len):
        return chrom_len // 2 if CHROMOSOME_MODE == 'hex' else chrom_len

    @staticmethod
    def _render_row_cells(chrom, swap_indices=None, mutation_indices=None, inversion_indices=None):
        is_hex = CHROMOSOME_MODE == 'hex'
        if not is_hex:
            for i, gene in enumerate(chrom):
                style = ""
                if swap_indices is not None and i in swap_indices:
                    style = "background-color:#ffe69c; fw-bold"
                if mutation_indices is not None and i in mutation_indices:
                    style = "background-color:#f8d7da; color:#842029; fw-bold border:2px solid red;"
                elif inversion_indices is not None and i in inversion_indices:
                    style = "background-color:#cfe2ff; color:#084298;"
                yield f"<td style='{style}'>{gene}</td>"
        else:
            chrom_str = chrom if isinstance(chrom, str) else ''.join(chrom)
            for i in range(0, len(chrom_str), 2):
                cell_val = chrom_str[i:i+2].upper()
                char_pair = {i, i + 1}
                style = ""
                if swap_indices is not None and char_pair & swap_indices:
                    style = "background-color:#ffe69c; fw-bold"
                if mutation_indices is not None and char_pair & mutation_indices:
                    style = "background-color:#f8d7da; color:#842029; fw-bold border:2px solid red;"
                elif inversion_indices is not None and char_pair & inversion_indices:
                    style = "background-color:#cfe2ff; color:#084298;"
                yield f"<td style='{style}'>{cell_val}</td>"

    @staticmethod
    def format_matrix_html(population, title):
        if not population: return ""
        chrom_len = len(population[0])
        html = [f"<div class='mt-3 mb-2'><strong>>> {title}</strong></div>"] if title else []
        html.append("<div class='table-responsive' style='overflow-x: auto; white-space: nowrap; border: 1px solid #ccc;'>")
        html.append("<table class='table table-sm table-bordered table-striped mb-0' style='font-size: 0.75em; text-align: center; font-family: monospace;'>")
        html.append("<thead class='table-dark'><tr>")
        html.append("<th style='position: sticky; left: 0; z-index: 1;'>Individu</th>") 
        num_cols = GeneticUtils._display_cols(chrom_len)
        for g in range(num_cols): html.append(f"<th>G{g+1}</th>")
        html.append("</tr></thead><tbody>")
        for i, chrom in enumerate(population):
            html.append("<tr>")
            html.append(f"<td class='fw-bold bg-light' style='position: sticky; left: 0;'>Kromosom {i+1}</td>")
            html.append("".join(GeneticUtils._render_row_cells(chrom)))
            html.append("</tr>")
        html.append("</tbody></table></div>")
        return "".join(html)

    @staticmethod
    def _hex_to_bin(hex_str):
        cleaned = (hex_str if isinstance(hex_str, str) else ''.join(hex_str))
        cleaned = cleaned.replace(' ', '').lower()
        out = []
        for ch in cleaned:
            if ch in '0123456789abcdef':
                out.append(f'{int(ch, 16):04b}')
            else:
                out.append('0000')
        return ''.join(out)

    @staticmethod
    def _render_binary_rows_chrom(chrom):
        bin_str = GeneticUtils._hex_to_bin(chrom)
        for bit in bin_str:
            yield f"<td>{bit}</td>"

    @staticmethod
    def format_binary_matrix_html(population, title):
        if not population: return ""
        first_bin = GeneticUtils._hex_to_bin(population[0])
        num_cols = len(first_bin)
        html = [f"<div class='mt-3 mb-2'><strong>>> {title}</strong></div>"] if title else []
        html.append("<div class='table-responsive' style='overflow-x: auto; white-space: nowrap; border: 1px solid #ccc;'>")
        html.append("<table class='table table-sm table-bordered table-striped mb-0' style='font-size: 0.75em; text-align: center; font-family: monospace;'>")
        html.append("<thead class='table-dark'><tr>")
        html.append("<th style='position: sticky; left: 0; z-index: 1;'>Individu</th>")
        for g in range(num_cols): html.append(f"<th>G{g+1}</th>")
        html.append("</tr></thead><tbody>")
        for i, chrom in enumerate(population):
            html.append("<tr>")
            html.append(f"<td class='fw-bold bg-light' style='position: sticky; left: 0;'>Kromosom {i+1}</td>")
            html.append("".join(GeneticUtils._render_binary_rows_chrom(chrom)))
            html.append("</tr>")
        html.append("</tbody></table></div>")
        return "".join(html)

    @staticmethod
    def process_file_binary(file_path, key_str):
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
            binary_preview = raw_bytes.hex().upper()[:500] 

            is_image = file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.webp', '.tiff'))

            metadata = {
                'filename': os.path.basename(file_path),
                'size': f"{stat.st_size / 1024:.2f} KB",
                'type': "Image Hash (SHA-256)" if is_image else "PDF Metadata",
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            }

            if is_image:
                file_hash = hashlib.sha256(raw_bytes).hexdigest().upper()
                final_key = file_hash[:key_length].ljust(key_length, 'X')
                return {'metadata': metadata, 'generated_key': final_key, 'plaintext_sample': f"SHA-256 HASH:\n{file_hash}"}
            else:
                if file_path.lower().endswith('.pdf'):
                    try:
                        reader = PdfReader(file_path)
                        for page in reader.pages:
                            text = page.extract_text()
                            if text: content_text += text + "\n"
                    except Exception as e: return {'error': f'PDF Error: {str(e)}'}
                else: return {'error': 'Bukan PDF atau Gambar yang didukung'}

                data = {}
                patterns = PDF_METADATA_PATTERNS
                for pat, key in patterns:
                    match = re.search(pat, content_text, re.DOTALL | re.IGNORECASE)
                    if match: data[key] = match.group(1)

                raw_string = "".join(data.values() if data else [])
                raw_key = "".join(ch for ch in raw_string if ch.isalnum())
                if len(raw_key) < 5: raw_key = "".join(ch for ch in content_text if ch.isalnum())

                final_key = raw_key[:key_length]
                while len(final_key) < key_length: final_key += "X"

                return {'metadata': metadata, 'generated_key': final_key, 'plaintext_sample': binary_preview}
        except Exception as e: return {'error': str(e)}

    @staticmethod
    def chromosome_to_key_bytes(chromosome):
        if CHROMOSOME_MODE == 'hex':
            hex_str = chromosome[:CHROM_LEN].ljust(CHROM_LEN, '0')
            return bytes.fromhex(hex_str)
        else:
            bits = ''.join('1' if b else '0' for b in chromosome[:CHROM_LEN])
            if len(bits) < CHROM_LEN:
                bits = bits.ljust(CHROM_LEN, '0')
            return bytes(int(bits[i:i+8], 2) for i in range(0, CHROM_LEN, 8))

    @staticmethod
    def chromosome_to_hex_key(chromosome):
        if CHROMOSOME_MODE == 'hex':
            hex_str = chromosome[:CHROM_LEN].upper()
            return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        else:
            return GeneticUtils.chromosome_to_key_bytes(chromosome).hex().upper()

    @staticmethod
    def _load_training_plain(file_path):
        is_image = file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.webp', '.tiff'))
        if is_image:
            img = Image.open(file_path).convert('RGB')
            try: img = img.resize((256, 256), Image.Resampling.LANCZOS)
            except AttributeError: img = img.resize((256, 256), Image.LANCZOS)
            return bytes(img.tobytes()), True
        with open(file_path, 'rb') as f:
            return f.read(), False

    @staticmethod
    def _fitness_from_cipher(plain_bytes, key_bytes, is_image):
        fixed_iv = b'\x00' * 16
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=fixed_iv)
        padded = pad(plain_bytes, AES.block_size)
        c1 = cipher.encrypt(padded)

        entropy = EvaluationUtils.calculate_entropy(c1)
        ent_norm = min(entropy / 8.0, 1.0)

        modified = bytearray(plain_bytes)
        bit_to_flip = 0 if is_image else len(modified) // 2
        modified[bit_to_flip] ^= 0x01
        cipher2 = AES.new(key_bytes, AES.MODE_CBC, iv=fixed_iv)
        c2 = cipher2.encrypt(pad(bytes(modified), AES.block_size))
        ae = EvaluationUtils.calculate_avalanche_effect(c1, c2)
        ava_norm = 1 - abs(ae - 50.0) / 50.0

        total_bits = len(c1) * 8
        ones = int.from_bytes(c1, 'big').bit_count()
        frac1 = ones / total_bits if total_bits else 0.5
        bit_norm = 1 - 2 * abs(frac1 - 0.5)

        fitness = (W_ENT * ent_norm + W_AVA * ava_norm + W_BIT * bit_norm) * MAX_FITNESS
        return fitness, ent_norm, ava_norm, bit_norm

    @staticmethod
    def extract_raw_source(file_path):
        with open(file_path, 'rb') as f:
            raw_bytes = f.read()
        if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.webp', '.tiff')):
            return hashlib.sha256(raw_bytes).hexdigest().upper()
        if file_path.lower().endswith('.pdf'):
            try:
                reader = PdfReader(file_path)
                content_text = ''.join((p.extract_text() or '') for p in reader.pages)
            except Exception:
                content_text = raw_bytes.hex()
            data = {}
            for pat, key in PDF_METADATA_PATTERNS:
                match = re.search(pat, content_text, re.DOTALL | re.IGNORECASE)
                if match: data[key] = match.group(1)
            raw_string = "".join(data.values() if data else [])
            raw_key = "".join(ch for ch in raw_string if ch.isalnum())
            if len(raw_key) < 5:
                raw_key = "".join(ch for ch in content_text if ch.isalnum())
            return raw_key
        return hashlib.sha256(raw_bytes).hexdigest().upper()

    @staticmethod
    def _derive_seed(file_path, is_image, train_plain):
        if is_image:
            h = hashlib.sha256(train_plain).hexdigest()
        else:
            h = hashlib.sha256(GeneticUtils.extract_raw_source(file_path).encode('utf-8')).hexdigest()
        return int(h, 16) % (2 ** 32)

    @staticmethod
    def tournament_selection(population, fitness_scores, base_seed, debug=False):
        selected = []
        debug_html = [] 
        step_data = []
        temp_seed = base_seed + int(sum(fitness_scores))
        chrom_len = len(population[0]) if population else 0

        for i in range(2): 
            pengacak = PRNG(temp_seed)
            tournament_indices = [pengacak.randint(0, len(population) - 1) for _ in range(3)]
            tournament_fitness = [fitness_scores[idx] for idx in tournament_indices]
            
            best_val = max(tournament_fitness)
            best_local_idx = tournament_fitness.index(best_val)
            best_pop_idx = tournament_indices[best_local_idx]
            winner_chrom = population[best_pop_idx]
            
            selected.append(winner_chrom)

            chrom_key = lambda c: c if isinstance(c, str) else ''.join(str(g) for g in c)
            step_data.append({
                'parent_no': i + 1,
                'kandidat': [{'idx': idx + 1, 'krom': GeneticUtils.chromosome_to_hex_key(population[idx]), 'fitness': fit}
                             for idx, fit in zip(tournament_indices, tournament_fitness)],
                'winner_idx': best_pop_idx + 1,
                'winner_krom': GeneticUtils.chromosome_to_hex_key(winner_chrom),
                'winner_fitness': best_val
            })
            
            if debug:
                debug_html.append(f"<div class='mt-3 mb-1 fw-bold text-primary'>Induk {i+1}</div>")
                debug_html.append("<div class='table-responsive mb-2'>")
                debug_html.append("<table class='table table-bordered table-sm table-striped mb-0' style='font-size: 0.7em; text-align: center; font-family: monospace;'>")
                debug_html.append("<thead class='table-dark'><tr><th>Kandidat</th>")
                num_cols = GeneticUtils._display_cols(chrom_len)
                for g in range(num_cols): debug_html.append(f"<th>G{g+1}</th>")
                debug_html.append("<th>Fitness</th></tr></thead><tbody>")
                
                for idx, fit in zip(tournament_indices, tournament_fitness):
                    row_style = "table-info fw-bold" if idx == best_pop_idx else ""
                    debug_html.append(f"<tr class='{row_style}'>")
                    debug_html.append(f"<td class='text-nowrap'>Kromosom {idx+1}</td>")
                    debug_html.append("".join(GeneticUtils._render_row_cells(population[idx])))
                    debug_html.append(f"<td class='fw-bold text-danger'>{fit:.0f}</td></tr>")
                debug_html.append("</tbody></table></div>")
                
                debug_html.append(f"<div class='mb-1 fw-bold text-success'>Pemenang Induk {i+1}</div>")
                debug_html.append("<div class='table-responsive mb-4'>")
                debug_html.append("<table class='table table-bordered table-sm' style='font-size: 0.7em; text-align: center; font-family: monospace; border: 2px solid #198754;'>")
                debug_html.append("<thead class='table-success'><tr><th>Pemenang</th>")
                for g in range(num_cols): debug_html.append(f"<th>G{g+1}</th>")
                debug_html.append("<th>Fitness</th></tr></thead><tbody><tr>")
                debug_html.append(f"<td class='fw-bold'>Kromosom {best_pop_idx+1}</td>")
                debug_html.append("".join(GeneticUtils._render_row_cells(winner_chrom)))
                debug_html.append(f"<td class='fw-bold'>{best_val:.0f}</td></tr></tbody></table></div>")

            temp_seed += 1
            
        if debug: return selected, "".join(debug_html), step_data
        return selected

    @staticmethod
    def uniform_crossover(parent1, parent2, crossover_rate, base_seed, chrom_len, debug=False):
        if CHROMOSOME_MODE == 'hex':
            child1, child2 = list(parent1), list(parent2)
            seed_sum = sum(ord(c) for c in parent1) + sum(ord(c) for c in parent2)
        else:
            child1, child2 = parent1.copy(), parent2.copy()
            seed_sum = sum(parent1) + sum(parent2)
        pengacak = PRNG(base_seed + seed_sum)
        swap_indices = []
        occurred = False
        
        if pengacak.randint(0, 99) < crossover_rate:
            occurred = True
            for i in range(chrom_len):
                if pengacak.randint(0, 99) < 50:
                    child1[i], child2[i] = parent2[i], parent1[i]
                    swap_indices.append(i)

        if CHROMOSOME_MODE == 'hex':
            child1, child2 = ''.join(child1), ''.join(child2)

        cross_data = {
            'parent1': GeneticUtils.chromosome_to_hex_key(parent1) if CHROMOSOME_MODE == 'hex' else ''.join(str(g) for g in parent1),
            'parent2': GeneticUtils.chromosome_to_hex_key(parent2) if CHROMOSOME_MODE == 'hex' else ''.join(str(g) for g in parent2),
            'child1': GeneticUtils.chromosome_to_hex_key(child1) if CHROMOSOME_MODE == 'hex' else ''.join(str(g) for g in child1),
            'child2': GeneticUtils.chromosome_to_hex_key(child2) if CHROMOSOME_MODE == 'hex' else ''.join(str(g) for g in child2),
            'swap_positions': swap_indices,
            'occurred': occurred
        }

        debug_html = ""
        if debug:
            debug_html += f"<div class='mt-3 mb-1 fw-bold text-primary'>Simulasi Crossover Uniform (Induk 1 & 2)</div>"
            if not occurred: debug_html += f"<div class='alert alert-warning py-1 small'>Crossover tidak terjadi (Probabilitas < {crossover_rate}%)</div>"
            
            debug_html += "<div class='table-responsive mb-4'>"
            debug_html += "<table class='table table-bordered table-sm mb-0' style='font-size: 0.7em; text-align: center; font-family: monospace;'>"
            debug_html += "<thead class='table-dark'><tr><th>Status</th>"
            num_cols = GeneticUtils._display_cols(chrom_len)
            for g in range(num_cols): debug_html += f"<th>G{g+1}</th>"
            debug_html += "</tr></thead><tbody><tr><td class='fw-bold'>Induk 1</td>"
            debug_html += "".join(GeneticUtils._render_row_cells(parent1, swap_indices=set(swap_indices)))
            debug_html += "</tr><tr><td class='fw-bold'>Induk 2</td>"
            debug_html += "".join(GeneticUtils._render_row_cells(parent2, swap_indices=set(swap_indices)))
            debug_html += "</tr><tr><td colspan='" + str(num_cols + 1) + "' class='bg-secondary text-white small py-0'>⬇️ HASIL PERTUKARAN GEN ⬇️</td></tr>"
            debug_html += "<tr><td class='fw-bold text-success'>Child 1</td>"
            debug_html += "".join(GeneticUtils._render_row_cells(child1, swap_indices=set(swap_indices)))
            debug_html += "</tr><tr><td class='fw-bold text-success'>Child 2</td>"
            debug_html += "".join(GeneticUtils._render_row_cells(child2, swap_indices=set(swap_indices)))
            debug_html += "</tr></tbody></table></div>"

        if debug: return child1, child2, debug_html, cross_data
        return child1, child2
    
    @staticmethod
    def hybrid_mutation(chromosome, mutation_rate, base_seed, chrom_len, debug=False):
        if CHROMOSOME_MODE == 'hex':
            mutated = list(chromosome)
            seed_sum = sum(ord(c) for c in chromosome)
        else:
            mutated = chromosome.copy()
            seed_sum = sum(chromosome)
        pengacak = PRNG(base_seed + seed_sum)
        
        start_pos, end_pos = pengacak.randint(0, chrom_len - 1), pengacak.randint(0, chrom_len - 1)
        if start_pos > end_pos: start_pos, end_pos = end_pos, start_pos
        mutated[start_pos:end_pos + 1] = mutated[start_pos:end_pos + 1][::-1]
        inversion_indices = list(range(start_pos, end_pos + 1))
        
        mutation_indices = []
        mut_count = max(1, round(chrom_len * mutation_rate / 100))
        for _ in range(mut_count):
            idx = pengacak.randint(0, chrom_len - 1)
            if CHROMOSOME_MODE == 'hex':
                mutated[idx] = format(pengacak.randint(0, 15), '01x')
            else:
                mutated[idx] = pengacak.randint(0, 1)
            mutation_indices.append(idx)

        if CHROMOSOME_MODE == 'hex':
            mutated = ''.join(mutated)

        mut_data = {
            'before': GeneticUtils.chromosome_to_hex_key(chromosome) if CHROMOSOME_MODE == 'hex' else ''.join(str(g) for g in chromosome),
            'after': GeneticUtils.chromosome_to_hex_key(mutated) if CHROMOSOME_MODE == 'hex' else ''.join(str(g) for g in mutated),
            'inversion_positions': inversion_indices,
            'mutation_positions': mutation_indices
        }

        debug_html = ""
        if debug:
            debug_html += "<div class='table-responsive mb-2'>"
            debug_html += "<table class='table table-bordered table-sm mb-0' style='font-size: 0.7em; text-align: center; font-family: monospace;'>"
            debug_html += "<thead class='table-dark'><tr><th>Status</th>"
            num_cols = GeneticUtils._display_cols(chrom_len)
            for g in range(num_cols): debug_html += f"<th>G{g+1}</th>"
            debug_html += "</tr></thead><tbody><tr><td class='text-muted'>Sebelum</td>"
            debug_html += "".join(GeneticUtils._render_row_cells(chromosome))
            debug_html += "</tr><tr><td class='fw-bold text-danger'>Sesudah</td>"
            debug_html += "".join(GeneticUtils._render_row_cells(
                mutated,
                mutation_indices=set(mutation_indices),
                inversion_indices=set(inversion_indices)
            ))
            debug_html += "</tr></tbody></table></div>"
            debug_html += "<div class='small text-muted mb-3'>Legenda: <span class='badge bg-primary bg-opacity-25 text-primary border'>Biru = Inversion</span> <span class='badge bg-danger bg-opacity-25 text-danger border'>Merah = Random Resetting</span></div>"

        if debug: return mutated, debug_html, mut_data
        return mutated

    @staticmethod
    def run_genetic_algorithm_murni(target_key, filename, params):
        return GeneticUtils._run_optimization_logic(target_key, filename, params, mode='ga')

    @staticmethod
    def _run_optimization_logic(target_key, filename, params, mode):
        logs = []
        chrom_len = CHROM_LEN

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        train_plain, is_image = GeneticUtils._load_training_plain(file_path)

        if 'fixed_seed' in params and params['fixed_seed']:
            base_seed = int(params['fixed_seed'])
        else:
            base_seed = GeneticUtils._derive_seed(file_path, is_image, train_plain)
            
        prng = PRNG(base_seed)
        if CHROMOSOME_MODE == 'hex':
            population = [''.join(format(prng.randint(0, 15), '01x') for _ in range(chrom_len)) for _ in range(POPULATION_SIZE)]
        else:
            population = [[prng.randint(0, 1) for _ in range(chrom_len)] for _ in range(POPULATION_SIZE)]
        best_hist, global_best = [], []
        max_fit = 0 
        fitness_distribution = []
        avg_history = []
        ga_steps = {
            'populasi_awal': [],
            'selection': [],
            'crossover': [],
            'mutation': [],
            'hasil_populasi_baru': [],
            'evolusi': [],
            'aes_process': {}
        }
        max_gen_val = int(params['max_gen'])
        capture_gens = {0}
        if max_gen_val > 1:
            capture_gens.add(max_gen_val // 2)
            capture_gens.add(max_gen_val - 1)

        safe_target = target_key.replace('<', '&lt;').replace('>', '&gt;')
        logs.append(f"<div class='alert alert-info py-1 mb-2 small'><strong>[INIT]</strong> Mode: {mode.upper()} | Target: '{safe_target}' | <strong>Seed: {base_seed}</strong></div>")
        
        first_gen_log = "" 
        total_gen_duration = 0
        gen_count_real = 0

        for gen in range(int(params['max_gen'])):
            gen_start_time = time.perf_counter()

            fitness_scores = []
            for c in population:
                fit, _, _, _ = GeneticUtils._fitness_from_cipher(train_plain, GeneticUtils.chromosome_to_key_bytes(c), is_image)
                fitness_scores.append(fit)
            current_max = max(fitness_scores)
            current_avg = sum(fitness_scores) / len(fitness_scores)
            
            if gen in capture_gens:
                fitness_distribution.append({
                    'generation': gen,
                    'scores': fitness_scores.copy(),
                    'max_fit': current_max,
                    'avg_fit': current_avg
                })
            avg_history.append(current_avg)
            
            best_idx = fitness_scores.index(current_max)
            current_best_chrom = population[best_idx]
            current_best_text = GeneticUtils.chromosome_to_hex_key(current_best_chrom)
            
            is_new_record = False
            if current_max > max_fit:
                max_fit = current_max
                global_best = current_best_chrom
                is_new_record = True
            
            if gen == 0: global_best = current_best_chrom
            best_hist.append(max_fit)

            if gen == 0:
                logs.append(GeneticUtils.format_binary_matrix_html(population, "Populasi Awal (Biner)"))
                logs.append(GeneticUtils.format_matrix_html(population, "Populasi Awal"))
            if gen == 0:
                ga_steps['populasi_awal'] = [
                    {'kromosom': GeneticUtils.chromosome_to_hex_key(population[i]),
                     'kromosom_biner': GeneticUtils._hex_to_bin(population[i]),
                     'fitness': fitness_scores[i]}
                    for i in range(len(population))
                ]

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
            
            if gen == 0: first_gen_log = log_row
            else: logs.append(log_row)

            new_pop = [] 
            debug_sel, debug_cross, debug_mut = [], [], []
            selection_sim_html, crossover_sim_html, mutation_sim_html = "", "", ""

            while len(new_pop) < POPULATION_SIZE:
                loop_seed = base_seed + gen + len(new_pop)
                
                if gen == 0 and len(new_pop) == 0:
                    p, sel_html, sel_data = GeneticUtils.tournament_selection(population, fitness_scores, loop_seed, debug=True)
                    selection_sim_html = sel_html
                    ga_steps['selection'] = sel_data
                else: p = GeneticUtils.tournament_selection(population, fitness_scores, loop_seed, debug=False)

                if gen == 0 and len(new_pop) == 0:
                    c1, c2, cross_html, cross_data = GeneticUtils.uniform_crossover(p[0], p[1], int(params['cross_rate']), loop_seed, chrom_len, debug=True)
                    crossover_sim_html = cross_html
                    ga_steps['crossover'].append(cross_data)
                else: c1, c2 = GeneticUtils.uniform_crossover(p[0], p[1], int(params['cross_rate']), loop_seed, chrom_len, debug=False)

                if gen == 0 and len(new_pop) == 0:
                    m1, mut_log1, mut_data1 = GeneticUtils.hybrid_mutation(c1, int(params['mut_rate']), loop_seed, chrom_len, debug=True)
                    m2, mut_log2, mut_data2 = GeneticUtils.hybrid_mutation(c2, int(params['mut_rate']), loop_seed, chrom_len, debug=True)
                    mutation_sim_html = f"<div class='fw-bold text-primary mb-1'>Simulasi Mutasi Child 1</div>{mut_log1}<div class='fw-bold text-primary mb-1'>Simulasi Mutasi Child 2</div>{mut_log2}"
                    ga_steps['mutation'].extend([mut_data1, mut_data2])
                else:
                    m1 = GeneticUtils.hybrid_mutation(c1, int(params['mut_rate']), loop_seed, chrom_len)
                    m2 = GeneticUtils.hybrid_mutation(c2, int(params['mut_rate']), loop_seed, chrom_len)

                if gen == 0:
                    debug_sel.extend(p); debug_cross.extend([c1, c2]); debug_mut.extend([m1, m2])

                new_pop.extend([m1, m2])
            
            if gen == 0:
                logs.append("<div class='mt-4 mb-2'><strong>>> Tahap 1: Selection</strong></div>")
                if selection_sim_html: logs.append(f"<div class='card card-body bg-light border p-2 mb-3'>{selection_sim_html}</div>")

                logs.append("<div class='mt-4 mb-2'><strong>>> Tahap 2: Crossover</strong></div>")
                if crossover_sim_html: logs.append(f"<div class='card card-body bg-light border p-2 mb-3'>{crossover_sim_html}</div>")
                
                logs.append("<div class='mt-4 mb-2'><strong>>> Tahap 3: Mutation</strong></div>")
                if mutation_sim_html: logs.append(f"<div class='card card-body bg-light border p-2 mb-3'>{mutation_sim_html}</div>")
                
                logs.append(GeneticUtils.format_matrix_html(debug_mut[:POPULATION_SIZE], "Hasil Populasi Baru (Setelah Mutasi)")) 
                logs.append(GeneticUtils.format_binary_matrix_html(debug_mut[:POPULATION_SIZE], "Hasil Populasi Baru (Setelah Mutasi) - Biner"))
                ga_steps['hasil_populasi_baru'] = [
                    {'kromosom': GeneticUtils.chromosome_to_hex_key(debug_mut[i]),
                     'kromosom_biner': GeneticUtils._hex_to_bin(debug_mut[i]),
                     'fitness': fitness_scores[i] if i < len(fitness_scores) else 0}
                    for i in range(POPULATION_SIZE)
                ]
                
                logs.append("<div class='mt-3 mb-2 fw-bold text-primary border-bottom'>=== MULAI EVOLUSI ===</div>")
                logs.append(
                    "<div class='d-flex justify-content-between small border-bottom py-1 mb-1 fw-bold bg-dark text-white'>"
                    "<span style='width:60px;'>Gen</span><span style='width:80px;'>Max Fit</span><span style='width:90px;'>Avg Fit</span><span class='text-end' style='width:150px;'>Kunci Terbaik</span>"
                    "</div>"
                )
                logs.append(first_gen_log)

            population = new_pop[:POPULATION_SIZE]

            # ELITISME (Setelah Mutasi): ganti offspring terburuk dengan kromosom terbaik
            if population:
                new_scores = []
                for c in population:
                    fit, _, _, _ = GeneticUtils._fitness_from_cipher(train_plain, GeneticUtils.chromosome_to_key_bytes(c), is_image)
                    new_scores.append(fit)
                worst_idx = new_scores.index(min(new_scores))
                population[worst_idx] = global_best

            ga_steps['evolusi'].append({
                'gen': gen + 1,
                'max_fitness': current_max,
                'avg_fitness': round(current_avg, 2),
                'best_kromosom': current_best_text,
                'populasi_akhir': [
                    GeneticUtils.chromosome_to_hex_key(population[i])
                    for i in range(len(population))
                ]
            })
            gen_end_time = time.perf_counter()
            total_gen_duration += (gen_end_time - gen_start_time)
            gen_count_real += 1

        avg_gen_time = total_gen_duration / gen_count_real if gen_count_real > 0 else 0
        logs.append(f"<div class='alert alert-secondary py-1 small mt-2'>⏱️ Rata-rata waktu per generasi: <strong>{avg_gen_time:.6f} detik</strong></div>")

        final_key = GeneticUtils.chromosome_to_hex_key(global_best)
        best_fitness = max_fit

        enc_result = GeneticUtils.process_file_binary(os.path.join(app.config['UPLOAD_FOLDER'], filename), final_key)
        
        key_bytes = _prepare_key(final_key)
        aes_ver, aes_rounds, rk_data, aes_steps = AESUtils.simulate_aes_block_data(list(train_plain[:16]), key_bytes)
        ga_steps['aes_process'] = {
            'key_hex': final_key,
            'round_keys': rk_data,
            'steps': aes_steps,
            'aes_version': aes_ver,
            'rounds': aes_rounds
        }
        
        simulation_html = enc_result.get('simulation_html', '')
        if simulation_html:
            logs.append(simulation_html)

        safe_key = final_key.replace('<', '&lt;').replace('>', '&gt;')
        safe_key_attr = final_key.replace('"', '&quot;')
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
            'fitness_history': best_hist, 'avg_history': avg_history,
            'fitness_distribution': fitness_distribution,
            'fitness_percent': best_fitness / 1000,
            'match_percent': best_fitness / 1000,
            'enc_filename': enc_result.get('enc_filename'), 'metrics': enc_result.get('metrics'),
            'preview': enc_result.get('preview'),
            'source_filename': filename,
            'simulation_html': simulation_html,
            'ga_steps': ga_steps
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
        simulation_html = enc_result.get('simulation_html', '')
        
        logs = [
            f"<div class='alert alert-info py-1 mb-2 small'><strong>[INIT]</strong> Mode: TANPA OPTIMASI (AES SAJA) | Kunci: '{target_key}'</div>",
            "<div class='alert alert-success mt-2'><strong>🎯 ENKRIPSI SELESAI!</strong></div>"
        ]
        
        if simulation_html:
            logs.append(simulation_html)
            
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
            'logs': logs, 'final_key': target_key, 'best_fitness': 0, 'fitness_history': [], 'match_percent': 100.0,
            'enc_filename': enc_result.get('enc_filename'), 'metrics': enc_result.get('metrics'),
            'preview': enc_result.get('preview'),
            'source_filename': filename,
            'simulation_html': simulation_html
        }
        method_name = "AES"
    else:
        result = GeneticUtils.run_genetic_algorithm_murni(data.get('target_key'), data.get('filename'), data)
        method_name = "GA+AES"

    # Penanganan Nilai Metrik agar aman masuk database
    metrics = result.get('metrics', {})
    fitness_val = result.get('best_fitness', 0.0)
    
    try: avalanche_val = float(metrics.get('avalanche', '0.0').replace('%', ''))
    except: avalanche_val = 0.0

    try: npcr_val = float(metrics.get('npcr', 0.0))
    except: npcr_val = 0.0
    
    try: uaci_val = float(metrics.get('uaci', 0.0))
    except: uaci_val = 0.0

    try: time_dec_val = float(metrics.get('time_decryption_sec', 0.0))
    except: time_dec_val = 0.0

    corr_plain_val = None
    corr_cipher_val = None
    corr_data = metrics.get('correlation')
    if corr_data:
        corr_plain_val = float(corr_data['plain_h'])
        corr_cipher_val = float(corr_data['cipher_h'])

    history_id = save_to_history({
        'filename': data.get('filename'), 'method': method_name,
        'key_length': len(data.get('target_key')), 'final_key': result.get('final_key'),
        'fitness': fitness_val, 'time_taken': metrics.get('time_taken_sec'),
        'entropy': metrics.get('entropy'), 'p_value': metrics.get('key_stats', {}).get('p_value', 0), 
        'avalanche': avalanche_val, 'npcr': npcr_val, 'uaci': uaci_val,
        'time_decryption': time_dec_val, 'corr_plain': corr_plain_val, 'corr_cipher': corr_cipher_val,
        'enc_filename': result.get('enc_filename'),
        'pixel_histogram': metrics.get('pixel_histogram'),
        'fitness_distribution': result.get('fitness_distribution'),
        'fitness_history': result.get('fitness_history'),
        'avg_history': result.get('avg_history'),
        'logs': result.get('logs'),
        'simulation_html': result.get('simulation_html'),
        'key_stats': metrics.get('key_stats')
    })
    if history_id and result.get('ga_steps'):
        save_ga_steps(history_id, result['ga_steps'])
    return jsonify(result)

@app.route('/get_history', methods=['GET'])
def get_history():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM history WHERE method NOT IN ('GA Murni [Internal]', 'ga+aes [Internal]') ORDER BY id DESC").fetchall()
        conn.close()
        
        history_data = []
        for row in rows:
            r_dict = dict(row)
            fit_val = r_dict.get('fitness')
            if fit_val is None or pd.isna(fit_val) or str(fit_val).strip().lower() in ['nan', 'none', '', '-']:
                r_dict['fitness'] = 0
            history_data.append(r_dict)
            
        return jsonify(history_data)
    except Exception as e: return jsonify({'error': str(e)})

def parse_json_field(val):
    if not val: return None
    try:
        parsed = json.loads(val)
        return parsed
    except Exception:
        return val

@app.route('/get_history_item/<int:item_id>', methods=['GET'])
def get_history_item(item_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM history WHERE id = ?", (item_id,)).fetchone()
        conn.close()
        if row is None:
            return jsonify({'error': 'Data tidak ditemukan'}), 404

        r_dict = dict(row)
        for col in ['pixel_histogram', 'fitness_distribution', 'fitness_history', 'avg_history', 'logs', 'key_stats']:
            r_dict[col] = parse_json_field(r_dict.get(col))

        fit_val = r_dict.get('fitness')
        if fit_val is None or pd.isna(fit_val) or str(fit_val).strip().lower() in ['nan', 'none', '', '-']:
            r_dict['fitness'] = 0

        return jsonify(r_dict)
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/delete_history_item/<int:item_id>', methods=['POST'])
def delete_history_item(item_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute("DELETE FROM ga_steps WHERE history_id = ?", (item_id,))
        conn.execute("DELETE FROM history WHERE id = ?", (item_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)})

@app.route('/clear_history', methods=['POST'])
def clear_history():
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute("DELETE FROM ga_steps")
        conn.execute("DELETE FROM history")
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e: return jsonify({'error': str(e)})

@app.route('/download_ga_excel/<int:item_id>')
def download_ga_excel(item_id):
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM history WHERE id = ?", (item_id,)).fetchone()
        gs_row = conn.execute("SELECT ga_steps FROM ga_steps WHERE history_id = ?", (item_id,)).fetchone()
        conn.close()
        if not gs_row:
            return jsonify({'error': 'Data langkah GA tidak ditemukan'}), 404
        ga_steps = json.loads(gs_row['ga_steps'])
        history = dict(row) if row else {}

        wb = openpyxl.Workbook()
        hdr_font = Font(bold=True, color="FFFFFF")
        hdr_fill = PatternFill(start_color="4472C4", end_color="4472C4", fill_type="solid")
        hex_font = Font(name="Consolas", size=10)

        def write_headers(ws, headers):
            for col, h in enumerate(headers, 1):
                cell = ws.cell(row=1, column=col, value=h)
                cell.font = hdr_font
                cell.fill = hdr_fill
                cell.alignment = Alignment(horizontal='center')
            ws.auto_filter.ref = f"A1:{openpyxl.utils.get_column_letter(len(headers))}1"
            ws.freeze_panes = "A2"

        def auto_width(ws):
            for col in ws.columns:
                max_len = max(len(str(c.value or '')) for c in col)
                ws.column_dimensions[col[0].column_letter].width = min(max_len + 2, 50)

        def hex_to_matrix(hex_str, cols=16):
            return [hex_str[i:i+2].upper() for i in range(0, len(hex_str), 2)]

        def state_to_matrix(state, cols=16):
            return [format(state[i], '02X') for i in range(len(state))]

        # Sheet 1: Populasi Awal
        ws = wb.active
        ws.title = "Populasi Awal"
        write_headers(ws, ["No", "Kromosom (Hex)"] + [f"G{i+1}" for i in range(16)] + ["Fitness"])
        for i, item in enumerate(ga_steps.get('populasi_awal', []), 1):
            chrom = item['kromosom'].replace(' ', '')
            hex_cols = hex_to_matrix(chrom)
            ws.cell(row=i+1, column=1, value=i).font = Font(bold=True)
            ws.cell(row=i+1, column=2, value=item['kromosom']).font = hex_font
            for g, val in enumerate(hex_cols):
                ws.cell(row=i+1, column=3+g, value=val).font = hex_font
            ws.cell(row=i+1, column=19, value=item['fitness'])
        auto_width(ws)

        # Sheet 1b: Populasi Awal (Biner)
        ws = wb.create_sheet("Populasi Awal (Biner)")
        write_headers(ws, ["No", "Kromosom (Biner - 128 bit)", "Fitness"])
        for i, item in enumerate(ga_steps.get('populasi_awal', []), 1):
            bin_str = item.get('kromosom_biner') or GeneticUtils._hex_to_bin(item['kromosom'].replace(' ', ''))
            ws.cell(row=i+1, column=1, value=i).font = Font(bold=True)
            ws.cell(row=i+1, column=2, value=bin_str).font = hex_font
            ws.cell(row=i+1, column=3, value=item.get('fitness'))
        auto_width(ws)

        # Sheet 2: Selection
        ws = wb.create_sheet("Selection")
        write_headers(ws, ["Induk Ke-", "Kandidat 1", "Krom 1", "Fit 1",
                           "Kandidat 2", "Krom 2", "Fit 2",
                           "Kandidat 3", "Krom 3", "Fit 3",
                           "Pemenang", "Krom Pemenang", "Fit Pemenang"])
        for i, sel in enumerate(ga_steps.get('selection', []), 1):
            kandidat = sel.get('kandidat', [])
            r = i + 1
            ws.cell(row=r, column=1, value=f"Induk {sel.get('parent_no', i)}").font = Font(bold=True)
            for k, kd in enumerate(kandidat):
                ws.cell(row=r, column=2+k*3, value=f"Kromosom {kd['idx']}")
                ws.cell(row=r, column=3+k*3, value=kd['krom']).font = hex_font
                ws.cell(row=r, column=4+k*3, value=kd['fitness'])
            ws.cell(row=r, column=11, value=f"Kromosom {sel.get('winner_idx')}").font = Font(bold=True, color="FF0000")
            ws.cell(row=r, column=12, value=sel.get('winner_krom', '')).font = Font(name="Consolas", size=10, bold=True, color="FF0000")
            ws.cell(row=r, column=13, value=sel.get('winner_fitness', 0)).font = Font(bold=True)
        auto_width(ws)

        # Sheet 3: Crossover
        ws = wb.create_sheet("Crossover")
        write_headers(ws, ["Status", "Parent 1 (Hex)", "Parent 2 (Hex)",
                           "Child 1 (Hex)", "Child 2 (Hex)", "Swap Positions (0-idx)"])
        for i, cx in enumerate(ga_steps.get('crossover', []), 1):
            r = i + 1
            ws.cell(row=r, column=1, value="Terjadi" if cx.get('occurred') else "Tidak").font = Font(bold=True)
            ws.cell(row=r, column=2, value=cx.get('parent1', '')).font = hex_font
            ws.cell(row=r, column=3, value=cx.get('parent2', '')).font = hex_font
            ws.cell(row=r, column=4, value=cx.get('child1', '')).font = hex_font
            ws.cell(row=r, column=5, value=cx.get('child2', '')).font = hex_font
            ws.cell(row=r, column=6, value=', '.join(str(p) for p in cx.get('swap_positions', [])))
        auto_width(ws)

        # Sheet 4: Mutation
        ws = wb.create_sheet("Mutation")
        write_headers(ws, ["No", "Sebelum Mutasi (Hex)", "Sesudah Mutasi (Hex)",
                           "Inversion Positions", "Mutation Positions"])
        for i, mu in enumerate(ga_steps.get('mutation', []), 1):
            r = i + 1
            ws.cell(row=r, column=1, value=i).font = Font(bold=True)
            ws.cell(row=r, column=2, value=mu.get('before', '')).font = hex_font
            ws.cell(row=r, column=3, value=mu.get('after', '')).font = hex_font
            ws.cell(row=r, column=4, value=', '.join(str(p) for p in mu.get('inversion_positions', [])))
            ws.cell(row=r, column=5, value=', '.join(str(p) for p in mu.get('mutation_positions', [])))
        auto_width(ws)

        # Sheet 5: Hasil Populasi Baru
        ws = wb.create_sheet("Hasil Populasi Baru")
        write_headers(ws, ["No", "Kromosom (Hex)"] + [f"G{i+1}" for i in range(16)] + ["Fitness"])
        for i, item in enumerate(ga_steps.get('hasil_populasi_baru', []), 1):
            chrom = item['kromosom'].replace(' ', '')
            hex_cols = hex_to_matrix(chrom)
            ws.cell(row=i+1, column=1, value=i).font = Font(bold=True)
            ws.cell(row=i+1, column=2, value=item['kromosom']).font = hex_font
            for g, val in enumerate(hex_cols):
                ws.cell(row=i+1, column=3+g, value=val).font = hex_font
            ws.cell(row=i+1, column=19, value=item.get('fitness', 0))
        auto_width(ws)

        # Sheet 5b: Hasil Populasi Baru (Biner)
        ws = wb.create_sheet("Hasil Populasi Baru (Biner)")
        write_headers(ws, ["No", "Kromosom (Biner - 128 bit)", "Fitness"])
        for i, item in enumerate(ga_steps.get('hasil_populasi_baru', []), 1):
            bin_str = item.get('kromosom_biner') or GeneticUtils._hex_to_bin(item['kromosom'].replace(' ', ''))
            ws.cell(row=i+1, column=1, value=i).font = Font(bold=True)
            ws.cell(row=i+1, column=2, value=bin_str).font = hex_font
            ws.cell(row=i+1, column=3, value=item.get('fitness', 0))
        auto_width(ws)

        # Sheet 6: Evolusi
        ws = wb.create_sheet("Evolusi")
        write_headers(ws, ["Generasi", "Max Fitness", "Avg Fitness", "Kromosom Terbaik", "Populasi Akhir"])
        for ev in ga_steps.get('evolusi', []):
            r = ev['gen'] + 1
            ws.cell(row=r, column=1, value=ev['gen']).font = Font(bold=True)
            ws.cell(row=r, column=2, value=ev['max_fitness'])
            ws.cell(row=r, column=3, value=ev['avg_fitness'])
            ws.cell(row=r, column=4, value=ev['best_kromosom']).font = hex_font
            ws.cell(row=r, column=5, value='\n'.join(ev.get('populasi_akhir', []))).font = hex_font
        auto_width(ws)

        # Sheet 7: Proses Enkripsi AES
        ws = wb.create_sheet("Proses Enkripsi AES")
        aes = ga_steps.get('aes_process', {})
        ws.cell(row=1, column=1, value="Kunci Final").font = Font(bold=True)
        ws.cell(row=1, column=2, value=aes.get('key_hex', '')).font = hex_font
        ws.cell(row=2, column=1, value="Versi AES").font = Font(bold=True)
        ws.cell(row=2, column=2, value=aes.get('aes_version', ''))
        ws.cell(row=3, column=1, value="Jumlah Round").font = Font(bold=True)
        ws.cell(row=3, column=2, value=aes.get('rounds', 0))

        ws.cell(row=5, column=1, value="Round Keys:").font = Font(bold=True)
        write_headers(ws, ["Round", "Key (Hex)"])
        for i, rk in enumerate(aes.get('round_keys', [])):
            ws.cell(row=i+6, column=1, value=rk['round']).font = Font(bold=True)
            ws.cell(row=i+6, column=2, value=rk['key_hex']).font = hex_font

        step_start = 6 + len(aes.get('round_keys', [])) + 1
        ws.cell(row=step_start, column=1, value="Langkah Enkripsi per Round:").font = Font(bold=True)
        write_headers(ws, ["Tahap"] + [f"B{i+1}" for i in range(16)])
        for i, step in enumerate(aes.get('steps', [])):
            r = step_start + 1 + i
            ws.cell(row=r, column=1, value=step['tahap']).font = Font(bold=True)
            state = step.get('state', [])
            for b, val in enumerate(state):
                hex_val = format(val, '02X') if isinstance(val, int) else str(val).upper()
                ws.cell(row=r, column=2+b, value=hex_val).font = hex_font
        auto_width(ws)

        # Sheet 8: Hasil Uji
        ws = wb.create_sheet("Hasil Uji")
        write_headers(ws, ["Metrik", "Nilai"])
        metrics_list = [
            ("Fitness", history.get('fitness', 0)),
            ("Entropy", history.get('entropy', 0)),
            ("P-Value", history.get('p_value', 0)),
            ("Avalanche (%)", history.get('avalanche', 0)),
            ("Korelasi Plaintext", history.get('corr_plain', 0)),
            ("Korelasi Ciphertext", history.get('corr_cipher', 0)),
            ("NPCR (%)", history.get('npcr', 0)),
            ("UACI (%)", history.get('uaci', 0)),
            ("Waktu Enkripsi (s)", history.get('time_taken', 0)),
            ("Waktu Dekripsi (s)", history.get('time_decryption', 0)),
        ]
        for i, (name, val) in enumerate(metrics_list, 2):
            ws.cell(row=i, column=1, value=name).font = Font(bold=True)
            ws.cell(row=i, column=2, value=val)
        auto_width(ws)

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx')
        wb.save(tmp.name)
        tmp.close()
        return send_file(tmp.name, as_attachment=True,
                         download_name=f"GA_Steps_{item_id}.xlsx")
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

def clean_illegal_chars(val):
    if isinstance(val, str): return re.sub(r'[\x00-\x1F\x7F]', '', val)
    return val

@app.route('/download_excel')
def download_excel():
    try:
        conn = sqlite3.connect(DB_NAME)
        df = pd.read_sql_query("SELECT * FROM history", conn)
        conn.close()

        if df.empty: return "Tidak ada data.", 404

        if hasattr(df, 'map'): df = df.map(clean_illegal_chars)
        else: df = df.applymap(clean_illegal_chars)

        df.replace(["NaN", "nan", "NAN", "None", "none", ""], None, inplace=True)
        df['key_length'] = pd.to_numeric(df['key_length'], errors='coerce')
        
        cols_std = ['filename', 'method', 'key_length', 'avalanche', 'time_taken', 'time_decryption', 
                    'entropy', 'p_value', 'npcr', 'uaci', 'corr_plain', 'corr_cipher', 'timestamp']
        rename_map = {'fitness': 'Fitness', 
            'p_value': 'P-Value',
            'avalanche': 'Avalanche (%)', 
            'time_taken': 'Waktu Enkripsi (s)', 
            'time_decryption': 'Waktu Dekripsi (s)', 
            'corr_plain': 'Korelasi Plaintext', 
            'corr_cipher': 'Korelasi Ciphertext', 
            'npcr': 'NPCR (%)', 
            'uaci': 'UACI (%)'
        }

        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df_ga_all = df[df['method'].str.contains(r"ga\+aes|GA Murni", case=False, na=False)].copy()
            df_ga_clean = df_ga_all[~df_ga_all['method'].isin(["GA Murni [Internal]", "ga+aes [Internal]"])]

            if not df_ga_clean.empty:
                cols_exist = [c for c in cols_std if c in df_ga_clean.columns]
                df_ga_std = df_ga_clean[cols_exist].copy()
                df_ga_std.rename(columns=rename_map, inplace=True)
                df_ga_std.sort_values(by='key_length', ascending=True).fillna("-").to_excel(writer, sheet_name='GA + AES', index=False)
            
            df_aes = df[df['method'].str.lower().isin(["aes", "aes saja"])].copy()
            if not df_aes.empty:
                cols_exist = [c for c in cols_std if c in df_aes.columns]
                df_aes_std = df_aes[cols_exist].copy()
                df_aes_std.rename(columns=rename_map, inplace=True)
                df_aes_std.sort_values(by='key_length', ascending=True).fillna("-").to_excel(writer, sheet_name='AES', index=False)
            
            if df_ga_clean.empty and df_aes.empty:
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

@app.route('/preview_result/<path:filename>')
def preview_result(filename):
    return send_from_directory(app.config['RESULTS_FOLDER'], filename, as_attachment=False)

@app.route('/preview_source/<path:filename>')
def preview_source(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

@app.route('/result_preview/<path:filename>')
def result_preview(filename):
    file_path = os.path.join(app.config['RESULTS_FOLDER'], filename)
    if not os.path.isfile(file_path):
        return jsonify({'error': 'Berkas hasil tidak ditemukan'}), 404
    try:
        with open(file_path, 'rb') as f: raw = f.read()
        is_image = filename.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.webp', '.tiff'))
        payload = AESUtils.build_cipher_preview(raw, is_image, filename, max_bytes=0 if is_image else 256)
        return jsonify(payload)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 SISTEM BERJALAN: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)