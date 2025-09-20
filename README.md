# 🛡️ Ransomware Simulation & Detection (Educational Demo)

⚠️ **WARNING: EDUCATIONAL USE ONLY** ⚠️  
This project contains code that simulates **ransomware behavior** (file encryption with ransom notes).  
It is intended **only for research, academic study, and defensive training** in **controlled environments (VMs, sandboxes, disposable test folders)**.  

❌ Do **NOT** run this on personal files, production systems, or any machine you do not own/operate.  
The authors are **not responsible for misuse**.  

---

## 📖 Overview
This repository contains two Python tools:

1. **`simulation.py`**  
   - Demonstrates ransomware behavior by encrypting files in a chosen directory and dropping a ransom note.  
   - Supports decryption if the original password is known.  

2. **`detect.py`**  
   - Scans directories for files with ransomware-like extensions.  
   - Provides options to isolate or attempt recovery (rename/copy) of affected files.  
   - Note: Recovery here does **not** decrypt files; use the simulation’s decryption function with the correct password.  

---

## 🛠️ Technology Used
- **Python 3.8+**
- **Tkinter** – GUI framework (bundled with Python)
- **cryptography** – AES-CBC encryption, Scrypt key derivation, PKCS7 padding  
- **os / shutil / threading** – filesystem traversal, file isolation, recovery operations  

---

## ⚡ How It Works
### 🔒 Simulation
- Encrypts files with AES-CBC, appends `.crypto` extension  
- Drops a `RANSOM_NOTE.txt` in each folder  
- Provides decryption if the correct password is supplied  

### 🔍 Detection
- Scans directories for known ransomware extensions (`.crypto`, `.wannacry`, `.ryuk`, etc.)  
- Lists suspicious files in the GUI  
- Allows:
  - **Isolation** → moves suspicious files to quarantine  
  - **Recovery** → renames/removes extension (does not decrypt contents)  

---

## 🚀 Usage (Safe Sandbox Instructions)
1. **Run only in disposable test folders or VMs**. Example:
   ```bash
   mkdir /tmp/ransom-demo
   echo "test" > /tmp/ran
