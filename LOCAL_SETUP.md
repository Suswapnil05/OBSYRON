# OBSYRON XTM 2.0 — Local Development & Setup Guide

## 1. Quick Start (Windows / macOS / Linux)

### Step 1: System Requirements
- Python 3.11+
- Git

### Step 2: Clone & Environment Setup
```bash
# Clone the repository
git clone https://github.com/Suswapnil05/OBSYRON.git
cd OBSYRON

# Optional: Create a virtual environment
python -m venv venv

# Activate on Windows:
venv\Scripts\activate
# Activate on macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Run the Application
```bash
python app.py
```
Open your browser to: `http://localhost:8000/`.

---

## 2. Windows 1-Click Launch Script

On Windows machines, double-click `start_obsyron.bat`. This script will:
1. Verify Python installation.
2. Install dependencies from `requirements.txt` if needed.
3. Launch `app.py` on `http://localhost:8000`.
4. Automatically open your default web browser to the OBSYRON SOC Cockpit.

---

## 3. Verifying Local Installation

Execute direct endpoint verification:
```bash
python test_direct_endpoints.py
```
If all tests report `✓ PASS`, your local installation is fully verified and operational.
