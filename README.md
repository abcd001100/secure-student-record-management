# Secure Student Record Management

Individual project for **CCS2243 Cryptography Essential**, Albukhary International University.

- **Student:** Abdulaziz Taju Mohammedyasin
- **Student ID:** AIU24102453
- **Group:** BCS2B

## What this is

A desktop application (Python + Tkinter + SQLite) that stores student
records and protects a defined set of sensitive fields (IC/passport
number, phone number, address, guardian contact, remarks) with
**AES-256-GCM** envelope encryption. Login passwords are protected
separately with **PBKDF2-HMAC-SHA256**. Full design and security
discussion is in the accompanying project report.

## Requirements

- Python 3.10+
- `pip install -r requirements.txt` (installs the `cryptography`
  package; `tkinter` and `sqlite3` ship with standard Python)

## Running the application

```
python main.py
```

- **First run:** you will be asked to create a *master password* (this
  generates the AES-256 Data Encryption Key and wraps it) and then to
  create the first administrator account.
- **Later runs:** enter the master password to unlock the encryption
  key, then log in with a username/password account.

Two files are created next to `main.py` and are intentionally not
committed to this repository (see `.gitignore`):
- `students.db` -- the SQLite database (student data + audit log).
- `keystore.json` -- the wrapped Data Encryption Key.

## Running in GitHub Codespaces

This repo includes a `.devcontainer` configuration. Open it in a
Codespace, wait for the container to finish building, then:

1. Open the **Ports** tab and click the forwarded port labelled
   "Desktop (noVNC)" to open a small virtual desktop in your browser
   (VNC password: `vscode`).
2. In the Codespace's integrated terminal, run `python main.py`.
3. The Tkinter window will appear inside that virtual desktop tab.

## Running the automated tests

```
python -m unittest discover -s tests -v
```

31 tests covering password hashing, envelope-key wrap/unwrap,
corrupted-input handling, AES-GCM correctness and negative cases,
CRUD, validation, and authentication/RBAC including account lockout
and reactivation.

## Generating fresh cryptographic evidence

```
python tests/demo_evidence.py
```

Prints real, freshly measured entropy, timing, and negative-test
(tamper / wrong-key / wrong-master-password) evidence using a
throw-away temporary database, then deletes it.

## Project layout

```
secure_student_records/
  main.py                    Entry point
  requirements.txt
  app/
    crypto_utils.py          Password hashing + AES-256-GCM envelope encryption
    database.py               SQLite schema and queries (parameterised)
    validators.py             Input validation
    auth.py                   Login, RBAC, account lockout/reactivation
    records.py                Student record service (validate -> encrypt -> store)
    gui.py                     Tkinter screens
    storage_paths.py          File locations for students.db / keystore.json
  tests/
    test_crypto.py             Unit tests for crypto_utils
    test_records_and_db.py    Integration tests for records/auth/database
    demo_evidence.py          Evidence-generation script (not a unit test)
  diagrams/                   Source files (Mermaid + SVG) for the design diagrams
  screenshots/                Application screenshots used in the project report
  .devcontainer/              GitHub Codespaces configuration (GUI support via noVNC)
```
