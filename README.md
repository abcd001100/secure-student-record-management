# Secure Student Record Management

Individual project for **CCS2243 Cryptography Essential**, Albukhary International University.

- **Student:** Abdulaziz Taju Mohammedyasin
- **Student ID:** AIU24102453
- **Group:** BCS2B

## What this is

A desktop application (Python + Tkinter + SQLite) that stores student
records and protects every sensitive field (IC/passport number, phone
number, address, guardian contact, remarks) with **AES-256-GCM**
envelope encryption. Login passwords are protected separately with
**PBKDF2-HMAC-SHA256**. See the full report
(`REPORT_Secure_Student_Record_Management.md`) for the full design and
justification.

## Requirements

- Python 3.10+
- `pip install -r requirements.txt` (installs the `cryptography` package;
  `tkinter` and `sqlite3` ship with standard Python on Windows)

## Running the application

```
python main.py
```

- **First run:** you will be asked to create a *master password* (this
  generates the AES-256 Data Encryption Key and wraps it) and then to
  create the first administrator account.
- **Later runs:** enter the master password to unlock the encryption
  key, then log in with a username/password account.

Two files are created next to `main.py`:
- `students.db` — the SQLite database (student data + audit log).
- `keystore.json` — the wrapped Data Encryption Key. **Do not commit or
  submit this file next to a plaintext copy of the master password.**

## Running the automated tests

```
python -m unittest discover -s tests -v
```

## Generating fresh evidence for the report

```
python tests/demo_evidence.py
```

This prints real, freshly measured entropy, timing, and negative-test
(tamper / wrong-key / wrong-master-password) evidence using a
throw-away temporary database, then deletes it.

## Project layout

```
secure_student_records/
  main.py                    Entry point
  app/
    crypto_utils.py          Password hashing + AES-256-GCM envelope encryption
    database.py               SQLite schema and queries (parameterised)
    validators.py             Input validation
    auth.py                   Login + RBAC + account lockout
    records.py                Student record service (validate -> encrypt -> store)
    gui.py                     Tkinter screens
    storage_paths.py          File locations for students.db / keystore.json
  tests/
    test_crypto.py             Unit tests for crypto_utils
    test_records_and_db.py    Integration tests for records/auth/database
    demo_evidence.py          Manual evidence-generation script (not a unit test)
```
