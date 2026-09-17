"""
Entry point for the Secure Student Record Management system.

Run with:
    python main.py

On first run you will be asked to create a master password (this
generates and wraps the AES-256 Data Encryption Key) and then to
create the first administrator account. On every later run you supply
the master password to unlock the DEK, then log in with a normal user
account.
"""
from app.gui import main

if __name__ == "__main__":
    main()
