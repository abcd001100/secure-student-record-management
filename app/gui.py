"""
gui.py
------
Tkinter desktop interface for the Secure Student Record Management
system. The GUI is intentionally thin: every screen calls into
records.py / auth.py / crypto_utils.py and only ever displays the
results. No cryptographic code lives in this file.

Screens, in order of use:
  1. MasterPasswordScreen  - create the keystore on first run, or
     unlock the existing DEK on every later run.
  2. LoginScreen           - authenticate an individual user account.
  3. Dashboard             - list of students (non-sensitive columns
     only) with buttons for the actions the logged-in role is allowed
     to perform.
  4. StudentFormDialog     - add / edit a student record.
  5. StudentViewDialog     - decrypt and display one record's sensitive
     fields on demand (never all at once).
  6. UserManagementDialog  - admin-only: create staff/admin accounts
     and reactivate locked ones.
  7. AuditLogDialog        - admin-only: read-only view of audit_log.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from . import auth, crypto_utils, records, storage_paths, validators
from .auth import AuthError, Session
from .database import Database


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Student Record Management")
        self.geometry("900x520")
        self.minsize(760, 440)

        self.db = Database(storage_paths.DB_PATH)
        self.dek: bytes | None = None
        self.session: Session | None = None

        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)

        self._show_master_password_screen()

    # ------------------------------------------------------------------
    def _clear(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def _show_master_password_screen(self):
        self._clear()
        first_run = not storage_paths.keystore_exists()
        frame = ttk.Frame(self.container, padding=40)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        title = "Create master password" if first_run else "Unlock encryption key"
        ttk.Label(frame, text=title, font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 15))

        ttk.Label(frame, text="Master password:").grid(row=1, column=0, sticky="e", pady=5)
        pwd_var = tk.StringVar()
        pwd_entry = ttk.Entry(frame, textvariable=pwd_var, show="*", width=30)
        pwd_entry.grid(row=1, column=1, pady=5)
        pwd_entry.focus()

        confirm_var = tk.StringVar()
        if first_run:
            ttk.Label(frame, text="Confirm password:").grid(row=2, column=0, sticky="e", pady=5)
            ttk.Entry(frame, textvariable=confirm_var, show="*", width=30).grid(row=2, column=1, pady=5)

        status = ttk.Label(frame, text="", foreground="red")
        status.grid(row=3, column=0, columnspan=2)

        def submit(event=None):
            pwd = pwd_var.get()
            if first_run:
                try:
                    validators.validate_password_strength(pwd)
                except validators.ValidationError as exc:
                    status.config(text=str(exc))
                    return
                if pwd != confirm_var.get():
                    status.config(text="Passwords do not match.")
                    return
                keystore = crypto_utils.create_keystore(pwd)
                storage_paths.save_keystore(keystore)
                self.dek = crypto_utils.unlock_keystore(pwd, keystore)
                self.db.log(None, "KEYSTORE", detail="created", success=True)
                messagebox.showinfo("Setup complete", "Master password created. Create an admin account next.")
                self._show_first_admin_screen()
            else:
                keystore = storage_paths.load_keystore()
                try:
                    self.dek = crypto_utils.unlock_keystore(pwd, keystore)
                except crypto_utils.CryptoError:
                    self.db.log(None, "KEYSTORE", detail="wrong master password", success=False)
                    status.config(text="Incorrect master password.")
                    return
                self.db.log(None, "KEYSTORE", detail="unlocked", success=True)
                if self.db.user_count() == 0:
                    # The keystore was created on a previous run, but no
                    # account was ever finished (e.g. the app was closed
                    # during first-run setup). Route back to admin
                    # creation instead of a login screen nobody can use.
                    self._show_first_admin_screen()
                else:
                    self._show_login_screen()

        ttk.Button(frame, text="Continue", command=submit).grid(row=4, column=0, columnspan=2, pady=(15, 0))
        self.bind("<Return>", submit)

    def _show_first_admin_screen(self):
        self._clear()
        self.unbind("<Return>")  # clear the master-password screen's stale Enter binding
        frame = ttk.Frame(self.container, padding=40)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(frame, text="Create the first administrator account", font=("Segoe UI", 14, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 15)
        )
        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky="e", pady=5)
        user_var = tk.StringVar()
        ttk.Entry(frame, textvariable=user_var).grid(row=1, column=1, pady=5)
        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky="e", pady=5)
        pwd_var = tk.StringVar()
        ttk.Entry(frame, textvariable=pwd_var, show="*").grid(row=2, column=1, pady=5)
        status = ttk.Label(frame, text="", foreground="red")
        status.grid(row=3, column=0, columnspan=2)

        def submit():
            try:
                auth.create_user(self.db, user_var.get(), pwd_var.get(), "admin")
            except (validators.ValidationError, Exception) as exc:
                status.config(text=str(exc))
                return
            messagebox.showinfo("Account created", "Administrator account created. Please log in.")
            self._show_login_screen()

        ttk.Button(frame, text="Create account", command=submit).grid(row=4, column=0, columnspan=2, pady=(15, 0))

    def _show_login_screen(self):
        self._clear()
        self.unbind("<Return>")
        frame = ttk.Frame(self.container, padding=40)
        frame.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(frame, text="Sign in", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 15))
        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky="e", pady=5)
        user_var = tk.StringVar()
        ttk.Entry(frame, textvariable=user_var).grid(row=1, column=1, pady=5)
        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky="e", pady=5)
        pwd_var = tk.StringVar()
        pwd_entry = ttk.Entry(frame, textvariable=pwd_var, show="*")
        pwd_entry.grid(row=2, column=1, pady=5)
        status = ttk.Label(frame, text="", foreground="red")
        status.grid(row=3, column=0, columnspan=2)

        def submit(event=None):
            try:
                self.session = auth.login(self.db, user_var.get().strip(), pwd_var.get())
            except AuthError as exc:
                status.config(text=str(exc))
                return
            self._show_dashboard()

        ttk.Button(frame, text="Log in", command=submit).grid(row=4, column=0, columnspan=2, pady=(15, 0))
        self.bind("<Return>", submit)
        pwd_entry.focus()

    # ------------------------------------------------------------------
    def _show_dashboard(self):
        self._clear()
        self.unbind("<Return>")
        top = ttk.Frame(self.container, padding=10)
        top.pack(fill="x")
        ttk.Label(
            top, text=f"Logged in as {self.session.username} ({self.session.role})",
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left")
        ttk.Button(top, text="Log out", command=self._show_login_screen).pack(side="right")

        toolbar = ttk.Frame(self.container, padding=(10, 0))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Add student", command=self._open_add_dialog).pack(side="left", padx=3)
        ttk.Button(toolbar, text="View / Decrypt", command=self._open_view_dialog).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Edit", command=self._open_edit_dialog).pack(side="left", padx=3)
        ttk.Button(toolbar, text="Delete", command=self._delete_selected).pack(side="left", padx=3)
        if self.session.is_admin:
            ttk.Button(toolbar, text="Manage users", command=self._open_user_management).pack(side="left", padx=3)
            ttk.Button(toolbar, text="Audit log", command=self._open_audit_log).pack(side="left", padx=3)

        columns = ("student_id", "full_name", "program", "intake", "created_by", "updated_at")
        self.tree = ttk.Treeview(self.container, columns=columns, show="headings")
        for col, label, width in zip(
            columns,
            ("Student ID", "Full name", "Program", "Intake", "Added by", "Last updated"),
            (110, 160, 160, 90, 100, 160),
        ):
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

        note = ttk.Label(
            self.container,
            text="IC/passport number, phone, address, guardian contact and remarks are encrypted "
                 "(AES-256-GCM) and are only shown after using 'View / Decrypt'.",
            foreground="#555555",
        )
        note.pack(fill="x", padx=10, pady=(0, 8))

        self._refresh_table()

    def _refresh_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for s in records.list_students(self.db):
            self.tree.insert("", "end", iid=s.student_id, values=(
                s.student_id, s.full_name, s.program, s.intake or "", s.created_by, s.updated_at or "-",
            ))

    def _selected_student_id(self) -> str | None:
        sel = self.tree.selection()
        return sel[0] if sel else None

    # -- dialogs ---------------------------------------------------------
    def _open_add_dialog(self):
        StudentFormDialog(self, mode="add")

    def _open_edit_dialog(self):
        sid = self._selected_student_id()
        if not sid:
            messagebox.showwarning("No selection", "Select a student row first.")
            return
        StudentFormDialog(self, mode="edit", student_id=sid)

    def _open_view_dialog(self):
        sid = self._selected_student_id()
        if not sid:
            messagebox.showwarning("No selection", "Select a student row first.")
            return
        try:
            view = records.view_student(self.db, self.dek, self.session, sid)
        except crypto_utils.CryptoError as exc:
            messagebox.showerror("Integrity check failed", str(exc))
            return
        StudentViewDialog(self, view)

    def _delete_selected(self):
        sid = self._selected_student_id()
        if not sid:
            messagebox.showwarning("No selection", "Select a student row first.")
            return
        if not messagebox.askyesno("Confirm delete", f"Permanently delete {sid}?"):
            return
        try:
            records.delete_student(self.db, self.session, sid)
        except AuthError as exc:
            messagebox.showerror("Not allowed", str(exc))
            return
        self._refresh_table()

    def _open_user_management(self):
        UserManagementDialog(self)

    def _open_audit_log(self):
        AuditLogDialog(self)


class StudentFormDialog(tk.Toplevel):
    FIELDS = [
        ("student_id", "Student ID"),
        ("full_name", "Full name"),
        ("program", "Program"),
        ("intake", "Intake (e.g. Sem3 2025-2026)"),
        ("ic_passport_no", "IC / Passport number"),
        ("phone", "Phone number"),
        ("address", "Address"),
        ("guardian_contact", "Guardian contact"),
        ("remarks", "Remarks (medical / academic notes)"),
    ]

    def __init__(self, app: App, mode: str, student_id: str | None = None):
        super().__init__(app)
        self.app = app
        self.mode = mode
        self.title("Add student" if mode == "add" else f"Edit {student_id}")
        self.geometry("420x430")
        self.vars: dict[str, tk.StringVar] = {}

        prefill = None
        if mode == "edit":
            prefill = records.view_student(app.db, app.dek, app.session, student_id)

        for row, (key, label) in enumerate(self.FIELDS):
            ttk.Label(self, text=label + ":").grid(row=row, column=0, sticky="ne", padx=8, pady=4)
            var = tk.StringVar()
            if prefill is not None:
                var.set(getattr(prefill, key))
            entry = ttk.Entry(self, textvariable=var, width=30)
            entry.grid(row=row, column=1, pady=4, sticky="w")
            if key == "student_id" and mode == "edit":
                entry.config(state="disabled")
            self.vars[key] = var

        self.status = ttk.Label(self, text="", foreground="red", wraplength=380)
        self.status.grid(row=len(self.FIELDS), column=0, columnspan=2, pady=6)

        ttk.Button(self, text="Save", command=self._save).grid(
            row=len(self.FIELDS) + 1, column=0, columnspan=2, pady=8
        )

    def _save(self):
        data = records.StudentInput(**{k: v.get() for k, v in self.vars.items()})
        try:
            if self.mode == "add":
                records.add_student(self.app.db, self.app.dek, self.app.session, data)
            else:
                records.update_student(self.app.db, self.app.dek, self.app.session, data)
        except (validators.ValidationError, Exception) as exc:
            self.status.config(text=str(exc))
            return
        self.app._refresh_table()
        self.destroy()


class StudentViewDialog(tk.Toplevel):
    def __init__(self, app: App, view: records.StudentView):
        super().__init__(app)
        self.title(f"Student record: {view.student_id}")
        self.geometry("420x380")
        rows = [
            ("Student ID", view.student_id),
            ("Full name", view.full_name),
            ("Program", view.program),
            ("Intake", view.intake),
            ("IC / Passport", view.ic_passport_no),
            ("Phone", view.phone),
            ("Address", view.address),
            ("Guardian contact", view.guardian_contact),
            ("Remarks", view.remarks),
            ("Added by", view.created_by),
            ("Created at", view.created_at),
            ("Last updated", view.updated_at or "-"),
        ]
        for i, (label, value) in enumerate(rows):
            ttk.Label(self, text=label + ":", font=("Segoe UI", 9, "bold")).grid(
                row=i, column=0, sticky="ne", padx=8, pady=3
            )
            ttk.Label(self, text=value, wraplength=260, justify="left").grid(
                row=i, column=1, sticky="w", padx=4, pady=3
            )
        ttk.Button(self, text="Close", command=self.destroy).grid(row=len(rows), column=0, columnspan=2, pady=8)


class UserManagementDialog(tk.Toplevel):
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app
        self.title("Manage user accounts")
        self.geometry("480x360")

        form = ttk.LabelFrame(self, text="Create new account", padding=10)
        form.pack(fill="x", padx=10, pady=10)
        ttk.Label(form, text="Username:").grid(row=0, column=0, sticky="e")
        user_var = tk.StringVar()
        ttk.Entry(form, textvariable=user_var).grid(row=0, column=1, padx=4)
        ttk.Label(form, text="Password:").grid(row=1, column=0, sticky="e")
        pwd_var = tk.StringVar()
        ttk.Entry(form, textvariable=pwd_var, show="*").grid(row=1, column=1, padx=4)
        ttk.Label(form, text="Role:").grid(row=2, column=0, sticky="e")
        role_var = tk.StringVar(value="staff")
        ttk.Combobox(form, textvariable=role_var, values=["staff", "admin"], state="readonly", width=17).grid(
            row=2, column=1, padx=4
        )
        status = ttk.Label(form, text="", foreground="red")
        status.grid(row=3, column=0, columnspan=2)

        def create():
            try:
                auth.create_user(app.db, user_var.get().strip(), pwd_var.get(), role_var.get())
            except Exception as exc:
                status.config(text=str(exc))
                return
            refresh_list()
            user_var.set("")
            pwd_var.set("")

        ttk.Button(form, text="Create", command=create).grid(row=4, column=0, columnspan=2, pady=6)

        list_frame = ttk.LabelFrame(self, text="Existing accounts", padding=10)
        list_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        columns = ("username", "role", "status")
        tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=6)
        for col, label, width in zip(columns, ("Username", "Role", "Status"), (140, 80, 90)):
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="w")
        tree.pack(fill="both", expand=True)

        def refresh_list():
            for row in tree.get_children():
                tree.delete(row)
            for u in app.db.list_users():
                status_txt = "active" if u.is_active else "LOCKED"
                tree.insert("", "end", iid=u.username, values=(u.username, u.role, status_txt))

        def reactivate_selected():
            sel = tree.selection()
            if not sel:
                status.config(foreground="red", text="Select an account first.")
                return
            try:
                auth.reactivate_user(app.db, app.session, sel[0])
            except Exception as exc:
                status.config(foreground="red", text=str(exc))
                return
            status.config(foreground="green", text=f"'{sel[0]}' reactivated.")
            refresh_list()

        ttk.Button(list_frame, text="Reactivate selected account", command=reactivate_selected).pack(
            pady=(6, 0)
        )

        refresh_list()


class AuditLogDialog(tk.Toplevel):
    def __init__(self, app: App):
        super().__init__(app)
        self.title("Audit log (most recent 200 events)")
        self.geometry("720x400")
        columns = ("ts", "username", "action", "target", "detail", "success")
        tree = ttk.Treeview(self, columns=columns, show="headings")
        for col, label, width in zip(
            columns, ("Timestamp", "User", "Action", "Target", "Detail", "OK"), (170, 100, 120, 100, 180, 40)
        ):
            tree.heading(col, text=label)
            tree.column(col, width=width, anchor="w")
        tree.pack(fill="both", expand=True, padx=10, pady=10)
        for row in app.db.recent_log():
            tree.insert("", "end", values=(
                row["ts"], row["username"] or "-", row["action"], row["target"] or "-",
                row["detail"] or "", "Yes" if row["success"] else "No",
            ))


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
