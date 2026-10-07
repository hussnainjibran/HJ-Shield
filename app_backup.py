import tkinter as tk
from tkinter import filedialog, messagebox
import os
import hashlib
import shutil
import threading
from datetime import datetime

# =========================
# HJ SHIELD
# =========================

THREAT_HASHES = {
    "26b527c6debff9ce8cb0fc19b8b88840bc86f7203971b02973d6d824f0c54fe3"
}

QUARANTINE_FOLDER = "quarantine"
HISTORY_FILE = "scan_history.txt"

# Settings
AUTO_SAVE_HISTORY = True
SHOW_SCAN_DETAILS = True


# =========================
# SHA-256
# =========================

def get_sha256(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while True:
                data = f.read(1024 * 1024)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except Exception:
        return None


# =========================
# Scan
# =========================

def scan_folder(folder_path):

    threats = 0
    files_scanned = 0

    quarantine_path = os.path.join(
        folder_path,
        QUARANTINE_FOLDER
    )

    os.makedirs(quarantine_path, exist_ok=True)

    for root, dirs, files in os.walk(folder_path):

        if QUARANTINE_FOLDER in dirs:
            dirs.remove(QUARANTINE_FOLDER)

        for filename in files:

            file_path = os.path.join(root, filename)

            files_scanned += 1

            if SHOW_SCAN_DETAILS:
                app.after(
                    0,
                    lambda name=filename:
                    status_label.config(
                        text=f"🔍 Checking: {name}"
                    )
                )

            file_hash = get_sha256(file_path)

            if file_hash in THREAT_HASHES:

                threats += 1

                try:
                    destination = os.path.join(
                        quarantine_path,
                        filename
                    )

                    if os.path.exists(destination):

                        name, ext = os.path.splitext(filename)

                        destination = os.path.join(
                            quarantine_path,
                            name + "_quarantined" + ext
                        )

                    shutil.move(
                        file_path,
                        destination
                    )

                except Exception:
                    pass

    return files_scanned, threats


# =========================
# History
# =========================

def save_history(files_scanned, threats):

    if not AUTO_SAVE_HISTORY:
        return

    now = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    with open(
        HISTORY_FILE,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            f"{now} | Files scanned: "
            f"{files_scanned} | Threats: {threats}\n"
        )


def show_history():

    history_window = tk.Toplevel(app)

    history_window.title(
        "HJ SHIELD - Scan History"
    )

    history_window.geometry(
        "650x400"
    )

    tk.Label(
        history_window,
        text="📊 Scan History",
        font=("Arial", 18, "bold")
    ).pack(pady=15)

    text_box = tk.Text(
        history_window,
        width=75,
        height=18,
        font=("Consolas", 10)
    )

    text_box.pack(
        padx=15,
        pady=10
    )

    if os.path.exists(HISTORY_FILE):

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            history = f.read()

        if history.strip():

            text_box.insert(
                "1.0",
                history
            )

        else:

            text_box.insert(
                "1.0",
                "Abhi koi scan history nahi hai."
            )

    else:

        text_box.insert(
            "1.0",
            "Abhi koi scan history nahi hai."
        )

    text_box.config(
        state="disabled"
    )


# =========================
# Quarantine
# =========================

def show_quarantine():

    quarantine_window = tk.Toplevel(app)

    quarantine_window.title(
        "HJ SHIELD - Quarantine"
    )

    quarantine_window.geometry(
        "600x400"
    )

    tk.Label(
        quarantine_window,
        text="🔒 Quarantine Manager",
        font=("Arial", 18, "bold")
    ).pack(pady=15)

    listbox = tk.Listbox(
        quarantine_window,
        width=70,
        height=12
    )

    listbox.pack(
        padx=15,
        pady=10
    )

    quarantine_path = os.path.join(
        os.getcwd(),
        QUARANTINE_FOLDER
    )

    os.makedirs(
        quarantine_path,
        exist_ok=True
    )

    def refresh():

        listbox.delete(
            0,
            tk.END
        )

        for filename in os.listdir(
            quarantine_path
        ):

            listbox.insert(
                tk.END,
                filename
            )

    def restore_file():

        selected = listbox.curselection()

        if not selected:

            messagebox.showwarning(
                "HJ SHIELD",
                "Pehle file select karo."
            )

            return

        filename = listbox.get(
            selected[0]
        )

        source = os.path.join(
            quarantine_path,
            filename
        )

        destination = os.path.join(
            os.getcwd(),
            filename
        )

        if os.path.exists(destination):

            messagebox.showerror(
                "HJ SHIELD",
                "Same filename already exist karta hai."
            )

            return

        try:

            shutil.move(
                source,
                destination
            )

            refresh()

            messagebox.showinfo(
                "HJ SHIELD",
                "File restore ho gayi."
            )

        except Exception as e:

            messagebox.showerror(
                "Error",
                str(e)
            )

    def delete_file():

        selected = listbox.curselection()

        if not selected:

            messagebox.showwarning(
                "HJ SHIELD",
                "Pehle file select karo."
            )

            return

        filename = listbox.get(
            selected[0]
        )

        file_path = os.path.join(
            quarantine_path,
            filename
        )

        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"{filename}\n\nDelete karna hai?"
        )

        if confirm:

            try:

                os.remove(file_path)

                refresh()

                messagebox.showinfo(
                    "HJ SHIELD",
                    "File delete ho gayi."
                )

            except Exception as e:

                messagebox.showerror(
                    "Error",
                    str(e)
                )

    buttons = tk.Frame(
        quarantine_window
    )

    buttons.pack(
        pady=10
    )

    tk.Button(
        buttons,
        text="↩ Restore",
        width=15,
        command=restore_file
    ).pack(
        side="left",
        padx=5
    )

    tk.Button(
        buttons,
        text="🗑 Delete",
        width=15,
        command=delete_file
    ).pack(
        side="left",
        padx=5
    )

    refresh()


# =========================
# Protection Status
# =========================

def show_protection_status():

    window = tk.Toplevel(app)

    window.title(
        "HJ SHIELD - Protection Status"
    )

    window.geometry(
        "500x350"
    )

    tk.Label(
        window,
        text="🛡️ Protection Status",
        font=("Arial", 20, "bold")
    ).pack(pady=20)

    tk.Label(
        window,
        text="● HJ SHIELD ENGINE",
        font=("Arial", 14, "bold")
    ).pack(pady=5)

    tk.Label(
        window,
        text="Status: ACTIVE",
        font=("Arial", 13)
    ).pack(pady=5)

    tk.Label(
        window,
        text="Detection: SHA-256 signatures",
        font=("Arial", 11)
    ).pack(pady=5)

    tk.Label(
        window,
        text="Quarantine: ENABLED",
        font=("Arial", 11)
    ).pack(pady=5)

    tk.Label(
        window,
        text="Real-time protection: NOT AVAILABLE",
        font=("Arial", 10)
    ).pack(pady=15)

    tk.Label(
        window,
        text="Learning prototype — not a full antivirus.",
        font=("Arial", 9)
    ).pack()


# =========================
# Settings
# =========================

def show_settings():

    settings_window = tk.Toplevel(app)

    settings_window.title(
        "HJ SHIELD - Settings"
    )

    settings_window.geometry(
        "500x430"
    )

    tk.Label(
        settings_window,
        text="⚙️ Settings",
        font=("Arial", 20, "bold")
    ).pack(pady=20)

    history_var = tk.BooleanVar(
        value=AUTO_SAVE_HISTORY
    )

    details_var = tk.BooleanVar(
        value=SHOW_SCAN_DETAILS
    )

    def apply_settings():

        global AUTO_SAVE_HISTORY
        global SHOW_SCAN_DETAILS

        AUTO_SAVE_HISTORY = history_var.get()
        SHOW_SCAN_DETAILS = details_var.get()

        messagebox.showinfo(
            "HJ SHIELD",
            "Settings successfully apply ho gayi hain."
        )

    tk.Label(
        settings_window,
        text="Scan Settings",
        font=("Arial", 13, "bold")
    ).pack(pady=5)

    tk.Checkbutton(
        settings_window,
        text="📊 Automatically save scan history",
        variable=history_var,
        font=("Arial", 11)
    ).pack(
        anchor="w",
        padx=80,
        pady=8
    )

    tk.Checkbutton(
        settings_window,
        text="🔍 Show files while scanning",
        variable=details_var,
        font=("Arial", 11)
    ).pack(
        anchor="w",
        padx=80,
        pady=8
    )

    tk.Label(
        settings_window,
        text="Quarantine",
        font=("Arial", 13, "bold")
    ).pack(pady=15)

    tk.Label(
        settings_window,
        text="🔒 Quarantine protection: ENABLED",
        font=("Arial", 11)
    ).pack(pady=5)

    tk.Label(
        settings_window,
        text="Quarantine cannot be disabled in this prototype.",
        font=("Arial", 9)
    ).pack(pady=3)

    tk.Button(
        settings_window,
        text="💾 Apply Settings",
        width=20,
        command=apply_settings
    ).pack(pady=20)

    tk.Button(
        settings_window,
        text="Close",
        width=20,
        command=settings_window.destroy
    ).pack()


# =========================
# Start Scan
# =========================

def start_scan():

    folder = filedialog.askdirectory(
        title="Folder select karo"
    )

    if not folder:
        return

    scan_button.config(
        state="disabled"
    )

    status_label.config(
        text="🔍 Scanning..."
    )

    files_label.config(
        text="Files scanned: 0"
    )

    threats_label.config(
        text="Threats: 0"
    )

    def worker():

        files_scanned, threats = scan_folder(
            folder
        )

        app.after(
            0,
            lambda: finish_scan(
                files_scanned,
                threats
            )
        )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


def finish_scan(
    files_scanned,
    threats
):

    files_label.config(
        text=f"Files scanned: {files_scanned}"
    )

    threats_label.config(
        text=f"Threats: {threats}"
    )

    if threats == 0:

        status_label.config(
            text="✅ Scan Complete — No threats found"
        )

    else:

        status_label.config(
            text=f"🚨 Scan Complete — {threats} threat(s) found"
        )

    save_history(
        files_scanned,
        threats
    )

    scan_button.config(
        state="normal"
    )


# =========================
# Main GUI
# =========================

app = tk.Tk()

app.title(
    "HJ SHIELD 🛡️"
)

app.geometry(
    "600x650"
)

app.resizable(
    False,
    False
)


tk.Label(
    app,
    text="🛡️ HJ SHIELD",
    font=("Arial", 28, "bold")
).pack(pady=25)


tk.Label(
    app,
    text="Windows Security Prototype",
    font=("Arial", 12)
).pack()


status_label = tk.Label(
    app,
    text="● Protection Status: Ready",
    font=("Arial", 13)
)

status_label.pack(pady=20)


scan_button = tk.Button(
    app,
    text="🔍 Quick Scan",
    width=25,
    height=2,
    font=("Arial", 12, "bold"),
    command=start_scan
)

scan_button.pack(pady=7)


tk.Button(
    app,
    text="🔒 Quarantine",
    width=25,
    height=2,
    font=("Arial", 12, "bold"),
    command=show_quarantine
).pack(pady=7)


tk.Button(
    app,
    text="📊 Scan History",
    width=25,
    height=2,
    font=("Arial", 12, "bold"),
    command=show_history
).pack(pady=7)


tk.Button(
    app,
    text="🛡️ Protection Status",
    width=25,
    height=2,
    font=("Arial", 12, "bold"),
    command=show_protection_status
).pack(pady=7)


tk.Button(
    app,
    text="⚙️ Settings",
    width=25,
    height=2,
    font=("Arial", 12, "bold"),
    command=show_settings
).pack(pady=7)


files_label = tk.Label(
    app,
    text="Files scanned: 0",
    font=("Arial", 11)
)

files_label.pack(pady=12)


threats_label = tk.Label(
    app,
    text="Threats: 0",
    font=("Arial", 11)
)

threats_label.pack(pady=3)


tk.Label(
    app,
    text="HJ SHIELD • Learning Project",
    font=("Arial", 9)
).pack(
    side="bottom",
    pady=15
)


app.mainloop()