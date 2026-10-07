import tkinter as tk
from tkinter import filedialog, messagebox, ttk
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

AUTO_SAVE_HISTORY = True
SHOW_SCAN_DETAILS = True

# Theme
BG = "#0b1220"
CARD = "#111c2e"
CARD2 = "#17243a"
TEXT = "#f3f6fb"
MUTED = "#9aa8bd"
ACCENT = "#4f8cff"
SUCCESS = "#35c98b"
DANGER = "#ff5c6c"


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
# SCANNER
# =========================

def scan_folder(folder_path):

    quarantine_path = os.path.join(
        folder_path,
        QUARANTINE_FOLDER
    )

    os.makedirs(
        quarantine_path,
        exist_ok=True
    )

    files_to_scan = []

    for root, dirs, files in os.walk(folder_path):

        if QUARANTINE_FOLDER in dirs:
            dirs.remove(QUARANTINE_FOLDER)

        for filename in files:
            files_to_scan.append(
                os.path.join(root, filename)
            )

    total_files = len(files_to_scan)
    files_scanned = 0
    threats = 0

    app.after(
        0,
        lambda: progress_bar.config(
            maximum=max(total_files, 1),
            value=0
        )
    )

    for file_path in files_to_scan:
        if scan_cancelled:
            break

        filename = os.path.basename(file_path)

        if SHOW_SCAN_DETAILS:

            app.after(
                0,
                lambda name=filename:
                status_label.config(
                    text=f"Checking  •  {name}"
                )
            )

        file_hash = get_sha256(file_path)

        files_scanned += 1

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

        app.after(
            0,
            lambda value=files_scanned:
            update_progress(value)
        )

    return files_scanned, threats


def update_progress(value):

    progress_bar.config(
        value=value
    )

    files_label.config(
        text=f"{value:,}"
    )


# =========================
# HISTORY
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

    window = tk.Toplevel(app)

    window.title(
        "HJ SHIELD - Scan History"
    )

    window.geometry(
        "700x460"
    )

    window.configure(
        bg=BG
    )

    tk.Label(
        window,
        text="SCAN HISTORY",
        bg=BG,
        fg=TEXT,
        font=("Arial", 20, "bold")
    ).pack(
        pady=(22, 5)
    )

    tk.Label(
        window,
        text="Previous HJ SHIELD scan results",
        bg=BG,
        fg=MUTED,
        font=("Arial", 10)
    ).pack(
        pady=(0, 12)
    )

    box = tk.Frame(
        window,
        bg=CARD
    )

    box.pack(
        fill="both",
        expand=True,
        padx=25,
        pady=10
    )

    text_box = tk.Text(
        box,
        bg=CARD,
        fg=TEXT,
        insertbackground=TEXT,
        relief="flat",
        font=("Consolas", 10)
    )

    text_box.pack(
        padx=12,
        pady=12,
        fill="both",
        expand=True
    )

    history = ""

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
            "No scan history available yet."
        )

    text_box.config(
        state="disabled"
    )


# =========================
# QUARANTINE
# =========================

def show_quarantine():

    window = tk.Toplevel(app)

    window.title(
        "HJ SHIELD - Quarantine"
    )

    window.geometry(
        "650x440"
    )

    window.configure(
        bg=BG
    )

    tk.Label(
        window,
        text="QUARANTINE MANAGER",
        bg=BG,
        fg=TEXT,
        font=("Arial", 20, "bold")
    ).pack(
        pady=(22, 5)
    )

    tk.Label(
        window,
        text="Isolated files",
        bg=BG,
        fg=MUTED,
        font=("Arial", 10)
    ).pack(
        pady=(0, 12)
    )

    frame = tk.Frame(
        window,
        bg=CARD
    )

    frame.pack(
        padx=25,
        pady=5,
        fill="both",
        expand=True
    )

    listbox = tk.Listbox(
        frame,
        bg=CARD,
        fg=TEXT,
        selectbackground=ACCENT,
        selectforeground="white",
        relief="flat",
        font=("Consolas", 10)
    )

    listbox.pack(
        padx=12,
        pady=12,
        fill="both",
        expand=True
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

        try:

            for filename in os.listdir(
                quarantine_path
            ):

                listbox.insert(
                    tk.END,
                    filename
                )

        except Exception:
            pass

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

                os.remove(
                    file_path
                )

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
        window,
        bg=BG
    )

    buttons.pack(
        pady=15
    )

    tk.Button(
        buttons,
        text="↩  Restore",
        width=16,
        command=restore_file,
        bg=CARD2,
        fg=TEXT,
        activebackground=ACCENT,
        activeforeground="white",
        relief="flat",
        font=("Arial", 10, "bold")
    ).pack(
        side="left",
        padx=6
    )

    tk.Button(
        buttons,
        text="Delete",
        width=16,
        command=delete_file,
        bg=DANGER,
        fg="white",
        activebackground=DANGER,
        relief="flat",
        font=("Arial", 10, "bold")
    ).pack(
        side="left",
        padx=6
    )

    refresh()


# =========================
# PROTECTION STATUS
# =========================

def show_protection_status():

    window = tk.Toplevel(app)

    window.title(
        "HJ SHIELD - Protection Status"
    )

    window.geometry(
        "540x390"
    )

    window.configure(
        bg=BG
    )

    tk.Label(
        window,
        text="PROTECTION STATUS",
        bg=BG,
        fg=TEXT,
        font=("Arial", 20, "bold")
    ).pack(
        pady=(25, 8)
    )

    tk.Label(
        window,
        text="●  HJ SHIELD ENGINE",
        bg=BG,
        fg=SUCCESS,
        font=("Arial", 14, "bold")
    ).pack(
        pady=8
    )

    card = tk.Frame(
        window,
        bg=CARD
    )

    card.pack(
        fill="x",
        padx=35,
        pady=12
    )

    rows = [
        ("Engine status", "ACTIVE"),
        ("Detection", "SHA-256 signatures"),
        ("Quarantine", "ENABLED"),
        ("Real-time protection", "NOT AVAILABLE")
    ]

    for label, value in rows:

        row = tk.Frame(
            card,
            bg=CARD
        )

        row.pack(
            fill="x",
            padx=18,
            pady=9
        )

        tk.Label(
            row,
            text=label,
            bg=CARD,
            fg=MUTED,
            font=("Arial", 10)
        ).pack(
            side="left"
        )

        tk.Label(
            row,
            text=value,
            bg=CARD,
            fg=SUCCESS if value in
            ("ACTIVE", "ENABLED") else TEXT,
            font=("Arial", 10, "bold")
        ).pack(
            side="right"
        )

    tk.Label(
        window,
        text="Learning prototype — not a full antivirus.",
        bg=BG,
        fg=MUTED,
        font=("Arial", 9)
    ).pack(
        pady=15
    )


# =========================
# SETTINGS
# =========================

def show_settings():

    window = tk.Toplevel(app)

    window.title(
        "HJ SHIELD - Settings"
    )

    window.geometry(
        "540x430"
    )

    window.configure(
        bg=BG
    )

    tk.Label(
        window,
        text="SETTINGS",
        bg=BG,
        fg=TEXT,
        font=("Arial", 20, "bold")
    ).pack(
        pady=(22, 15)
    )

    card = tk.Frame(
        window,
        bg=CARD
    )

    card.pack(
        fill="x",
        padx=35,
        pady=5
    )

    history_var = tk.BooleanVar(
        value=AUTO_SAVE_HISTORY
    )

    details_var = tk.BooleanVar(
        value=SHOW_SCAN_DETAILS
    )

    tk.Label(
        card,
        text="SCAN SETTINGS",
        bg=CARD,
        fg=ACCENT,
        font=("Arial", 11, "bold")
    ).pack(
        anchor="w",
        padx=20,
        pady=(18, 8)
    )

    tk.Checkbutton(
        card,
        text="Automatically save scan history",
        variable=history_var,
        bg=CARD,
        fg=TEXT,
        selectcolor=CARD2,
        activebackground=CARD,
        activeforeground=TEXT,
        font=("Arial", 10)
    ).pack(
        anchor="w",
        padx=20,
        pady=7
    )

    tk.Checkbutton(
        card,
        text="Show files while scanning",
        variable=details_var,
        bg=CARD,
        fg=TEXT,
        selectcolor=CARD2,
        activebackground=CARD,
        activeforeground=TEXT,
        font=("Arial", 10)
    ).pack(
        anchor="w",
        padx=20,
        pady=(7, 18)
    )

    tk.Label(
        card,
        text="QUARANTINE",
        bg=CARD,
        fg=ACCENT,
        font=("Arial", 11, "bold")
    ).pack(
        anchor="w",
        padx=20,
        pady=(8, 4)
    )

    tk.Label(
        card,
        text="Quarantine protection: ENABLED",
        bg=CARD,
        fg=SUCCESS,
        font=("Arial", 10)
    ).pack(
        anchor="w",
        padx=20,
        pady=(0, 18)
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

    tk.Button(
        window,
        text="Apply Settings",
        width=22,
        command=apply_settings,
        bg=ACCENT,
        fg="white",
        activebackground=ACCENT,
        relief="flat",
        font=("Arial", 10, "bold")
    ).pack(
        pady=18
    )


# =========================
# START SCAN
# =========================

def get_windows_drives():
    """Return available Windows drive roots such as C:\\ and D:\\."""
    drives = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            drives.append(drive)
    return drives


def scan_whole_pc():
    """Scan accessible Windows drives without following directory links."""
    drives = get_windows_drives()
    files_scanned = 0
    threats = 0

    app_dir = os.path.abspath(os.path.dirname(__file__))
    quarantine_path = os.path.abspath(
        os.path.join(os.getcwd(), QUARANTINE_FOLDER)
    )
    os.makedirs(quarantine_path, exist_ok=True)

    for drive in drives:
        for root, dirs, files in os.walk(drive, topdown=True, onerror=lambda e: None):
            root_abs = os.path.abspath(root)

            # Do not scan HJ SHIELD's own working folder or its quarantine.
            filtered_dirs = []
            for d in dirs:
                child = os.path.abspath(os.path.join(root, d))
                try:
                    if os.path.commonpath([child, app_dir]) == app_dir:
                        continue
                    if os.path.commonpath([child, quarantine_path]) == quarantine_path:
                        continue
                except ValueError:
                    pass

                # Avoid following symbolic links/junction-like links where possible.
                if os.path.islink(child):
                    continue
                filtered_dirs.append(d)
            dirs[:] = filtered_dirs

            for filename in files:
                file_path = os.path.join(root_abs, filename)

                if SHOW_SCAN_DETAILS:
                    app.after(
                        0,
                        lambda name=filename, folder=root_abs:
                        status_label.config(
                            text=f"Checking  •  {name}"
                        )
                    )

                file_hash = get_sha256(file_path)
                files_scanned += 1

                if file_hash in THREAT_HASHES:
                    threats += 1
                    try:
                        destination = os.path.join(quarantine_path, filename)

                        if os.path.exists(destination):
                            name, ext = os.path.splitext(filename)
                            destination = os.path.join(
                                quarantine_path,
                                name + "_quarantined" + ext
                            )

                        shutil.move(file_path, destination)
                    except Exception:
                        pass

                app.after(
                    0,
                    lambda value=files_scanned:
                    update_progress(value)
                )

    return files_scanned, threats


def stop_scan():
    global scan_cancelled
    scan_cancelled=True


def start_scan():
    drives = get_windows_drives()

    if not drives:
        messagebox.showerror(
            "HJ SHIELD",
            "Koi Windows drive available nahi mili."
        )
        return

    confirm = messagebox.askyesno(
        "HJ SHIELD - Whole PC Scan",
        "HJ SHIELD available Windows drives ko scan karega.\n\n"
        + "Drives: " + ", ".join(drives)
        + "\n\nScan start karna hai?"
    )

    if not confirm:
        return

    scan_button.config(state="disabled")

    status_label.config(
        text="Preparing whole PC scan...",
        fg=MUTED
    )

    status_dot.config(
        text="● SCANNING",
        fg=ACCENT
    )

    files_label.config(text="0")
    threats_label.config(text="0")

    progress_bar.stop()
    progress_bar.config(mode="indeterminate")
    progress_bar.start(12)

    def worker():
        try:
            files_scanned, threats = scan_whole_pc()
            app.after(
                0,
                lambda: finish_scan(files_scanned, threats)
            )
        except Exception as e:
            app.after(
                0,
                lambda error=str(e): finish_scan_with_error(error)
            )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


def finish_scan_with_error(error):
    progress_bar.stop()
    progress_bar.config(mode="determinate", maximum=1, value=0)
    status_label.config(
        text="Scan stopped بسبب an unexpected error",
        fg=DANGER
    )
    status_dot.config(
        text="● SCAN ERROR",
        fg=DANGER
    )
    scan_button.config(state="normal")
    messagebox.showerror("HJ SHIELD", f"Scan error:\n{error}")



def finish_scan(
    files_scanned,
    threats
):

    files_label.config(
        text=f"{files_scanned:,}"
    )

    threats_label.config(
        text=str(threats)
    )

    if threats == 0:

        status_label.config(
            text="Scan complete  •  No threats found",
            fg=SUCCESS
        )

        status_dot.config(
            text="● PROTECTED",
            fg=SUCCESS
        )

    else:

        status_label.config(
            text=f"Scan complete  •  {threats} threat(s) found",
            fg=DANGER
        )

        status_dot.config(
            text="● ACTION REQUIRED",
            fg=DANGER
        )

    save_history(
        files_scanned,
        threats
    )

    scan_button.config(
        state="normal"
    )


# =========================
# MAIN GUI
# =========================

app = tk.Tk()

app.title(
    "HJ SHIELD"
)

app.geometry(
    "650x720"
)

app.resizable(
    False,
    False
)

app.configure(
    bg=BG
)


# Header

header = tk.Frame(
    app,
    bg=BG
)

header.pack(
    fill="x",
    padx=32,
    pady=(28, 5)
)

tk.Label(
    header,
    text="HJ SHIELD",
    bg=BG,
    fg=TEXT,
    font=("Arial", 28, "bold")
).pack(
    anchor="w"
)

tk.Label(
    header,
    text="Windows Security Prototype",
    bg=BG,
    fg=MUTED,
    font=("Arial", 10)
).pack(
    anchor="w"
)


# Protection Card

protection_card = tk.Frame(
    app,
    bg=CARD
)

protection_card.pack(
    fill="x",
    padx=32,
    pady=22
)

status_dot = tk.Label(
    protection_card,
    text="● PROTECTED",
    bg=CARD,
    fg=SUCCESS,
    font=("Arial", 13, "bold")
)

status_dot.pack(
    anchor="w",
    padx=22,
    pady=(18, 3)
)

tk.Label(
    protection_card,
    text="Manual scanning is ready",
    bg=CARD,
    fg=MUTED,
    font=("Arial", 10)
).pack(
    anchor="w",
    padx=22,
    pady=(0, 18)
)


# Scan Button

stop_button = tk.Button(
    app,
    text="STOP SCAN",
    width=28,
    height=2,
    bg=DANGER,
    fg="white",
    activebackground=DANGER,
    activeforeground="white",
    relief="flat",
    font=("Arial", 13, "bold"),
    command=stop_scan
)

stop_button.pack(pady=4)
stop_button.config(state="disabled")

scan_button = tk.Button(
    app,
    text="SCAN NOW",
    width=28,
    height=2,
    bg=ACCENT,
    fg="white",
    activebackground=ACCENT,
    activeforeground="white",
    relief="flat",
    font=("Arial", 13, "bold"),
    command=start_scan
)

scan_button.pack(
    pady=4
)


status_label = tk.Label(
    app,
    text="Ready to scan a folder",
    bg=BG,
    fg=MUTED,
    font=("Arial", 10)
)

status_label.pack(
    pady=(10, 8)
)


# Progress Bar

style = ttk.Style()

try:
    style.theme_use("clam")
except tk.TclError:
    pass

style.configure(
    "HJ.Horizontal.TProgressbar",
    troughcolor=CARD2,
    background=ACCENT,
    bordercolor=CARD2,
    lightcolor=ACCENT,
    darkcolor=ACCENT
)

progress_bar = ttk.Progressbar(
    app,
    orient="horizontal",
    length=500,
    mode="determinate",
    style="HJ.Horizontal.TProgressbar"
)

progress_bar.pack(
    pady=(2, 18)
)


# Statistics

stats = tk.Frame(
    app,
    bg=BG
)

stats.pack(
    fill="x",
    padx=32,
    pady=3
)


files_card = tk.Frame(
    stats,
    bg=CARD
)

files_card.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(0, 7)
)

tk.Label(
    files_card,
    text="FILES SCANNED",
    bg=CARD,
    fg=MUTED,
    font=("Arial", 9, "bold")
).pack(
    pady=(16, 3)
)

files_label = tk.Label(
    files_card,
    text="0",
    bg=CARD,
    fg=TEXT,
    font=("Arial", 17, "bold")
)

files_label.pack(
    pady=(0, 16)
)


threats_card = tk.Frame(
    stats,
    bg=CARD
)

threats_card.pack(
    side="right",
    fill="both",
    expand=True,
    padx=(7, 0)
)

tk.Label(
    threats_card,
    text="THREATS",
    bg=CARD,
    fg=MUTED,
    font=("Arial", 9, "bold")
).pack(
    pady=(16, 3)
)

threats_label = tk.Label(
    threats_card,
    text="0",
    bg=CARD,
    fg=TEXT,
    font=("Arial", 17, "bold")
)

threats_label.pack(
    pady=(0, 16)
)


# Tools

tools = tk.Frame(
    app,
    bg=BG
)

tools.pack(
    fill="x",
    padx=32,
    pady=20
)


def tool_button(
    parent,
    text,
    command
):

    return tk.Button(
        parent,
        text=text,
        command=command,
        width=20,
        height=2,
        bg=CARD2,
        fg=TEXT,
        activebackground=ACCENT,
        activeforeground="white",
        relief="flat",
        font=("Arial", 10, "bold")
    )


tool_button(
    tools,
    "QUARANTINE",
    show_quarantine
).grid(
    row=0,
    column=0,
    padx=5,
    pady=5
)

tool_button(
    tools,
    "SCAN HISTORY",
    show_history
).grid(
    row=0,
    column=1,
    padx=5,
    pady=5
)

tool_button(
    tools,
    "PROTECTION",
    show_protection_status
).grid(
    row=1,
    column=0,
    padx=5,
    pady=5
)

tool_button(
    tools,
    "SETTINGS",
    show_settings
).grid(
    row=1,
    column=1,
    padx=5,
    pady=5
)


# Footer

tk.Label(
    app,
    text="HJ SHIELD  •  Learning Project",
    bg=BG,
    fg=MUTED,
    font=("Arial", 9)
).pack(
    side="bottom",
    pady=14
)


app.mainloop()