from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk
import os
import hashlib
import shutil
import threading
from datetime import datetime
import json

# ============================================================
# HJ SHIELD — PERSONAL ANTIVIRUS & SECURITY SCANNER
# ============================================================

APP_NAME = "HJ SHIELD"
QUARANTINE_FOLDER = "quarantine"
HISTORY_FILE = "scan_history.txt"
METADATA_FILE = "quarantine_metadata.json"

THREAT_HASHES = {
    "26b527c6debff9ce8cb0fc19b8b88840bc86f7203971b02973d6d824f0c54fe3"
}

SUSPICIOUS_EXTENSIONS = {
    ".scr", ".pif", ".com", ".hta", ".cpl"
}

SUSPICIOUS_NAME_WORDS = {
    "malware", "virus", "trojan", "ransom", "payload"
}

AUTO_SAVE_HISTORY = True
SHOW_SCAN_DETAILS = True

# ============================================================
# GOLD / BLACK THEME
# ============================================================

BG = "#080808"
CARD = "#111111"
CARD2 = "#181818"
BORDER = "#292929"

TEXT = "#F5F5F5"
MUTED = "#969696"

GOLD = "#D6A84F"
GOLD_LIGHT = "#F0C96A"

SUCCESS = "#48C78E"
DANGER = "#E05A5A"

# ============================================================
# GLOBAL STATE
# ============================================================

scan_cancelled = False
scan_running = False
last_scan_time = "Never"
last_scan_files = 0
last_scan_threats = 0


# ============================================================
# HELPERS
# ============================================================

def app_folder():
    return os.path.abspath(os.path.dirname(__file__))


def quarantine_folder():
    path = os.path.join(app_folder(), QUARANTINE_FOLDER)
    os.makedirs(path, exist_ok=True)
    return path


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


def get_windows_drives():
    drives = []

    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        drive = f"{letter}:\\"

        if os.path.exists(drive):
            drives.append(drive)

    return drives


def rule_based_detection(file_path):
    name = Path(file_path).name.lower()
    ext = Path(file_path).suffix.lower()

    if ext in SUSPICIOUS_EXTENSIONS:
        return True

    return any(word in name for word in SUSPICIOUS_NAME_WORDS)


# ============================================================
# QUARANTINE METADATA
# ============================================================

def load_quarantine_metadata():
    try:
        if os.path.exists(METADATA_FILE):
            with open(METADATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)

            return data if isinstance(data, dict) else {}

    except Exception:
        pass

    return {}


def save_quarantine_metadata(data):
    try:
        with open(METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    except Exception:
        pass


def record_quarantine(original, destination, file_hash, reason):
    data = load_quarantine_metadata()

    filename = os.path.basename(destination)

    data[filename] = {
        "original_path": os.path.abspath(original),
        "quarantine_path": os.path.abspath(destination),
        "sha256": file_hash,
        "reason": reason,
        "timestamp": datetime.now().isoformat(timespec="seconds")
    }

    save_quarantine_metadata(data)


# ============================================================
# HISTORY
# ============================================================

def save_history(files_scanned, threats):
    if not AUTO_SAVE_HISTORY:
        return

    now = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    try:
        with open(HISTORY_FILE, "a", encoding="utf-8") as f:
            f.write(
                f"{now} | Files scanned: "
                f"{files_scanned} | Threats: {threats}\n"
            )

    except Exception:
        pass


# ============================================================
# UI HELPERS
# ============================================================

def set_status(text, color=MUTED):
    try:
        status_label.config(text=text, fg=color)
    except Exception:
        pass


def update_cards(files, threats):
    files_label.config(text=f"{files:,}")
    threats_label.config(text=str(threats))


def update_progress(value):
    try:
        progress_bar.config(value=value)
        files_label.config(text=f"{value:,}")
    except Exception:
        pass


# ============================================================
# WHOLE PC SCANNER
# ============================================================

def scan_whole_pc():
    global scan_cancelled

    drives = get_windows_drives()

    files_scanned = 0
    threats = 0

    quarantine_path = quarantine_folder()

    app_dir = os.path.abspath(app_folder())

    for drive in drives:

        if scan_cancelled:
            break

        for root, dirs, files in os.walk(
            drive,
            topdown=True,
            onerror=lambda e: None
        ):

            if scan_cancelled:
                break

            root_abs = os.path.abspath(root)

            filtered_dirs = []

            for directory in dirs:

                child = os.path.abspath(
                    os.path.join(root, directory)
                )

                try:

                    if os.path.commonpath(
                        [child, app_dir]
                    ) == app_dir:
                        continue

                    if os.path.commonpath(
                        [child, quarantine_path]
                    ) == quarantine_path:
                        continue

                except ValueError:
                    pass

                if os.path.islink(child):
                    continue

                filtered_dirs.append(directory)

            dirs[:] = filtered_dirs

            for filename in files:

                if scan_cancelled:
                    break

                file_path = os.path.join(
                    root_abs,
                    filename
                )

                if SHOW_SCAN_DETAILS:
                    app.after(
                        0,
                        lambda name=filename:
                        set_status(
                            f"Checking  •  {name}",
                            GOLD
                        )
                    )

                file_hash = get_sha256(file_path)

                files_scanned += 1

                if (
                    file_hash in THREAT_HASHES
                    or rule_based_detection(file_path)
                ):

                    threats += 1

                    try:

                        destination = os.path.join(
                            quarantine_path,
                            filename
                        )

                        if os.path.exists(destination):

                            name, ext = os.path.splitext(
                                filename
                            )

                            destination = os.path.join(
                                quarantine_path,
                                name + "_quarantined" + ext
                            )

                        shutil.move(
                            file_path,
                            destination
                        )

                        record_quarantine(
                            file_path,
                            destination,
                            file_hash or "unknown",
                            "Signature / rule detection"
                        )

                    except Exception:
                        pass

                app.after(
                    0,
                    lambda value=files_scanned:
                    update_progress(value)
                )

    return files_scanned, threats


# ============================================================
# START / STOP SCAN
# ============================================================

def stop_scan():
    global scan_cancelled

    if not scan_running:
        return

    scan_cancelled = True

    set_status(
        "Stopping scan...",
        GOLD
    )

    stop_button.config(
        state="disabled"
    )


def start_scan():

    global scan_cancelled
    global scan_running

    if scan_running:
        return

    drives = get_windows_drives()

    if not drives:
        messagebox.showerror(
            APP_NAME,
            "No Windows drive was found."
        )
        return

    confirm = messagebox.askyesno(
        "HJ SHIELD — Whole PC Scan",
        "HJ SHIELD will scan the available Windows drives.\n\n"
        + "Drives: "
        + ", ".join(drives)
        + "\n\nStart scan?"
    )

    if not confirm:
        return

    scan_cancelled = False
    scan_running = True

    scan_button.config(
        state="disabled"
    )

    stop_button.config(
        state="normal"
    )

    status_dot.config(
        text="● SCANNING",
        fg=GOLD
    )

    set_status(
        "Preparing whole PC scan...",
        GOLD
    )

    files_label.config(text="0")
    threats_label.config(text="0")

    progress_bar.config(
        mode="indeterminate"
    )

    progress_bar.start(12)

    def worker():

        try:

            files, threats = scan_whole_pc()

            app.after(
                0,
                lambda:
                finish_scan(
                    files,
                    threats
                )
            )

        except Exception as error:

            app.after(
                0,
                lambda:
                finish_scan_error(
                    str(error)
                )
            )

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


def finish_scan(files, threats):

    global scan_running
    global last_scan_time
    global last_scan_files
    global last_scan_threats

    scan_running = False

    last_scan_time = datetime.now().strftime(
        "%H:%M:%S"
    )

    last_scan_files = files
    last_scan_threats = threats

    progress_bar.stop()

    progress_bar.config(
        mode="determinate",
        maximum=max(files, 1),
        value=files
    )

    update_cards(
        files,
        threats
    )

    last_scan_label.config(
        text=last_scan_time
    )

    scan_button.config(
        state="normal"
    )

    stop_button.config(
        state="disabled"
    )

    if scan_cancelled:

        status_dot.config(
            text="● SCAN STOPPED",
            fg=GOLD
        )

        set_status(
            f"Scan stopped  •  {files:,} files checked",
            GOLD
        )

    elif threats == 0:

        status_dot.config(
            text="● PROTECTED",
            fg=SUCCESS
        )

        set_status(
            "Scan complete  •  No threats found",
            SUCCESS
        )

    else:

        status_dot.config(
            text="● ACTION REQUIRED",
            fg=DANGER
        )

        set_status(
            f"Scan complete  •  {threats} threat(s) found",
            DANGER
        )

    save_history(
        files,
        threats
    )


def finish_scan_error(error):

    global scan_running

    scan_running = False

    progress_bar.stop()

    progress_bar.config(
        mode="determinate",
        maximum=1,
        value=0
    )

    scan_button.config(
        state="normal"
    )

    stop_button.config(
        state="disabled"
    )

    status_dot.config(
        text="● SCAN ERROR",
        fg=DANGER
    )

    set_status(
        "Scan stopped because of an error",
        DANGER
    )

    messagebox.showerror(
        APP_NAME,
        f"Scan error:\n{error}"
    )


# ============================================================
# QUARANTINE WINDOW
# ============================================================

def show_quarantine():

    window = tk.Toplevel(app)

    window.title(
        "HJ SHIELD — Quarantine"
    )

    window.geometry(
        "700x500"
    )

    window.configure(
        bg=BG
    )

    tk.Label(
        window,
        text="QUARANTINE",
        bg=BG,
        fg=TEXT,
        font=("Arial", 22, "bold")
    ).pack(
        pady=(25, 5)
    )

    tk.Label(
        window,
        text="Isolated files detected by HJ SHIELD",
        bg=BG,
        fg=MUTED,
        font=("Arial", 10)
    ).pack(
        pady=(0, 15)
    )

    frame = tk.Frame(
        window,
        bg=CARD,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    frame.pack(
        fill="both",
        expand=True,
        padx=30,
        pady=5
    )

    listbox = tk.Listbox(
        frame,
        bg=CARD,
        fg=TEXT,
        selectbackground=GOLD,
        selectforeground="black",
        relief="flat",
        font=("Consolas", 10)
    )

    listbox.pack(
        fill="both",
        expand=True,
        padx=15,
        pady=15
    )

    qpath = quarantine_folder()

    def refresh():

        listbox.delete(
            0,
            tk.END
        )

        try:

            for filename in os.listdir(qpath):

                full = os.path.join(
                    qpath,
                    filename
                )

                if os.path.isfile(full):
                    listbox.insert(
                        tk.END,
                        filename
                    )

        except Exception:
            pass

    def restore():

        selected = listbox.curselection()

        if not selected:
            messagebox.showwarning(
                APP_NAME,
                "Select a file first."
            )
            return

        filename = listbox.get(
            selected[0]
        )

        source = os.path.join(
            qpath,
            filename
        )

        metadata = load_quarantine_metadata()

        entry = metadata.get(
            filename,
            {}
        )

        destination = entry.get(
            "original_path",
            os.path.join(
                Path.home(),
                filename
            )
        )

        if os.path.exists(destination):

            messagebox.showerror(
                APP_NAME,
                "Original location already contains a file with this name."
            )
            return

        try:

            os.makedirs(
                os.path.dirname(destination),
                exist_ok=True
            )

            shutil.move(
                source,
                destination
            )

            metadata.pop(
                filename,
                None
            )

            save_quarantine_metadata(
                metadata
            )

            refresh()

            messagebox.showinfo(
                APP_NAME,
                "File restored."
            )

        except Exception as error:

            messagebox.showerror(
                APP_NAME,
                str(error)
            )

    def delete_file():

        selected = listbox.curselection()

        if not selected:
            messagebox.showwarning(
                APP_NAME,
                "Select a file first."
            )
            return

        filename = listbox.get(
            selected[0]
        )

        path = os.path.join(
            qpath,
            filename
        )

        confirm = messagebox.askyesno(
            "Delete",
            f"{filename}\n\nPermanently delete this quarantined file?"
        )

        if not confirm:
            return

        try:

            os.remove(path)

            metadata = load_quarantine_metadata()

            metadata.pop(
                filename,
                None
            )

            save_quarantine_metadata(
                metadata
            )

            refresh()

        except Exception as error:

            messagebox.showerror(
                APP_NAME,
                str(error)
            )

    buttons = tk.Frame(
        window,
        bg=BG
    )

    buttons.pack(
        pady=18
    )

    tk.Button(
        buttons,
        text="RESTORE",
        width=16,
        command=restore,
        bg=CARD2,
        fg=TEXT,
        activebackground=GOLD,
        activeforeground="black",
        relief="flat",
        font=("Arial", 10, "bold")
    ).pack(
        side="left",
        padx=6
    )

    tk.Button(
        buttons,
        text="DELETE",
        width=16,
        command=delete_file,
        bg="#2A1515",
        fg=DANGER,
        activebackground=DANGER,
        activeforeground="white",
        relief="flat",
        font=("Arial", 10, "bold")
    ).pack(
        side="left",
        padx=6
    )

    refresh()


# ============================================================
# SCAN HISTORY
# ============================================================

def show_history():

    window = tk.Toplevel(app)

    window.title(
        "HJ SHIELD — Scan History"
    )

    window.geometry(
        "700x470"
    )

    window.configure(
        bg=BG
    )

    tk.Label(
        window,
        text="SCAN HISTORY",
        bg=BG,
        fg=TEXT,
        font=("Arial", 22, "bold")
    ).pack(
        pady=(25, 5)
    )

    tk.Label(
        window,
        text="Previous HJ SHIELD scan results",
        bg=BG,
        fg=MUTED,
        font=("Arial", 10)
    ).pack(
        pady=(0, 15)
    )

    box = tk.Frame(
        window,
        bg=CARD,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    box.pack(
        fill="both",
        expand=True,
        padx=30,
        pady=5
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
        fill="both",
        expand=True,
        padx=15,
        pady=15
    )

    try:

        if os.path.exists(HISTORY_FILE):

            with open(
                HISTORY_FILE,
                "r",
                encoding="utf-8"
            ) as f:

                history = f.read()

        else:
            history = "No scan history available yet."

    except Exception:
        history = "Unable to read scan history."

    text_box.insert(
        "1.0",
        history
    )

    text_box.config(
        state="disabled"
    )


# ============================================================
# PROTECTION INFO
# ============================================================

def show_protection():

    window = tk.Toplevel(app)

    window.title(
        "HJ SHIELD — Protection"
    )

    window.geometry(
        "580x430"
    )

    window.configure(
        bg=BG
    )

    tk.Label(
        window,
        text="PROTECTION STATUS",
        bg=BG,
        fg=TEXT,
        font=("Arial", 22, "bold")
    ).pack(
        pady=(28, 10)
    )

    card = tk.Frame(
        window,
        bg=CARD,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    card.pack(
        fill="x",
        padx=35,
        pady=10
    )

    rows = [
        ("Scanner", "ACTIVE"),
        ("Detection", "SHA-256 + Rules"),
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
            padx=20,
            pady=12
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
            fg=SUCCESS if value in (
                "ACTIVE",
                "ENABLED"
            ) else TEXT,
            font=("Arial", 10, "bold")
        ).pack(
            side="right"
        )

    tk.Label(
        window,
        text="Defensive learning prototype — not a full commercial antivirus.",
        bg=BG,
        fg=MUTED,
        font=("Arial", 9)
    ).pack(
        pady=18
    )


# ============================================================
# SETTINGS
# ============================================================

def show_settings():

    window = tk.Toplevel(app)

    window.title(
        "HJ SHIELD — Settings"
    )

    window.geometry(
        "580x440"
    )

    window.configure(
        bg=BG
    )

    tk.Label(
        window,
        text="SETTINGS",
        bg=BG,
        fg=TEXT,
        font=("Arial", 22, "bold")
    ).pack(
        pady=(28, 18)
    )

    card = tk.Frame(
        window,
        bg=CARD,
        highlightbackground=BORDER,
        highlightthickness=1
    )

    card.pack(
        fill="x",
        padx=35
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
        fg=GOLD,
        font=("Arial", 11, "bold")
    ).pack(
        anchor="w",
        padx=20,
        pady=(20, 10)
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
        pady=8
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
        pady=(8, 20)
    )

    def apply():

        global AUTO_SAVE_HISTORY
        global SHOW_SCAN_DETAILS

        AUTO_SAVE_HISTORY = history_var.get()
        SHOW_SCAN_DETAILS = details_var.get()

        messagebox.showinfo(
            APP_NAME,
            "Settings applied successfully."
        )

    tk.Button(
        window,
        text="APPLY SETTINGS",
        width=24,
        command=apply,
        bg=GOLD,
        fg="black",
        activebackground=GOLD_LIGHT,
        activeforeground="black",
        relief="flat",
        font=("Arial", 10, "bold")
    ).pack(
        pady=22
    )


# ============================================================
# MAIN WINDOW
# ============================================================

app = tk.Tk()

app.title(
    "HJ SHIELD"
)

app.geometry(
    "850x850"
)

app.resizable(
    False,
    False
)

app.configure(
    bg=BG
)

# ------------------------------------------------------------
# HEADER
# ------------------------------------------------------------

header = tk.Frame(
    app,
    bg=BG
)

header.pack(
    fill="x",
    padx=45,
    pady=(30, 5)
)

tk.Label(
    header,
    text="HJ SHIELD",
    bg=BG,
    fg=TEXT,
    font=("Arial", 30, "bold")
).pack(
    anchor="w"
)

tk.Label(
    header,
    text="Personal Antivirus & Security Scanner",
    bg=BG,
    fg=MUTED,
    font=("Arial", 11)
).pack(
    anchor="w",
    pady=(2, 0)
)

# ------------------------------------------------------------
# TOP STAT CARDS
# ------------------------------------------------------------

stats = tk.Frame(
    app,
    bg=BG
)

stats.pack(
    fill="x",
    padx=45,
    pady=(25, 15)
)


def create_stat_card(parent, title, value):

    card = tk.Frame(
        parent,
        bg=CARD,
        highlightbackground=BORDER,
        highlightthickness=1,
        width=175,
        height=100
    )

    card.pack(
        side="left",
        expand=True,
        fill="both",
        padx=5
    )

    card.pack_propagate(False)

    tk.Label(
        card,
        text=title,
        bg=CARD,
        fg=MUTED,
        font=("Arial", 8, "bold")
    ).pack(
        anchor="w",
        padx=15,
        pady=(15, 4)
    )

    label = tk.Label(
        card,
        text=value,
        bg=CARD,
        fg=TEXT,
        font=("Arial", 17, "bold")
    )

    label.pack(
        anchor="w",
        padx=15
    )

    return label


protection_value = create_stat_card(
    stats,
    "PROTECTION STATUS",
    "READY"
)

files_label = create_stat_card(
    stats,
    "FILES SCANNED",
    "0"
)

threats_label = create_stat_card(
    stats,
    "THREATS DETECTED",
    "0"
)

last_scan_label = create_stat_card(
    stats,
    "LAST SCAN",
    "Never"
)

# ------------------------------------------------------------
# MAIN SCAN CARD
# ------------------------------------------------------------

scan_card = tk.Frame(
    app,
    bg=CARD,
    highlightbackground=BORDER,
    highlightthickness=1
)

scan_card.pack(
    fill="x",
    padx=45,
    pady=10
)

status_dot = tk.Label(
    scan_card,
    text="● SYSTEM READY",
    bg=CARD,
    fg=SUCCESS,
    font=("Arial", 12, "bold")
)

status_dot.pack(
    anchor="w",
    padx=25,
    pady=(20, 2)
)

status_label = tk.Label(
    scan_card,
    text="Ready to scan available Windows drives",
    bg=CARD,
    fg=MUTED,
    font=("Arial", 10)
)

status_label.pack(
    anchor="w",
    padx=25
)

# ------------------------------------------------------------
# BUTTONS
# ------------------------------------------------------------

button_frame = tk.Frame(
    scan_card,
    bg=CARD
)

button_frame.pack(
    pady=18
)

scan_button = tk.Button(
    button_frame,
    text="SCAN NOW",
    width=22,
    height=2,
    command=start_scan,
    bg=GOLD,
    fg="black",
    activebackground=GOLD_LIGHT,
    activeforeground="black",
    relief="flat",
    font=("Arial", 11, "bold")
)

scan_button.pack(
    side="left",
    padx=7
)

stop_button = tk.Button(
    button_frame,
    text="STOP SCAN",
    width=22,
    height=2,
    command=stop_scan,
    bg=CARD2,
    fg=MUTED,
    activebackground=DANGER,
    activeforeground="white",
    relief="flat",
    font=("Arial", 11, "bold")
)

stop_button.pack(
    side="left",
    padx=7
)

stop_button.config(
    state="disabled"
)

# ------------------------------------------------------------
# PROGRESS
# ------------------------------------------------------------

progress_frame = tk.Frame(
    scan_card,
    bg=CARD
)

progress_frame.pack(
    fill="x",
    padx=25,
    pady=(0, 25)
)

style = ttk.Style()

try:
    style.theme_use("clam")
except tk.TclError:
    pass

style.configure(
    "HJ.Horizontal.TProgressbar",
    troughcolor=CARD2,
    background=GOLD,
    bordercolor=CARD2,
    lightcolor=GOLD,
    darkcolor=GOLD
)

progress_bar = ttk.Progressbar(
    progress_frame,
    orient="horizontal",
    mode="determinate",
    length=700,
    style="HJ.Horizontal.TProgressbar"
)

progress_bar.pack(
    fill="x"
)

# ------------------------------------------------------------
# TOOLS
# ------------------------------------------------------------

tools_title = tk.Label(
    app,
    text="SECURITY TOOLS",
    bg=BG,
    fg=MUTED,
    font=("Arial", 9, "bold")
)

tools_title.pack(
    anchor="w",
    padx=50,
    pady=(20, 8)
)

tools = tk.Frame(
    app,
    bg=BG
)

tools.pack(
    fill="x",
    padx=45
)


def tool_card(parent, title, subtitle, command):

    button = tk.Button(
        parent,
        text=title + "\n" + subtitle,
        command=command,
        width=22,
        height=3,
        bg=CARD,
        fg=TEXT,
        activebackground=GOLD,
        activeforeground="black",
        relief="flat",
        highlightbackground=BORDER,
        highlightthickness=1,
        font=("Arial", 9, "bold")
    )

    return button


tool_card(
    tools,
    "QUARANTINE",
    "Manage isolated files",
    show_quarantine
).grid(
    row=0,
    column=0,
    padx=5,
    pady=5
)

tool_card(
    tools,
    "SCAN HISTORY",
    "View previous scans",
    show_history
).grid(
    row=0,
    column=1,
    padx=5,
    pady=5
)

tool_card(
    tools,
    "PROTECTION",
    "Security engine status",
    show_protection
).grid(
    row=0,
    column=2,
    padx=5,
    pady=5
)

tool_card(
    tools,
    "SETTINGS",
    "Scanner preferences",
    show_settings
).grid(
    row=0,
    column=3,
    padx=5,
    pady=5
)

# ------------------------------------------------------------
# SHA-256 SECTION
# ------------------------------------------------------------

sha_card = tk.Frame(
    app,
    bg=CARD,
    highlightbackground=BORDER,
    highlightthickness=1
)

sha_card.pack(
    fill="x",
    padx=45,
    pady=(20, 10)
)

tk.Label(
    sha_card,
    text="SHA-256 FILE IDENTIFICATION",
    bg=CARD,
    fg=GOLD,
    font=("Arial", 10, "bold")
).pack(
    anchor="w",
    padx=20,
    pady=(15, 3)
)

tk.Label(
    sha_card,
    text="Files are checked using SHA-256 signatures and defensive rules.",
    bg=CARD,
    fg=MUTED,
    font=("Arial", 9)
).pack(
    anchor="w",
    padx=20,
    pady=(0, 15)
)

# ------------------------------------------------------------
# FOOTER
# ------------------------------------------------------------

tk.Label(
    app,
    text="HJ SHIELD  •  Personal Security Project  •  Defensive Prototype",
    bg=BG,
    fg="#666666",
    font=("Arial", 8)
).pack(
    side="bottom",
    pady=12
)

app.mainloop()