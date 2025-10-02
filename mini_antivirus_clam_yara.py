#!/usr/bin/env python3
"""
Mini Antivirus Prototype with ClamAV + YARA integration (educational).
- Uses 'clamscan' or 'clamdscan' (if available) for signature-based scanning.
- Uses yara-python (import yara) for YARA rules scanning.
- Provides a Tkinter UI to select files/folders, run scans, and quarantine.
Important: This is an educational tool. Do NOT run on production systems without review.
"""

import os
import shutil
import time
import threading
import subprocess
import json
from tkinter import Tk, Button, Label, Text, END, filedialog, Scrollbar, RIGHT, Y, BOTH, LEFT, Frame, messagebox

# Optional import for yara; if not installed, YARA scans will be skipped with a message.
try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

# Config
QUARANTINE_DIR = os.path.join(os.getcwd(), "quarantine")
LOGFILE = "scan_log.txt"
SIGNATURE_DB = "signatures.json"
YARA_RULES = "rules.yar"  # YARA rules file

def ensure_dirs():
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    if not os.path.exists(SIGNATURE_DB):
        with open(SIGNATURE_DB, "w") as f:
            json.dump({"sha256": []}, f)

def save_log(line):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {line}\n")

def quarantine_file(path):
    try:
        base = os.path.basename(path)
        target = os.path.join(QUARANTINE_DIR, f"{int(time.time())}_{base}")
        shutil.move(path, target)
        save_log(f"QUARANTINE: {path} -> {target}")
        return True, target
    except Exception as e:
        save_log(f"QUARANTINE_FAILED: {path} ({e})")
        return False, str(e)

def call_clam_scan(path):
    """
    Call clamdscan (preferred) or clamscan. Returns (found:bool, output:str).
    """
    # Prefer clamdscan if available
    for cmd in (["clamdscan", "--fdpass", "--no-summary", path], ["clamscan", "--no-summary", path]):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            out = proc.stdout + proc.stderr
            # clamscan output lines containing 'OK' or 'FOUND'
            # If 'FOUND' present -> infected
            if "FOUND" in out or "Infected files: 1" in out:
                return True, out
            else:
                return False, out
        except FileNotFoundError:
            continue
        except Exception as e:
            return False, f"ERROR calling clam scan: {e}"
    return False, "ClamAV not found (install clamscan/clamdscan)."

def yara_scan_file(path, rules_path=YARA_RULES):
    if not YARA_AVAILABLE:
        return False, "yara-python not installed"
    if not os.path.exists(rules_path):
        return False, "YARA rules file not found"
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(path)
        return (len(matches) > 0), str(matches)
    except Exception as e:
        return False, f"YARA error: {e}"

class Scanner:
    def __init__(self, ui_append):
        self.ui_append = ui_append
        # load signature DB (sha256 list)
        try:
            with open(SIGNATURE_DB, "r") as f:
                self.sign_db = json.load(f)
        except Exception:
            self.sign_db = {"sha256": []}
        self.stop_flag = False

    def scan_file(self, path):
        if not os.path.isfile(path):
            self.ui_append(f"IGNORED (not file): {path}")
            return
        self.ui_append(f"Scanning: {path}")

        # 1) ClamAV scan
        infected, clam_out = call_clam_scan(path)
        if infected:
            self.ui_append(f"  INFECTED (ClamAV): {path}")
            save_log(f"CLAMAV_INFECTED: {path}")
            ok, info = quarantine_file(path)
            if ok:
                self.ui_append(f"  Quarantined: {info}")
            else:
                self.ui_append(f"  Quarantine failed: {info}")
            return

        # 2) YARA scan
        yara_found, yara_out = yara_scan_file(path)
        if yara_found:
            self.ui_append(f"  YARA MATCH: {path} -> {yara_out}")
            save_log(f"YARA_MATCH: {path} {yara_out}")
            ok, info = quarantine_file(path)
            if ok:
                self.ui_append(f"  Quarantined: {info}")
            else:
                self.ui_append(f"  Quarantine failed: {info}")
            return
        elif yara_out and "not installed" in yara_out or "not found" in yara_out:
            self.ui_append(f"  YARA skipped: {yara_out}")

        # 3) Signature DB (sha256) check (local DB)
        try:
            import hashlib
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            sha = h.hexdigest()
            if sha in self.sign_db.get("sha256", []):
                self.ui_append(f"  INFECTED (local signature): {path} sha256={sha}")
                save_log(f"LOCAL_SIG_INFECTED: {path} {sha}")
                ok, info = quarantine_file(path)
                if ok:
                    self.ui_append(f"  Quarantined: {info}")
                else:
                    self.ui_append(f"  Quarantine failed: {info}")
                return
        except Exception as e:
            self.ui_append(f"  Error computing sha256: {e}")

        # Otherwise clean
        self.ui_append(f"  CLEAN: {path}")
        save_log(f"CLEAN: {path}")

    def scan_path(self, root):
        if os.path.isfile(root):
            self.scan_file(root)
            return
        for dirpath, dirnames, filenames in os.walk(root):
            if self.stop_flag:
                self.ui_append("Scan stopped by user.")
                return
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                self.scan_file(fp)

    def stop(self):
        self.stop_flag = True

class App:
    def __init__(self, master):
        self.master = master
        master.title("Mini Antivirus (ClamAV + YARA) - Prototype")

        self.selected_path = None
        self.scanner = Scanner(self.ui_append)

        top = Frame(master)
        top.pack(fill=BOTH, padx=8, pady=8)

        self.lbl = Label(top, text="Aucun fichier/dossier sélectionné")
        self.lbl.pack(anchor="w")

        btn_frame = Frame(master)
        btn_frame.pack(fill=BOTH, padx=8, pady=4)

        Button(btn_frame, text="Choisir fichier", command=self.choose_file).pack(side=LEFT, padx=2)
        Button(btn_frame, text="Choisir dossier", command=self.choose_folder).pack(side=LEFT, padx=2)
        Button(btn_frame, text="Lancer le scan", command=self.start_scan).pack(side=LEFT, padx=2)
        Button(btn_frame, text="Arrêter le scan", command=self.stop_scan).pack(side=LEFT, padx=2)
        Button(btn_frame, text="Ouvrir quarantaine", command=self.open_quarantine).pack(side=LEFT, padx=2)

        log_frame = Frame(master)
        log_frame.pack(fill=BOTH, expand=True, padx=8, pady=4)

        self.txt = Text(log_frame, wrap='word', height=20)
        self.txt.pack(side=LEFT, fill=BOTH, expand=True)
        sb = Scrollbar(log_frame, command=self.txt.yview)
        sb.pack(side=RIGHT, fill=Y)
        self.txt.config(yscrollcommand=sb.set)

    def ui_append(self, text):
        self.txt.insert(END, text + "\n")
        self.txt.see("end")

    def choose_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.selected_path = p
            self.lbl.config(text=f"Fichier: {p}")
            self.ui_append(f"Selected: {p}")

    def choose_folder(self):
        p = filedialog.askdirectory()
        if p:
            self.selected_path = p
            self.lbl.config(text=f"Dossier: {p}")
            self.ui_append(f"Selected: {p}")

    def start_scan(self):
        if not self.selected_path:
            messagebox.showinfo("Sélectionnez", "Choisissez un fichier ou dossier d'abord.")
            return
        self.scanner = Scanner(self.ui_append)  # reload db
        t = threading.Thread(target=self._scan_thread, args=(self.selected_path,), daemon=True)
        t.start()
        self.ui_append("Scan lancé...")

    def _scan_thread(self, path):
        try:
            self.scanner.scan_path(path)
            self.ui_append("Scan terminé.")
        except Exception as e:
            self.ui_append(f"Erreur: {e}")

    def stop_scan(self):
        if hasattr(self, "scanner"):
            self.scanner.stop()
            self.ui_append("Demande d'arrêt envoyée.")

    def open_quarantine(self):
        if os.name == "nt":
            os.startfile(QUARANTINE_DIR)
        else:
            try:
                import subprocess
                subprocess.Popen(["xdg-open", QUARANTINE_DIR])
            except Exception:
                self.ui_append(f"Quarantine at: {QUARANTINE_DIR}")

if __name__ == "__main__":
    ensure_dirs()
    try:
        root = Tk()
        app = App(root)
        root.geometry("900x500")
        root.mainloop()
    except Exception as e:
        print("UI error:", e)
