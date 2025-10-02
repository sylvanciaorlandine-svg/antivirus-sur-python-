#!/usr/bin/env python3
"""
Mini Antivirus avec quarantaine contrôlée
- Analyse fichiers/dossiers avec ClamAV, YARA et SHA256 locale
- Vérifie l’existence du dossier quarantine avant d’y copier les fichiers infectés
- Popup pour créer le dossier si absent
- Interface Tkinter fonctionnelle
"""

import os
import subprocess
import json
import hashlib
import threading
import time
import shutil
from tkinter import Tk, Button, Label, Text, END, filedialog, Scrollbar, RIGHT, Y, BOTH, LEFT, Frame, messagebox

# Optionnel YARA
try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

# Config
LOGFILE = "scan_log.txt"
SIGNATURE_DB = "signatures.json"
YARA_RULES = "rules.yar"
QUARANTINE_DIR = "quarantine"

# Création de la base de signatures si elle n'existe pas
if not os.path.exists(SIGNATURE_DB):
    with open(SIGNATURE_DB, "w") as f:
        json.dump({"sha256": []}, f)

def save_log(line):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {line}\n")

def call_clam_scan(path):
    """Scan avec ClamAV"""
    for cmd in (["clamdscan", "--fdpass", "--no-summary", path], ["clamscan", "--no-summary", path]):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            out = proc.stdout + proc.stderr
            if "FOUND" in out or "Infected files: 1" in out:
                return True, out
            return False, out
        except FileNotFoundError:
            continue
        except Exception as e:
            return False, f"ERROR calling clam scan: {e}"
    return False, "ClamAV not found"

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

def quarantine_file(path):
    """Copie le fichier infecté dans le dossier quarantine"""
    base = os.path.basename(path)
    target = os.path.join(QUARANTINE_DIR, f"{int(time.time())}_{base}")
    shutil.copy2(path, target)
    return target

class Scanner:
    def __init__(self, ui_append, check_quarantine_func):
        self.ui_append = ui_append
        self.check_quarantine = check_quarantine_func
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

        # ClamAV
        infected, clam_out = call_clam_scan(path)
        if infected:
            if not self.check_quarantine():
                self.ui_append(f"Scan arrêté : dossier quarantine manquant pour {path}")
                return
            target = quarantine_file(path)
            self.ui_append(f"  INFECTED (ClamAV) -> {target}")
            save_log(f"CLAMAV_INFECTED: {path} -> {target}")
            return

        # YARA
        yara_found, yara_out = yara_scan_file(path)
        if yara_found:
            if not self.check_quarantine():
                self.ui_append(f"Scan arrêté : dossier quarantine manquant pour {path}")
                return
            target = quarantine_file(path)
            self.ui_append(f"  INFECTED (YARA) -> {target}")
            save_log(f"YARA_INFECTED: {path} -> {target} {yara_out}")
            return
        elif yara_out and ("not installed" in yara_out or "not found" in yara_out):
            self.ui_append(f"  YARA skipped: {yara_out}")

        # SHA256
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            sha = h.hexdigest()
            if sha in self.sign_db.get("sha256", []):
                if not self.check_quarantine():
                    self.ui_append(f"Scan arrêté : dossier quarantine manquant pour {path}")
                    return
                target = quarantine_file(path)
                self.ui_append(f"  INFECTED (local signature) -> {target}")
                save_log(f"LOCAL_SIG_INFECTED: {path} -> {target} {sha}")
                return
        except Exception as e:
            self.ui_append(f"  Error computing sha256: {e}")

        # Sinon clean
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
        master.title("Mini Antivirus - Quarantaine contrôlée")

        self.selected_path = None
        self.scanner = None

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
        Button(btn_frame, text="Ouvrir Quarantaine", command=self.open_quarantine).pack(side=LEFT, padx=2)

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

    def check_quarantine(self):
        if not os.path.exists(QUARANTINE_DIR):
            ans = messagebox.askyesno("Quarantaine manquante",
                                      f"Le dossier {QUARANTINE_DIR} n'existe pas.\nVoulez-vous le créer ?")
            if ans:
                os.makedirs(QUARANTINE_DIR)
                self.ui_append(f"Dossier {QUARANTINE_DIR} créé.")
                return True
            else:
                self.ui_append("Scan annulé : quarantaine requise.")
                return False
        return True

    def start_scan(self):
        if not self.selected_path:
            messagebox.showinfo("Sélectionnez", "Choisissez un fichier ou dossier d'abord.")
            return
        self.scanner = Scanner(self.ui_append, self.check_quarantine)
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
        if not os.path.exists(QUARANTINE_DIR):
            ans = messagebox.askyesno("Quarantaine manquante",
                                      f"Le dossier {QUARANTINE_DIR} n'existe pas.\nVoulez-vous le créer ?")
            if ans:
                os.makedirs(QUARANTINE_DIR)
                self.ui_append(f"Dossier {QUARANTINE_DIR} créé.")
            else:
                return
        # Ouvre le dossier quarantaine avec l'explorateur
        try:
            if os.name == 'nt':
                os.startfile(os.path.abspath(QUARANTINE_DIR))
            elif os.name == 'posix':
                subprocess.run(['xdg-open', os.path.abspath(QUARANTINE_DIR)])
        except Exception as e:
            self.ui_append(f"Impossible d'ouvrir le dossier: {e}")

if __name__ == "__main__":
    try:
        root = Tk()
        app = App(root)
        root.geometry("900x500")
        root.mainloop()
    except Exception as e:
        print("UI error:", e)
