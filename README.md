# Mini Antivirus Prototype (ClamAV + YARA)

Contenu:
- `mini_antivirus_clam_yara.py` : script principal (Tkinter UI)
- `signatures.json` : base de signatures locales (SHA256)
- `rules.yar` : exemple de règles YARA
- `requirements.txt` : dépendances Python recommandées

## Installation & prérequis (Linux / macOS / Windows WSL)
1. **Installer ClamAV** :
   - Debian/Ubuntu: `sudo apt update && sudo apt install clamav clamav-daemon`
   - Fedora: `sudo dnf install clamav clamav-update`
   - Windows: installer ClamAV ou utiliser WSL.
   - Mettre à jour les signatures: `sudo freshclam`

2. **Installer Python packages** :
   - Crée un environnement virtuel (recommandé):
     ```bash
     python3 -m venv venv
     source venv/bin/activate   # ou venv\\Scripts\\activate sur Windows
     pip install -r requirements.txt
     ```

3. **YARA (optionnel mais recommandé pour règles)** :
   - Installer yara-python: `pip install yara-python`
   - Créer/éditer `rules.yar` avec tes règles.

4. **Exécution** :
   - `python3 mini_antivirus_clam_yara.py`
   - Dans l'interface: choisis un fichier/dossier -> Lancer le scan.
   - Les fichiers suspects seront déplacés dans le dossier `quarantine`.

## Notes de sécurité
- **Ne pas** laisser ce script agir sans supervision sur des systèmes de production.
- Ce prototype **quarantaine** (déplace) les fichiers infectés — il ne tente pas de "réparer" automatiquement.
- Pour des analyses plus complètes, intégrer un moteur professionnel (ex: utiliser clamd comme service et API).

## Fichiers inclus
- `signatures.json` : contient un hash d'exemple.
- `rules.yar` : règle YARA d'exemple qui matche la chaîne "EVIL".