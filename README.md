# Proton Drive Sync (konfigurierbare Standardordner, z. B. `~/Dokumente`, `~/Zotero`, `~/.config`)

> **🤖 Hinweis (KI-Projekt):** Dieses Projekt wurde mithilfe künstlicher Intelligenz (KI-gestützte Entwicklung) konzipiert und erstellt.

Einweg-Synchronisationsskript (PC → Cloud) für den offiziellen `proton-drive` CLI-Client unter Linux.

## Voraussetzungen

- Python 3.9+ unter `/usr/bin/python3` oder `/usr/local/bin/python3` (keine externen Python-Abhängigkeiten nötig)
- Installierter und angemeldeter `proton-drive` CLI-Client unter `/usr/bin/proton-drive` oder `/usr/local/bin/proton-drive` (`proton-drive auth login`)

## Funktionsweise & Sicherheitsgarantien

1. **Quellen & Ziele (frei konfigurierbar über `sources.txt` & CLI):**
   - **Standardpfade ab Werk:**
     - Alle **Unterordner** in `~/Dokumente/<Ordner>` (bzw. `~/Documents/<Ordner>`, Modus `subfolders`) werden nach `/my-files/<Ordner>` synchronisiert; **lose Dateien** direkt in `~/Dokumente` werden ignoriert.
     - Der Ordner `~/Zotero` (Modus `folder`) wird vollständig inkl. Unterordner und loser Dateien nach `/my-files/Zotero` synchronisiert (laufende Zotero-Prozesse sowie verwaiste `-wal`/`-journal`-Dateien werden minimal-invasiv erkannt und `zotero.sqlite*` wird übersprungen, um korrupte Backups zu verhindern).
   - **Standardpfade hinzufügen oder entfernen:**
     - Dauerhaft über `./sync.sh --add-source <PFAD>` (optional mit `--source-mode folder|subfolders`), `./sync.sh --remove-source <PFAD>`, `./sync.sh --list-sources` oder über `sources.txt` (Vorlage: [`sources.example.txt`](sources.example.txt), per `.gitignore` vor versehentlichen Git-Commits geschützt), `sources.local.txt` sowie `~/.config/proton-sync/sources.txt`.
     - Einmalig pro Lauf über `--source` / `-s <PFAD>` bzw. `--skip-source <PFAD>`.
     - Explizit als `folder`-Quelle konfigurierte Punkt-Ordner (wie `~/.config` → `/my-files/.config`) werden auch ohne `--include-hidden` inklusive aller nicht-versteckten Unterordner und loser Dateien synchronisiert (während versteckte Dateien *innerhalb* des Ordners wie `.env` weiterhin geschützt bleiben).
2. **Ordner & Dateien ausschließen & Konfigurations-Schutz (Fail-Closed, Case-/Unicode-robust & OPSEC-sicher):**
   - Über `--exclude` / `-x`, eine lokale `exclude.txt` (Vorlage: [`exclude.example.txt`](exclude.example.txt), per `.gitignore` vor versehentlichen Git-Commits geschützt), `~/.config/proton-sync/exclude.txt` oder `DEFAULT_EXCLUDED_FOLDERS` in [`sync_proton_drive.py`](sync_proton_drive.py) lassen sich beliebige Ordner **und Einzeldateien** ausschließen (z. B. `Videos`, `node_modules`, `*.kdbx`, `Projekte/Archiv` oder `~/Dokumente/Temp`).
   - Hochsensible Pfade wie Browser-Profile (`google-chrome*`, `chromium*`, `BraveSoftware`, …), Proton-Session-/Vault-Verzeichnisse (`~/.config/proton*`, `~/.local/share/proton*`), SSH-/GPG-Schlüssel, Tresore (`*.kdbx`, `*.p12`, `*.pfx`), Cloud-CLI-Tokens (`gh`, `rclone`, `aws`, `gcloud`, …) sowie `*.env` sind über `SENSITIVE_DEFAULT_EXCLUDES` standardmäßig ausgeschlossen (optional deaktivierbar per `--allow-sensitive`).
   - Der Abgleich ignoriert Groß-/Kleinschreibung sowie Unicode-Normalisierungsunterschiede (`NFC`/`NFD`), sodass `*.kdbx` zuverlässig auch `Tresor.KDBX` ausschließt.
   - Fehlt eine explizit per `--exclude-file` / `--sources-file` angegebene Datei, ist eine Konfigurationsdatei ein Symlink, unlesbar, world-writable oder gehört einem fremden Benutzer, bricht das Skript sofort ab (**Fail-Closed**). `sources.txt` wird bei CLI-Änderungen atomar mit Modus `0600` und Symlink-Schutz geschrieben; Pfad-Traversierung (`..`), Wurzelpfad `/`, Systemverzeichnisse (`/etc`, `/proc`, `/sys`, …) und Steuerzeichen werden abgewiesen.
3. **TOCTOU-freies privates Staging & Prozess-Isolation:**
   - Versteckte Dateien (`.env`, `.git` usw., sofern nicht `--include-hidden` gesetzt ist), Symlinks, Hardlinks (`st_nlink > 1`, sofern nicht `--allow-hardlinks`) und fremde Dateisysteme/Mount-Points (sofern nicht `--cross-filesystems`) werden herausgefiltert.
   - `proton-drive` erhält niemals die echten Quellordner zum rekursiven Durchlaufen, sondern ausschließlich einen privaten Staging-Bereich (`0700` unter `~/.cache/proton-sync`) aus Inode-geprüften Hardlinks (bei `EXDEV`/`EPERM` mit sicherem FD-verifiziertem Kopier-Fallback statt ungeschütztem Live-Fallback). Das Aufräumen erfolgt über `dir_fd`-gebundene Systemaufrufe (`O_NOFOLLOW`).
   - `sync.sh` validiert Eigentümer und Verzeichniskette des Python-Interpreters und startet Python im isolierten Modus (`-I`), während `proton-drive` mit bereinigter Prozessumgebung (ohne `LD_*`, `DOTNET_*`, `SSLKEYLOGFILE`, `OPENSSL_CONF`, `PYTHON*`) aufgerufen wird.
4. **Synchronisations-Regeln & Prozessschutz:**
   - **Neue Ordner & Dateien:** Werden automatisch in die entsprechenden Zielordner unter `/my-files` hochgeladen.
   - **Cloud älter als PC:** Ist eine Datei auf dem PC neuer (`mtime` > `claimedModificationTime` der Cloud-Datei) und weicht der Inhalt ab, wird die Cloud-Datei durch die PC-Version aktualisiert (`-f create-new-revision -d merge`).
   - **Cloud neuer oder gleich alt / inhaltsgleich:** Dateien, die in der Cloud neuer sind oder denselben Hash besitzen, werden übersprungen (unplausible Zukunfts-Zeitstempel in Cloud-Metadaten werden erkannt und gemeldet).
   - **Kein Datenverlust:** Das Skript führt **niemals** Löschbefehle aus; die Strategie `replace` (verschiebt Cloud-Dateien in den Papierkorb) ist ohne ausdrückliches `--allow-trash` gesperrt. Alle CLI-Ausgaben werden gegen Terminal-Steuerzeichen bereinigt, Pfade stehen strikt hinter `--`, und parallele Läufe werden per `flock` blockiert.

## Verwendung

```bash
git clone https://github.com/Valyrian-Sol/proton-sync.git
cd proton-sync

# Optional: Eigene lokale Ausschlussdatei anlegen (wird nicht in Git eingecheckt)
cp exclude.example.txt exclude.txt

# 1. Trockenlauf (Dry-Run): Zeigt genau an, was hochgeladen oder aktualisiert würde
./sync.sh --dry-run

# 2. Bestimmte Ordner oder Dateimuster per Parameter ausschließen
./sync.sh -x Videos -x "*.kdbx" --dry-run
./sync.sh --exclude "Videos,Projekte/Archiv,node_modules"

# 3. Live-Synchronisation starten (alle nicht ausgeschlossenen Unterordner von ~/Dokumente + ~/Zotero)
./sync.sh

# 4. Nur einen einzelnen Ordner gezielt synchronisieren (z. B. Zotero oder Projekte)
./sync.sh --only Zotero
./sync.sh --only Projekte -x Projekte/Archiv --dry-run

# 5. Standardpfade anzeigen, hinzufügen oder entfernen
./sync.sh --list-sources
./sync.sh --add-source ~/.config
./sync.sh --add-source ~/Projekte --source-mode subfolders
./sync.sh --remove-source ~/Zotero
./sync.sh --source ~/Bilder --skip-source ~/Zotero --dry-run
```

## Selbsttests ausführen

```bash
python3 -m unittest test_sync_logic.py
```
