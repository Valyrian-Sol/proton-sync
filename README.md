# Proton Drive Sync (`~/Dokumente`-Unterordner & `~/Zotero`)

> **🤖 Hinweis (KI-Projekt):** Dieses Projekt wurde mithilfe künstlicher Intelligenz (KI-gestützte Entwicklung) konzipiert und erstellt.

Einweg-Synchronisationsskript (PC → Cloud) für den offiziellen `proton-drive` CLI-Client unter Linux.

## Voraussetzungen

- Python 3.9+ unter `/usr/bin/python3` oder `/usr/local/bin/python3` (keine externen Python-Abhängigkeiten nötig)
- Installierter und angemeldeter `proton-drive` CLI-Client unter `/usr/bin/proton-drive` oder `/usr/local/bin/proton-drive` (`proton-drive auth login`)

## Funktionsweise & Sicherheitsgarantien

1. **Quellen & Ziele (konfigurierbar über `--dokumente` und `--zotero`):**
   - Alle **Unterordner** in `~/Dokumente/<Ordner>` (bzw. `~/Documents/<Ordner>`) werden nach `/my-files/<Ordner>` synchronisiert.
   - **Lose Dateien** direkt in `~/Dokumente` (z. B. `~/Dokumente/Notiz.txt`) werden **ignoriert** (`~/Dokumente` selbst wird nicht als Überordner angelegt).
   - Der Ordner `~/Zotero` wird nach `/my-files/Zotero` synchronisiert (laufende Zotero-Prozesse sowie verwaiste `-wal`/`-journal`-Dateien werden minimal-invasiv erkannt und `zotero.sqlite*` wird übersprungen, um korrupte Backups zu verhindern).
2. **Ordner & Dateien ausschließen (Fail-Closed, Case-/Unicode-robust & OPSEC-sicher):**
   - Über `--exclude` / `-x`, eine lokale `exclude.txt` (Vorlage: [`exclude.example.txt`](exclude.example.txt), per `.gitignore` vor versehentlichen Git-Commits geschützt), `~/.config/proton-sync/exclude.txt` oder `DEFAULT_EXCLUDED_FOLDERS` in [`sync_proton_drive.py`](sync_proton_drive.py) lassen sich beliebige Ordner **und Einzeldateien** ausschließen (z. B. `Videos`, `node_modules`, `*.kdbx`, `Projekte/Archiv` oder `~/Dokumente/Temp`).
   - Der Abgleich ignoriert Groß-/Kleinschreibung sowie Unicode-Normalisierungsunterschiede (`NFC`/`NFD`), sodass `*.kdbx` zuverlässig auch `Tresor.KDBX` ausschließt.
   - Fehlt eine explizit per `--exclude-file` angegebene Datei oder ist eine Ausschlussdatei unlesbar, bricht das Skript sofort ab (**Fail-Closed**), statt ungeschützt hochzuladen.
3. **TOCTOU-freies Hardlink-Staging & Dateisystem-Grenzen:**
   - Versteckte Dateien (`.env`, `.git` usw., sofern nicht `--include-hidden` gesetzt ist), Symlinks, Hardlinks (`st_nlink > 1`, sofern nicht `--allow-hardlinks`) und fremde Dateisysteme/Mount-Points (sofern nicht `--cross-filesystems`) werden herausgefiltert.
   - `proton-drive` erhält niemals die echten Quellordner zum rekursiven Durchlaufen, sondern einen privaten Staging-Bereich (`0700`) aus Inode-geprüften Hardlinks. Selbst während eines laufenden Uploads nachträglich abgelegte Dateien oder Symlinks gelangen dadurch nicht in die Cloud.
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
```

## Selbsttests ausführen

```bash
python3 -m unittest test_sync_logic.py
```
