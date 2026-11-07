# Proton Drive Sync (`~/Dokumente`-Unterordner & `~/Zotero`)

> **🤖 Hinweis (KI-Projekt):** Dieses Projekt wurde mithilfe künstlicher Intelligenz (KI-gestützte Entwicklung) konzipiert und erstellt.

Einweg-Synchronisationsskript (PC → Cloud) für den offiziellen `proton-drive` CLI-Client unter Linux.

## Voraussetzungen

- Python 3.9+ (keine externen Python-Abhängigkeiten nötig)
- Installierter und angemeldeter `proton-drive` CLI-Client (`proton-drive auth login`)

## Funktionsweise & Sicherheitsgarantien

1. **Quellen & Ziele (konfigurierbar über `--dokumente` und `--zotero`):**
   - Alle **Unterordner** in `~/Dokumente/<Ordner>` (bzw. `~/Documents/<Ordner>`) werden nach `/my-files/<Ordner>` synchronisiert.
   - **Lose Dateien** direkt in `~/Dokumente` (z. B. `~/Dokumente/Notiz.txt`) werden **ignoriert** (`~/Dokumente` selbst wird nicht als Überordner angelegt).
   - Der Ordner `~/Zotero` wird nach `/my-files/Zotero` synchronisiert (geöffnete `zotero.sqlite`-Datenbanken werden automatisch erkannt und übersprungen, um korrupte Backups zu verhindern).
2. **Ordner & Dateien ausschließen (Fail-Closed & OPSEC-sicher):**
   - Über `--exclude` / `-x`, eine lokale `exclude.txt` (Vorlage: [`exclude.example.txt`](exclude.example.txt), per `.gitignore` vor versehentlichen Git-Commits geschützt), `~/.config/proton-sync/exclude.txt` oder `DEFAULT_EXCLUDED_FOLDERS` in [`sync_proton_drive.py`](sync_proton_drive.py) lassen sich beliebige Ordner **und Einzeldateien** ausschließen (z. B. `Videos`, `node_modules`, `*.kdbx`, `Projekte/Archiv` oder `~/Dokumente/Temp`).
   - Fehlt eine explizit per `--exclude-file` angegebene Datei oder ist eine Ausschlussdatei unlesbar, bricht das Skript sofort ab (**Fail-Closed**), statt ungeschützt hochzuladen.
   - Auch in komplett neuen Ordnern werden versteckte Dateien (`.env`, `.git` usw., sofern nicht `--include-hidden` gesetzt ist), Symlinks und ausgeschlossene Dateien niemals ungefiltert hochgeladen.
3. **Synchronisations-Regeln & Härtung:**
   - **Neue Ordner & Dateien:** Werden automatisch in die entsprechenden Zielordner unter `/my-files` hochgeladen.
   - **Cloud älter als PC:** Ist eine Datei auf dem PC neuer (`mtime` > `claimedModificationTime` der Cloud-Datei) und weicht der Inhalt ab, wird die Cloud-Datei durch die PC-Version aktualisiert (`-f create-new-revision -d merge`).
   - **Cloud neuer oder gleich alt / inhaltsgleich:** Dateien, die in der Cloud neuer sind oder denselben Hash besitzen, werden übersprungen (unplausible Zukunfts-Zeitstempel in Cloud-Metadaten werden erkannt und gemeldet).
   - **Kein Datenverlust & Prozessschutz:** Das Skript führt **niemals** Löschbefehle (`delete`/`trash`) aus, schützt parallele Läufe per `flock`, prüft Pfade unmittelbar vor dem Upload gegen Symlink-Races (TOCTOU) und übergibt Dateipfade strikt hinter `--`.

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
