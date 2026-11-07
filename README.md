# Proton Drive Sync (`~/Dokumente`-Unterordner & `~/Zotero`)

> **🤖 Hinweis (KI-Projekt):** Dieses Projekt wurde mithilfe künstlicher Intelligenz (KI-gestützte Entwicklung) konzipiert und erstellt.

Einweg-Synchronisationsskript (PC → Cloud) für den offiziellen `proton-drive` CLI-Client unter Linux.

## Voraussetzungen

- Python 3.9+ (keine externen Python-Abhängigkeiten nötig)
- Installierter und angemeldeter `proton-drive` CLI-Client (`proton-drive account status`)

## Funktionsweise & Garantien

1. **Quellen & Ziele (konfigurierbar über `--dokumente` und `--zotero`):**
   - Alle **Unterordner** in `~/Dokumente/<Ordner>` (bzw. `~/Documents/<Ordner>`) werden nach `/my-files/<Ordner>` synchronisiert.
   - **Lose Dateien** direkt in `~/Dokumente` (z. B. `~/Dokumente/Notiz.txt`) werden **ignoriert** (`~/Dokumente` selbst wird nicht als Überordner angelegt).
   - Der Ordner `~/Zotero` wird komplett nach `/my-files/Zotero` synchronisiert.
2. **Ordner ausschließen:**
   - Über `--exclude` / `-x`, die Datei [`exclude.txt`](exclude.txt) oder die Liste `DEFAULT_EXCLUDED_FOLDERS` in [`sync_proton_drive.py`](sync_proton_drive.py) lassen sich beliebige Top-Level- oder Unterordner ausschließen (per Ordnername wie `Videos`, `node_modules`, relativem Pfad wie `Projekte/Archiv` oder absolutem Pfad wie `~/Dokumente/Videos`).
3. **Synchronisations-Regeln:**
   - **Neue Ordner & Dateien:** Werden automatisch in die entsprechenden Zielordner hochgeladen. Existiert ein ganzer Ordner noch nicht in der Cloud (und enthält er keine ausgeschlossenen Unterordner), wird er in einem einzigen Schritt komplett übertragen.
   - **Cloud älter als PC:** Ist eine Datei auf dem PC neuer (`mtime` > `claimedModificationTime` der Cloud-Datei) und weicht der Inhalt (`SHA-1`) ab, wird die Cloud-Datei durch die PC-Version aktualisiert (`-f create-new-revision -d merge`).
   - **Cloud neuer oder gleich alt / inhaltsgleich:** Dateien, die in der Cloud neuer sind oder denselben `SHA-1`-Hash besitzen, werden übersprungen.
   - **Kein Datenverlust:** Das Skript führt **niemals** Löschbefehle (`delete`/`trash`) aus und nutzt für Ordner immer `-d merge` sowie für aktualisierte Dateien `-f create-new-revision` (legt eine neue Revision in Proton Drive an, ohne bestehende Dateien zu verwerfen).

## Verwendung

```bash
git clone <REPO-URL>
cd proton-sync

# 1. Trockenlauf (Dry-Run): Zeigt genau an, was hochgeladen oder aktualisiert würde
./sync.sh --dry-run

# 2. Bestimmte Ordner per Parameter ausschließen (-x mehrfach oder kommagetrennt)
./sync.sh -x Videos -x Archiv --dry-run
./sync.sh --exclude "Videos,Projekte/Archiv,node_modules"

# 3. Dauerhafte Ausschlüsse in exclude.txt eintragen (wird automatisch geladen)
#    Datei: ./exclude.txt

# 4. Live-Synchronisation starten (alle nicht ausgeschlossenen Unterordner von ~/Dokumente + ~/Zotero)
./sync.sh

# 5. Nur einen einzelnen Ordner gezielt synchronisieren (z. B. Zotero oder Projekte)
./sync.sh --only Zotero
./sync.sh --only Projekte -x Projekte/Archiv --dry-run
```

## Selbsttests ausführen

```bash
python3 -m unittest test_sync_logic.py
```
