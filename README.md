# Cisco MAC OUI Resolver (GUI)

Offline bulk OUI lookup for Cisco `show mac address-table` output.

- Paste or load text  
- Keeps **VLAN** + **Interface** with each MAC  
- Optional **Exclude Port-Channels (Po*)**  
- CSV export (`Hostname | VLAN | Interface | Mac | Vendor`)  
- UI and CSV both sorted numerically by **Interface**  
- Windows-friendly; can be built as a single `.exe`

---

## Run from source

```bash
py -m venv .venv
.\.venv\ScriptsActivate
pip install -r requirements.txt
py oui_lookup_gui.pyw
```

## Build a Windows EXE

```bash
pip install pyinstaller
py -m PyInstaller --noconfirm --noconsole --onefile --name OUILookup oui_lookup_gui.pyw
# output: dist/OUILookup.exe
```

---

## Getting the vendor database (`manuf`)

Some networks (corp TLS inspection) block the app from downloading the Wireshark **`manuf`** file. If the app can’t pull it, use the standalone downloader and import the file:

1. Double-click the standalone downloader **`get_manuf.pyw`**.  
   It saves a file named **`manuf`** in the **same folder** as the script.
2. In the GUI, click **Import DB** and select that `manuf` file.
3. The app will cache a copy at `%USERPROFILE%\.oui_lookup\manuf` for future runs.

> If your network allows it, **Update DB** will try to download `manuf` directly. If it fails, use the standalone script above.

### Where the DB lives (after import/update)
```
%USERPROFILE%\.oui_lookup\manuf
```

---

## Notes

- CPU rows are skipped automatically.  
- Unknown OUIs show `Unknown`.  
- Export default filename: `<SourceDevice>-MAC-OUI.csv` (e.g., `73-01-SW01-MAC-OUI.csv`).  
- The **Import DB** button lets you run fully offline.  
- Auto-detects **Source Device** from pasted prompts like `SW01#` or `SW01>`.

---

## Troubleshooting (for builders)

If PowerShell blocks venv activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

---

## License
MIT

<img width="1153" height="729" alt="image" src="https://github.com/user-attachments/assets/aea157b3-b447-4d14-af33-385f67a257c6" />
