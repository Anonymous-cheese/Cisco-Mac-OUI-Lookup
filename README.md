# Cisco MAC OUI Resolver (GUI)

Offline bulk OUI lookup for Cisco \show mac address-table\ output.
- Paste or load text
- Keeps VLAN + interface, optional exclude Port-Channels
- OUI via Wireshark \manuf\ (cached locally)
- CSV export
- Windows-friendly, can be built as a single \.exe\

## Run
\\\ash
py -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
py oui_lookup_gui.pyw
\\\

## Build EXE
\\\ash
py -m PyInstaller --noconfirm --noconsole --onefile --name OUILookup oui_lookup_gui.pyw
\\\

## Notes
- First run downloads \manuf\ to \%USERPROFILE%\.oui_lookup\.
- Export columns: Hostname | VLAN | Interface | Mac | Vendor.