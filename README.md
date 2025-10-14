# Cisco MAC OUI Resolver (GUI)

Offline bulk OUI lookup for Cisco `show mac address-table` output.

- Paste or load text
- Keeps **VLAN** + **Interface** with each MAC
- Optional **Exclude Port-Channels (Po\*)**
- OUI via Wireshark `manuf` (cached locally)
- CSV export (`Hostname | VLAN | Interface | Mac | Vendor`)
- UI and CSV both sorted numerically by **Interface**
- Windows-friendly; can be built as a single `.exe`

## Run

```bash
py -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
py oui_lookup_gui.pyw
