import os, sys, subprocess
try:
    import requests
except Exception:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

import re, csv, threading, tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

MANUF_URL="https://www.wireshark.org/download/automated/data/manuf"
CACHE_DIR=os.path.join(Path.home(),".oui_lookup")
CACHE_FILE=os.path.join(CACHE_DIR,"manuf")
ALT_CA_FILE=os.path.join(CACHE_DIR,"corp_ca.pem")

def _verify_arg():
    p=os.environ.get("REQUESTS_CA_BUNDLE")
    if p and os.path.exists(p): return p
    if os.path.exists(ALT_CA_FILE): return ALT_CA_FILE
    return True

def fetch_manuf():
    os.makedirs(CACHE_DIR,exist_ok=True)
    r=requests.get(MANUF_URL,timeout=30,verify=_verify_arg())
    r.raise_for_status()
    with open(CACHE_FILE,"wb") as f:
        f.write(r.content)

def import_manuf_from_file():
    p=filedialog.askopenfilename(title="Select Wireshark manuf file",filetypes=[("manuf or text","*.*")])
    if not p: return None
    os.makedirs(CACHE_DIR,exist_ok=True)
    with open(p,"rb") as src, open(CACHE_FILE,"wb") as dst:
        dst.write(src.read())
    return CACHE_FILE

def _load_lines_from(path):
    with open(path,"r",encoding="utf-8",errors="ignore") as f:
        return f.readlines()

def load_manuf():
    if not os.path.exists(CACHE_FILE):
        try:
            fetch_manuf()
        except Exception:
            chosen=import_manuf_from_file()
            if not chosen:
                raise
    lines=_load_lines_from(CACHE_FILE)
    buckets={}
    for L in lines:
        L=L.strip()
        if not L or L.startswith('#'): continue
        parts=L.split()
        prefix=parts[0]
        vendor=" ".join(parts[1:]) if len(parts)>1 else ""
        if '/' in prefix:
            base,maskbits=prefix.split('/',1)
            try: maskbits=int(maskbits)
            except: continue
        else:
            base=prefix
            maskbits=len(base.split(':'))*8 if ':' in base else len(re.sub(r'[^0-9A-Fa-f]','',base))*4
        h=re.sub(r'[^0-9A-Fa-f]','',base).upper()
        if not h: continue
        try: val=int(h,16)<<(48-len(h)*4)
        except: continue
        if maskbits<0 or maskbits>48: continue
        if maskbits not in buckets: buckets[maskbits]={}
        key=val>>(48-maskbits)
        buckets[maskbits][key]=vendor
    masks=sorted(buckets.keys(),reverse=True)
    return buckets,masks

def norm_hex(s):
    return re.sub(r'[^0-9A-Fa-f]','',s).upper()

def mac_to_format(mac,fmt):
    m=norm_hex(mac)
    if len(m)!=12: return mac
    if fmt=="AA:BB:CC:DD:EE:FF":
        return ":".join([m[i:i+2] for i in range(0,12,2)])
    if fmt=="AAAA.BBBB.CCCC":
        return ".".join([m[i:i+4] for i in range(0,12,4)])
    return mac

def lookup_vendor(m,buckets,masks):
    h=norm_hex(m)
    if len(h)<6: return "Unknown"
    mac_int=int(h.ljust(12,'0')[:12],16)
    for mask in masks:
        key=mac_int>>(48-mask)
        v=buckets[mask].get(key)
        if v: return v
    return "Unknown"

def parse_ios_mac_table(text):
    rows=[]
    for line in text.splitlines():
        if not line.strip(): continue
        parts=line.strip().split()
        if len(parts)<4: continue
        vlan, mac, typ, iface = parts[0], parts[1], parts[2], parts[3]
        if iface.upper()=="CPU": continue
        if not re.fullmatch(r'\d+', vlan): continue
        if not re.fullmatch(r'[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{12}|([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}', mac):
            continue
        rows.append((vlan,mac,typ,iface))
    return rows

IFACE_WEIGHT={"Fa":0,"Eth":0,"Gi":1,"Te":2,"Fo":3,"Hu":4,"Tw":5,"Po":9}
def iface_sort_key(s):
    t=re.match(r'([A-Za-z]+)([\d/]+)',s.strip())
    if not t: return (10,[s])
    p=t.group(1)
    nums=[int(x) for x in t.group(2).split('/') if x.isdigit()]
    w=IFACE_WEIGHT.get(p,5)
    return (w,nums)

def sanitize_filename(s):
    s=re.sub(r'[<>:"/\\|?*]+','-',s).strip()
    return s or "MAC-OUI"

def detect_hostname(text):
    for line in text.splitlines():
        m=re.match(r'^\s*([A-Za-z0-9._:-]+)[>#]', line)
        if m:
            return m.group(1)
    return ""

class App:
    def __init__(self,root):
        self.root=root
        self.root.title("Cisco MAC OUI Resolver")
        try:
            self.buckets,self.masks=load_manuf()
        except Exception as e:
            messagebox.showerror("Error loading vendor DB", str(e))
            self.buckets,self.masks={},[]
        top=ttk.Frame(root); top.pack(fill="both",expand=True,padx=10,pady=10)
        srcrow=ttk.Frame(top); srcrow.pack(fill="x",pady=(0,6))
        ttk.Label(srcrow,text="Source Device:").pack(side="left")
        self.src_var=tk.StringVar()
        ttk.Entry(srcrow,textvariable=self.src_var,width=32).pack(side="left",padx=(6,12))
        ttk.Label(srcrow,text="MAC Format:").pack(side="left")
        self.mac_fmt=tk.StringVar(value="AA:BB:CC:DD:EE:FF")
        ttk.Combobox(srcrow,textvariable=self.mac_fmt,values=["As seen","AA:BB:CC:DD:EE:FF","AAAA.BBBB.CCCC"],state="readonly",width=20).pack(side="left",padx=(6,12))
        self.exclude_po=tk.BooleanVar(value=True)
        ttk.Checkbutton(srcrow,text="Exclude Port-Channels (Po*)",variable=self.exclude_po).pack(side="left")
        btns=ttk.Frame(top); btns.pack(fill="x",pady=(6,6))
        ttk.Button(btns,text="Load File",command=self.load_file).pack(side="left",padx=4)
        ttk.Button(btns,text="Paste",command=self.paste_clipboard).pack(side="left",padx=4)
        ttk.Button(btns,text="Lookup",command=self.lookup).pack(side="left",padx=4)
        ttk.Button(btns,text="Export CSV",command=self.export_csv).pack(side="left",padx=4)
        ttk.Button(btns,text="Update DB",command=self.update_db).pack(side="left",padx=4)
        ttk.Button(btns,text="Import DB",command=self.import_db).pack(side="left",padx=4)
        ttk.Button(btns,text="Clear",command=self.clear_all).pack(side="left",padx=4)
        self.txt=tk.Text(top,height=10,wrap="none"); self.txt.pack(fill="x")
        cols=("Hostname","VLAN","Interface","Mac","Vendor")
        self.tree=ttk.Treeview(top,columns=cols,show="headings",height=18)
        for c in cols: self.tree.heading(c,text=c)
        self.tree.column("Hostname",width=180,stretch=False)
        self.tree.column("VLAN",width=80,stretch=False)
        self.tree.column("Interface",width=140,stretch=False)
        self.tree.column("Mac",width=180,stretch=False)
        self.tree.column("Vendor",width=520,stretch=True)
        self.tree.pack(fill="both",expand=True,pady=(6,0))
        self.status_var=tk.StringVar(value="Ready")
        ttk.Label(root,textvariable=self.status_var,anchor="w").pack(fill="x",padx=10,pady=(0,10))

    def set_status(self,msg):
        self.status_var.set(msg); self.root.update_idletasks()

    def maybe_autofill_hostname(self, text):
        if not self.src_var.get().strip():
            h=detect_hostname(text)
            if h: self.src_var.set(h)

    def paste_clipboard(self):
        try:
            d=self.root.clipboard_get()
            if not d.endswith("\n"): d=d+"\n"
            self.txt.insert("end",d)
            self.maybe_autofill_hostname(d)
        except tk.TclError:
            pass

    def load_file(self):
        p=filedialog.askopenfilename(title="Open MAC table",filetypes=[("Text","*.txt"),("All","*.*")])
        if not p: return
        with open(p,"r",encoding="utf-8",errors="ignore") as f:
            content=f.read()
        self.txt.insert("end",content)
        self.maybe_autofill_hostname(content)
        self.set_status(f"Loaded {os.path.basename(p)}")

    def clear_all(self):
        self.txt.delete("1.0","end")
        for i in self.tree.get_children(): self.tree.delete(i)
        self.set_status("Cleared")

    def update_db(self):
        def run():
            try:
                self.set_status("Updating vendor DB...")
                fetch_manuf()
                self.buckets,self.masks=load_manuf()
                self.set_status("Vendor DB updated")
            except Exception:
                self.set_status("Download failed; choose local manuf")
                try:
                    chosen=import_manuf_from_file()
                    if chosen:
                        self.buckets,self.masks=load_manuf()
                        self.set_status("Vendor DB loaded from local file")
                except Exception as e:
                    messagebox.showerror("Error",str(e))
        threading.Thread(target=run,daemon=True).start()

    def import_db(self):
        chosen=import_manuf_from_file()
        if not chosen:
            self.set_status("Import cancelled"); return
        try:
            self.buckets,self.masks=load_manuf()
            self.set_status("Vendor DB imported")
        except Exception as e:
            messagebox.showerror("Error",str(e))

    def lookup(self):
        raw=self.txt.get("1.0","end")
        if not self.src_var.get().strip():
            self.maybe_autofill_hostname(raw)
        src=self.src_var.get().strip() or ""
        rows=parse_ios_mac_table(raw)
        if not rows: self.set_status("No parsable rows"); return
        excl=self.exclude_po.get(); fmt=self.mac_fmt.get()
        for i in self.tree.get_children(): self.tree.delete(i)
        self.set_status("Resolving...")
        def run():
            resolved=[]
            for vlan,mac,typ,iface in rows:
                if excl and iface.startswith("Po"): continue
                mac_out=mac_to_format(mac,fmt)
                vendor=lookup_vendor(mac,self.buckets,self.masks)
                resolved.append((src,vlan,iface,mac_out,vendor))
            resolved.sort(key=lambda r: iface_sort_key(r[2]))
            for r in resolved: self.tree.insert("",tk.END,values=r)
            self.set_status(f"Resolved {len(resolved)} rows")
        threading.Thread(target=run,daemon=True).start()

    def export_csv(self):
        if not self.tree.get_children(): self.set_status("Nothing to export"); return
        base=sanitize_filename(self.src_var.get().strip())
        default=f"{base}-MAC-OUI.csv" if base else "MAC-OUI.csv"
        p=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV","*.csv")],initialfile=default)
        if not p: return
        rows=[self.tree.item(iid,"values") for iid in self.tree.get_children()]
        rows.sort(key=lambda r: iface_sort_key(r[2]))
        with open(p,"w",newline="",encoding="utf-8") as f:
            w=csv.writer(f); w.writerow(["Hostname","VLAN","Interface","Mac","Vendor"])
            for r in rows: w.writerow(r)
        self.set_status(f"Exported {os.path.basename(p)}")

if __name__=="__main__":
    root=tk.Tk()
    App(root)
    root.mainloop()
