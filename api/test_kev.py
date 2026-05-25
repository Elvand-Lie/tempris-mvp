import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from services.kev_loader import load_kev_data, get_all_findings

load_kev_data()
findings = get_all_findings()

print(f"Total findings: {len(findings)}")

rw = [f for f in findings if f["ransomware"]]
print(f"Ransomware-linked: {len(rw)}")

p0 = [f for f in findings if f["priority"] == "P0"]
print(f"Critical (P0): {len(p0)}")

if findings:
    top = findings[0]
    print(f"Top CVE: {top['cve']} - {top['title']}")
    print(f"Vendor: {top['vendor']} {top['product']}")
    print(f"CVSS: {top['cvss']}")
    print(f"Ransomware: {top['ransomware']}")
