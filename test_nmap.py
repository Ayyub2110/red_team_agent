from src.tools.nmap_tools import nmap_scan
print(nmap_scan.invoke({"target": "172.28.0.2", "ports": "80,8080"}))
