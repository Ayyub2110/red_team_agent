"""Central registry for all security tools used by the red team agent."""

from .http_tools import directory_bruteforce, http_get, http_post
from .metasploit_tools import msf_list_sessions, msf_run_exploit, msf_search_exploits
from .network_tools import banner_grab, ping_sweep, tcp_syn_scan
from .nmap_tools import nmap_os_detection, nmap_scan

# Aggregate all tools into a single list for the LangGraph agent
tools = [
    nmap_scan,
    nmap_os_detection,
    ping_sweep,
    tcp_syn_scan,
    banner_grab,
    http_get,
    http_post,
    directory_bruteforce,
    msf_search_exploits,
    msf_run_exploit,
    msf_list_sessions,
]
