"""Central registry for all security tools used by the red team agent."""

from .nmap_tools import nmap_scan, nmap_os_detection
from .network_tools import ping_sweep, tcp_syn_scan, banner_grab
from .http_tools import http_get, http_post, directory_bruteforce
from .metasploit_tools import msf_search_exploits, msf_run_exploit, msf_list_sessions

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
