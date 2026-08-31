
import sys
from pathlib import Path

# Cesta k adresáři, ve kterém leží tento skript (složka 'tests')
SCRIPT_DIR = Path(__file__).resolve().parent

# Přidání nadřazené složky (CiscoPacketTracer-AIgrader) do sys.path pro import PTexplorer
sys.path.append(str(SCRIPT_DIR.parent))

import re
import PTexplorer

# Dynamické sestavení absolutních cest k .pkt souborům
file_disconnected = SCRIPT_DIR / 'CPT-PKTtestFiles' / 'twoPT8200-disconnected.pkt'
file_connected = SCRIPT_DIR / 'CPT-PKTtestFiles' / 'twoPT8200-conneted.pkt'

xml_content = PTexplorer.decrypt_pkt_file(str(file_disconnected))
# Let's look for LINKS or similar sections

# Find sections that might contain link information
pattern = r'<LINKS[^>]*>.*?</LINKS>'
matches = re.findall(pattern, xml_content, re.IGNORECASE | re.DOTALL)
print('LINKS sections found:', len(matches))
for i, match in enumerate(matches):
    print(f'  LINKS section {i+1}: {match[:200]}...' if len(match) > 200 else f'  LINKS section {i+1}: {match}')

# Also look for any elements that might represent connections
# Použit nezachytávající skok (?:...) místo zachytávající skupiny, aby re.findall vracel celé tagy
connection_pattern = r'<(?:CONNECTION|LINK|CABLE|WIRE)[^>]*>.*?</(?:CONNECTION|LINK|CABLE|WIRE)>'
conn_matches = re.findall(connection_pattern, xml_content, re.IGNORECASE | re.DOTALL)
print('Connection-like elements found:', len(conn_matches))
for i, match in enumerate(conn_matches[:3]):
    print(f'  Connection element {i+1}: {match[:100]}...' if len(match) > 100 else f'  Connection element {i+1}: {match}')

# Let's also check the connected version for comparison
print('\n--- CONNECTED VERSION ---')
xml_content_conn = PTexplorer.decrypt_pkt_file(str(file_connected))
matches_conn = re.findall(pattern, xml_content_conn, re.IGNORECASE | re.DOTALL)
print('LINKS sections found:', len(matches_conn))
for i, match in enumerate(matches_conn):
    print(f'  LINKS section {i+1}: {match[:200]}...' if len(match) > 200 else f'  LINKS section {i+1}: {match}')

conn_matches_conn = re.findall(connection_pattern, xml_content_conn, re.IGNORECASE | re.DOTALL)
print('Connection-like elements found:', len(conn_matches_conn))
for i, match in enumerate(conn_matches_conn[:3]):
    print(f'  Connection element {i+1}: {match[:100]}...' if len(match) > 100 else f'  Connection element {i+1}: {match}')