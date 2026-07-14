#TODO: Not working, fix tommorow or later idk, if you are reading this, hello c:

import PTexplorer
xml_content = PTexplorer.decrypt_pkt_file('CPT-PKTtestFiles/twoPT8200-disconnected.pkt')
# Let's look for LINKS or similar sections
import re

# Find sections that might contain link information
pattern = r'<LINKS[^>]*>.*?</LINKS>'
matches = re.findall(pattern, xml_content, re.IGNORECASE | re.DOTALL)
print('LINKS sections found:', len(matches))
for i, match in enumerate(matches):
    print(f'  LINKS section {i+1}: {match[:200]}...' if len(match) > 200 else f'  LINKS section {i+1}: {match}')

# Also look for any elements that might represent connections
connection_pattern = r'<(CONNECTION|LINK|CABLE|WIRE)[^>]*>.*?</\1>'
conn_matches = re.findall(connection_pattern, xml_content, re.IGNORECASE | re.DOTALL)
print('Connection-like elements found:', len(conn_matches))
for i, match in enumerate(conn_matches[:3]):
    print(f'  Connection element {i+1}: {match[:100]}...' if len(match) > 100 else f'  Connection element {i+1}: {match}')

# Let's also check the connected version for comparison
print('\n--- CONNECTED VERSION ---')
xml_content_conn = PTexplorer.decrypt_pkt_file('CPT-PKTtestFiles/twoPT8200-conneted.pkt')
matches_conn = re.findall(pattern, xml_content_conn, re.IGNORECASE | re.DOTALL)
print('LINKS sections found:', len(matches_conn))
for i, match in enumerate(matches_conn):
    print(f'  LINKS section {i+1}: {match[:200]}...' if len(match) > 200 else f'  LINKS section {i+1}: {match}')

conn_matches_conn = re.findall(connection_pattern, xml_content_conn, re.IGNORECASE | re.DOTALL)
print('Connection-like elements found:', len(conn_matches_conn))
for i, match in enumerate(conn_matches_conn[:3]):
    print(f'  Connection element {i+1}: {match[:100]}...' if len(match) > 100 else f'  Connection element {i+1}: {match}')