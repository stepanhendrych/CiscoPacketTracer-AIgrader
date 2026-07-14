import PTexplorer
xml_content = PTexplorer.decrypt_pkt_file('CPT-PKTtestFiles/twoPT8200-disconnected.pkt')
print('Length:', len(xml_content))
print('Contains "link":', 'link' in xml_content.lower())
print('Contains "connection":', 'connection' in xml_content.lower())
print('Contains "cable":', 'cable' in xml_content.lower())
print('Contains "wire":', 'wire' in xml_content.lower())
# Let's see what's around the PT8200 mentions
import re
matches = list(re.finditer('pt8200', xml_content, re.IGNORECASE))
print('PT8200 matches:', len(matches))
for i, match in enumerate(matches[:3]):  # Show first 3 matches
    start = max(0, match.start() - 50)
    end = min(len(xml_content), match.end() + 50)
    print(f'  Match {i+1}: ...{xml_content[start:end]}...')