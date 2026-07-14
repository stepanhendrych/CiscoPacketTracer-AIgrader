import PTexplorer
import xml.etree.ElementTree as ET

# Test disconnected file
xml_content = PTexplorer.decrypt_pkt_file('CPT-PKTtestFiles/twoPT8200-disconnected.pkt')
print('=== DISCONNECTED FILE DEBUG ===')
root = ET.fromstring(xml_content)

# Check for LINKS section
links_section = root.find('.//LINKS')
print(f'LINKS section found: {links_section is not None}')
if links_section is not None:
    print(f'LINKS section tag: {links_section.tag}')
    print(f'LINKS section attributes: {list(links_section.attrib.keys()) if hasattr(links_section, "attrib") else "None"}')
    print(f'LINKS section text: "{links_section.text}"')
    print(f'LINKS section tail: "{links_section.tail}"')
    print(f'Number of direct children: {len(list(links_section))}')
    
    # Check all descendants
    all_descendants = list(links_section.iter())
    print(f'Total descendants in LINKS section: {len(all_descendants)}')
    for i, elem in enumerate(all_descendants[:10]):  # Show first 10
        print(f'  {i}: tag="{elem.tag}", attributes={dict(elem.attrib) if elem.attrib else {}}')
    
    # Specifically look for LINK tags
    link_elements = []
    for elem in links_section.iter():
        if elem.tag.upper() == 'LINK':
            link_elements.append(elem)
    print(f'Exact LINK tag elements found: {len(link_elements)}')
    
    # Show a sample of the LINKS section content
    links_str = ET.tostring(links_section, encoding='unicode')
    print(f'LINKS section content (first 500 chars): {links_str[:500]}')

print()

# Test connected file for comparison
print('=== CONNECTED FILE DEBUG ===')
xml_content_conn = PTexplorer.decrypt_pkt_file('CPT-PKTtestFiles/twoPT8200-conneted.pkt')
root_conn = ET.fromstring(xml_content_conn)

links_section_conn = root_conn.find('.//LINKS')
print(f'LINKS section found: {links_section_conn is not None}')
if links_section_conn is not None:
    print(f'LINKS section tag: {links_section_conn.tag}')
    print(f'Number of direct children: {len(list(links_section_conn))}')
    
    # Specifically look for LINK tags
    link_elements_conn = []
    for elem in links_section_conn.iter():
        if elem.tag.upper() == 'LINK':
            link_elements_conn.append(elem)
    print(f'Exact LINK tag elements found: {len(link_elements_conn)}')
    
    if link_elements_conn:
        print('First LINK element details:')
        first_link = link_elements_conn[0]
        print(f'  Tag: {first_link.tag}')
        print(f'  Attributes: {dict(first_link.attrib)}')
        print(f'  Children: {len(list(first_link))}')
        for i, child in enumerate(list(first_link)):
            print(f'    Child {i}: {child.tag} = {child.text}')