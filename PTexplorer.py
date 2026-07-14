"""
Module responsible for decrypting Cisco Packet Tracer (.pkt) files to XML.
Also provides helper functions for analysis (used by grader.py).
"""

import securedypkt
import xml.etree.ElementTree as ET
import re
import os
import sys
import argparse


def decrypt_pkt_file(pkt_file_path: str) -> str:
    """
    Decrypt a .pkt file and return the XML content as a string.
    
    Args:
        pkt_file_path: Path to the .pkt file
        
    Returns:
        XML content as string
        
    Raises:
        FileNotFoundError: If the .pkt file doesn't exist
        Exception: If decryption fails
    """
    if not os.path.exists(pkt_file_path):
        raise FileNotFoundError(f"Packet Tracer file not found: {pkt_file_path}")
    
    try:
        # Read the .pkt file as bytes
        with open(pkt_file_path, 'rb') as f:
            pkt_data = f.read()
        
        # Decrypt using securedypkt
        xml_bytes = securedypkt.decrypt_pkt(pkt_data)
        
        # Convert bytes to string (assuming UTF-8 encoding)
        xml_content = xml_bytes.decode('utf-8')
        
        return xml_content
        
    except Exception as e:
        raise Exception(f"Failed to decrypt .pkt file {pkt_file_path}: {str(e)}")


def decrypt_pkt_bytes(pkt_data: bytes) -> str:
    """
    Decrypt .pkt file bytes and return the XML content as a string.
    
    Args:
        pkt_data: Raw bytes of the .pkt file
        
    Returns:
        XML content as string
        
    Raises:
        Exception: If decryption fails
    """
    try:
        # Decrypt using securedypkt
        xml_bytes = securedypkt.decrypt_pkt(pkt_data)
        
        # Convert bytes to string (assuming UTF-8 encoding)
        xml_content = xml_bytes.decode('utf-8')
        
        return xml_content
        
    except Exception as e:
        raise Exception(f"Failed to decrypt .pkt data: {str(e)}")


def count_pt8200_routers(xml_content: str) -> int:
    """
    Count the number of PT8200 routers in the XML content.
    
    Args:
        xml_content: XML string from decrypted .pkt file
        
    Returns:
        Number of PT8200 routers found
    """
    try:
        root = ET.fromstring(xml_content)
        count = 0
        
        # Search through all elements for PT8200 routers
        for elem in root.iter():
            # Check element tag
            tag_lower = elem.tag.lower()
            if 'pt8200' in tag_lower or '8200' in tag_lower:
                count += 1
                continue  # Skip further checks for this element to avoid double counting
            
            # Check attributes for model information
            found_in_attrs = False
            for attr_name, attr_value in elem.attrib.items():
                attr_name_lower = attr_name.lower()
                attr_value_lower = attr_value.lower()
                if ('pt8200' in attr_value_lower or 
                    '8200' in attr_value_lower or
                    'pt8200' in attr_name_lower or
                    '8200' in attr_name_lower):
                    count += 1
                    found_in_attrs = True
                    break  # Break inner loop, continue with next element
            
            if found_in_attrs:
                continue  # Skip text check if already found in attributes
            
            # Check text content
            if elem.text:
                text_lower = elem.text.lower()
                if 'pt8200' in text_lower or '8200' in text_lower:
                    count += 1
        
        return count
        
    except ET.ParseError:
        # If XML parsing fails, fall back to string counting
        xml_lower = xml_content.lower()
        return xml_lower.count('pt8200') + xml_lower.count('8200')
    except Exception:
        # Fallback to simple string counting
        xml_lower = xml_content.lower()
        return xml_lower.count('pt8200') + xml_lower.count('8200')


def check_connection_between_devices(xml_content: str, device1_identifier: str = 'pt8200', 
                                   device2_identifier: str = 'pt8200') -> bool:
    """
    Check if two devices of specified types are connected in the topology.
    
    Args:
        xml_content: XML string from decrypted .pkt file
        device1_identifier: Identifier for first device type
        device2_identifier: Identifier for second device type
        
    Returns:
        True if devices are connected, False otherwise
    """
    try:
        # Parse the XML to get structured access
        root = ET.fromstring(xml_content)
        
        # Look for explicit LINKS section - this is the most reliable indicator
        links_section = root.find(".//LINKS")
        if links_section is not None:
            # Check if there are any actual link elements within LINKS
            link_elements = links_section.findall(".//LINK")
            if len(link_elements) > 0:
                # Additional check: verify that both device types exist in the topology
                xml_lower = xml_content.lower()
                has_device1 = device1_identifier in xml_lower
                has_device2 = device2_identifier in xml_lower
                return has_device1 and has_device2
        
        # Fallback: check for any connection-related elements
        connection_elements = []
        for elem in root.iter():
            tag_lower = elem.tag.lower()
            if any(conn_term in tag_lower for conn_term in ['link', 'connection', 'cable', 'wire']):
                connection_elements.append(elem)
        
        if len(connection_elements) > 0:
            # Verify both device types exist
            xml_lower = xml_content.lower()
            has_device1 = device1_identifier in xml_lower
            has_device2 = device2_identifier in xml_lower
            return has_device1 and has_device2
        
        # Final fallback: if we can't find explicit connection elements,
        # check if both device types exist AND there are any connection-related terms
        # (but be more restrictive to avoid false positives)
        xml_lower = xml_content.lower()
        
        # Look for connection indicators in contexts that suggest actual links
        # Focus on areas around device definitions or in specific sections
        connection_indicators = [
            'link', 'connection', 'cable', 'wire'
        ]
        
        # Check if these appear in contexts that are likely to be actual connections
        # rather than just descriptions or properties
        has_meaningful_connection = False
        for indicator in connection_indicators:
            # Look for the indicator in contexts like <LINK>, <CONNECTION>, etc.
            pattern = rf'<[^>]*{re.escape(indicator)}[^>]*>'
            if re.search(pattern, xml_content, re.IGNORECASE):
                has_meaningful_connection = True
                break
        
        return has_meaningful_connection
        
    except ET.ParseError:
        # If XML parsing fails, fall back to improved string-based approach
        xml_lower = xml_content.lower()
        has_device1 = device1_identifier in xml_lower
        has_device2 = device2_identifier in xml_lower
        
        if not (has_device1 and has_device2):
            return False
        
        # Look for actual link/connection elements in the XML
        link_pattern = r'<LINK[^>]*>.*?</LINK>'
        connection_pattern = r'<(CONNECTION|LINK|CABLE|WIRE)[^>]*>.*?</\1>'
        
        has_links = bool(re.search(link_pattern, xml_content, re.IGNORECASE | re.DOTALL))
        has_connections = bool(re.search(connection_pattern, xml_content, re.IGNORECASE | re.DOTALL))
        
        return has_links or has_connections
        
    except Exception:
        # Final fallback to basic approach
        xml_lower = xml_content.lower()
        has_device1 = device1_identifier in xml_lower
        has_device2 = device2_identifier in xml_lower
        return has_device1 and has_device2


def main():
    """Command-line interface for PTexplorer: decrypt .pkt to XML."""
    parser = argparse.ArgumentParser(
        description='Decrypt Cisco Packet Tracer (.pkt) files to XML.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -d lab.pkt                    # Decrypt lab.pkt and output XML to stdout
  %(prog)s -d lab.pkt -o lab.xml         # Decrypt lab.pkt and save XML to lab.xml
  %(prog)s -h                            # Show this help message
        '''
    )
    
    parser.add_argument('-d', '--decrypt', metavar='FILE',
                        help='Decrypt the specified .pkt file and output XML')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='Output file for decrypted XML (default: stdout)')
    
    args = parser.parse_args()
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    try:
        if args.decrypt:
            # Decrypt mode
            xml_content = decrypt_pkt_file(args.decrypt)
            
            if args.output:
                # Write to specified output file
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(xml_content)
                print(f"Decrypted XML written to: {args.output}")
            else:
                # Output to stdout
                print(xml_content)
        else:
            parser.print_help()
            sys.exit(1)
            
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()