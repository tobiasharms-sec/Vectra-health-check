#!/usr/bin/env python3
"""
Enhanced Vectra Health Check Script

This script performs a comprehensive health check of a Vectra platform deployment, displaying:
- System information (uptime, serial number, version)
- External connector status and details
- EDR configuration status and details
- Memory and CPU usage
- Network and traffic information
- Disk usage and RAID status
- Detection model health
- Vectra Match status

Uses the vectra_auth.py module for authentication.

Author: Tobias Harms
Version: 2.0
"""

import argparse
import json
import sys
import datetime
import time
from collections import defaultdict
import requests
import vectra_auth

# Try to import tabulate for table formatting
try:
    from tabulate import tabulate
except ImportError:
    # Define a simple tabulate function if the package is not available
    def tabulate(data, headers=None, tablefmt=None):
        result = []
        if headers:
            result.append("\t".join(headers))
            result.append("-" * 80)
        for row in data:
            result.append("\t".join(str(cell) for cell in row))
        return "\n".join(result)

# Disable insecure connection warnings if using self-signed certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_health_data(base_url, headers):
    """
    Retrieve health data from the Vectra platform
    """
    response = requests.get(f"{base_url}/api/v3.4/health", 
                           headers=headers, 
                           verify=False)
    response.raise_for_status()
    return response.json()

def get_external_connectors(base_url, headers):
    """
    Retrieve external connector status
    """
    response = requests.get(f"{base_url}/api/v3.4/health/external_connectors", 
                           headers=headers, 
                           verify=False)
    response.raise_for_status()
    return response.json()

def get_external_connectors_details(base_url, headers):
    """
    Retrieve detailed external connector information
    """
    response = requests.get(f"{base_url}/api/v3.4/health/external_connectors/details", 
                           headers=headers, 
                           verify=False)
    response.raise_for_status()
    return response.json()

def get_edr_status(base_url, headers):
    """
    Retrieve EDR status
    """
    response = requests.get(f"{base_url}/api/v3.4/health/edr", 
                           headers=headers, 
                           verify=False)
    response.raise_for_status()
    return response.json()

def get_edr_details(base_url, headers):
    """
    Retrieve detailed EDR information
    """
    response = requests.get(f"{base_url}/api/v3.4/health/edr/details", 
                           headers=headers, 
                           verify=False)
    response.raise_for_status()
    return response.json()

def get_network_brain_ping(base_url, headers):
    """
    Retrieve network brain connection status
    """
    response = requests.get(f"{base_url}/api/v3.4/health/network_brain/ping", 
                           headers=headers, 
                           verify=False)
    response.raise_for_status()
    return response.json()

def get_detection_health(base_url, headers):
    """
    Retrieve detection model health information
    """
    response = requests.get(f"{base_url}/api/v3.4/health/detection", 
                           headers=headers, 
                           verify=False)
    response.raise_for_status()
    return response.json()

def get_prioritized_hosts(base_url, headers):
    """
    Retrieve count of prioritized hosts with detections
    """
    params = {"type": "host", "is_prioritized": "true", "page_size": 1}
    response = requests.get(f"{base_url}/api/v3.4/entities", 
                           headers=headers, 
                           params=params,
                           verify=False)
    response.raise_for_status()
    return response.json()["count"]

def get_entities_with_detections(base_url, headers):
    """
    Retrieve count of entities with detections
    """
    try:
        # Query for hosts with detections
        host_params = {"type": "host", "last_detection_timestamp_gte": "2000-01-01T00:00:00Z", "page_size": 1}
        host_response = requests.get(f"{base_url}/api/v3.4/entities", 
                               headers=headers, 
                               params=host_params,
                               verify=False)
        host_response.raise_for_status()
        host_count = host_response.json()["count"]
        
        # Query for accounts with detections
        account_params = {"type": "account", "last_detection_timestamp_gte": "2000-01-01T00:00:00Z", "page_size": 1}
        account_response = requests.get(f"{base_url}/api/v3.4/entities", 
                                 headers=headers, 
                                 params=account_params,
                                 verify=False)
        account_response.raise_for_status()
        account_count = account_response.json()["count"]
        
        return host_count + account_count
    except Exception as e:
        raise Exception(f"Error getting entities with detections: {str(e)}")

def get_entities_in_lockdown(base_url, headers):
    """
    Retrieve count of entities in lockdown
    """
    try:
        response = requests.get(f"{base_url}/api/v3.4/lockdown", 
                               headers=headers, 
                               verify=False)
        response.raise_for_status()
        
        # Count items in the results array
        if 'results' in response.json():
            return len(response.json()['results'])
        else:
            return 0
    except Exception as e:
        raise Exception(f"Error getting entities in lockdown: {str(e)}")

def get_vectra_match_status(base_url, headers):
    """
    Retrieve Vectra Match status
    """
    try:
        # First try to get Match available devices
        response = requests.get(f"{base_url}/api/v3.4/vectra-match/available-devices", 
                               headers=headers, 
                               verify=False)
        response.raise_for_status()
        available_devices = response.json().get('devices', [])
        
        # If we got devices, check their enablement status
        match_status = []
        for device in available_devices:
            device_serial = device.get('device_serial')
            if device_serial:
                # Check if Vectra Match is enabled for this device
                enablement_response = requests.get(
                    f"{base_url}/api/v3.4/vectra-match/enablement",
                    headers=headers,
                    params={'device_serial': device_serial},
                    verify=False
                )
                
                if enablement_response.status_code == 200:
                    status_data = enablement_response.json()
                    match_status.append({
                        'device_serial': device_serial,
                        'device_name': device.get('alias', device_serial),
                        'is_enabled': status_data.get('is_enabled', False),
                        'product_name': device.get('product_name', 'Unknown'),
                        'mode': device.get('mode', 'Unknown')
                    })
        
        return match_status
    except Exception as e:
        raise Exception(f"Error getting Vectra Match status: {str(e)}")

def format_uptime(uptime_str):
    """
    Format uptime string to be more readable
    """
    if not uptime_str:
        return "N/A"
        
    parts = uptime_str.split(', ')
    formatted_parts = []
    for part in parts:
        if "day" in part:
            formatted_parts.append(part)
        else:
            time_elements = part.split(':')
            if len(time_elements) == 3:
                formatted_parts.append(f"{time_elements[0]}h {time_elements[1]}m {time_elements[2]}s")
    
    return ", ".join(formatted_parts)

def format_bytes(bytes_value, decimal_places=2):
    """
    Format bytes into human-readable format (KB, MB, GB, etc.)
    """
    if not isinstance(bytes_value, (int, float)):
        return "N/A"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if bytes_value < 1024.0 or unit == 'PB':
            break
        bytes_value /= 1024.0
    
    return f"{bytes_value:.{decimal_places}f} {unit}"

def check_section_has_data(data, section_name):
    """
    Check if a section has data to display
    """
    if section_name not in data:
        return False
        
    if data[section_name] is None:
        return False
        
    if isinstance(data[section_name], dict) and not data[section_name]:
        return False
        
    return True

def check_network_has_data(health_data):
    """
    Check if network section has meaningful data to display
    """
    if 'network' not in health_data:
        return False
        
    network_data = health_data.get('network', {})
    
    # Check if interfaces data exists and is not empty
    has_interfaces = ('interfaces' in network_data and 
                     isinstance(network_data['interfaces'], list) and 
                     len(network_data['interfaces']) > 0)
                     
    # Check if traffic data exists and is not empty
    has_traffic = ('traffic' in network_data and 
                  isinstance(network_data['traffic'], list) and 
                  len(network_data['traffic']) > 0)
                  
    # Check if VLANs data exists
    has_vlans = 'vlans' in health_data and health_data['vlans']
    
    return has_interfaces or has_traffic or has_vlans

def check_disk_has_data(health_data):
    """
    Check if disk section has meaningful data to display
    """
    if 'disk' not in health_data:
        return False
        
    disk_data = health_data.get('disk', {})
    
    # Check if disk utilization data exists and has at least one filesystem
    has_disk_utilization = ('disk_utilization' in disk_data and 
                           isinstance(disk_data['disk_utilization'], dict) and 
                           len(disk_data['disk_utilization']) > 0)
    
    # Check if RAID information exists
    has_raid_info = any(k for k in disk_data.keys() if 'raid' in k.lower() and disk_data[k])
    
    return has_disk_utilization or has_raid_info

def print_system_info(health_data):
    """
    Print system information
    """
    system_data = health_data.get('system', {})
    version_data = system_data.get('version', {})
    
    vectra_auth.print_info("===== SYSTEM INFORMATION =====")
    
    # Create a table for system info
    system_table = []
    
    # Add serial number
    system_table.append(["Serial Number", system_data.get('serial_number', 'N/A')])
    
    # Add model
    system_table.append(["Model", version_data.get('model', 'N/A')])
    
    # Add version
    system_table.append(["Version", version_data.get('version', 'N/A')])
    
    # Add uptime
    if 'uptime' in system_data:
        system_table.append(["Uptime", format_uptime(system_data['uptime'])])
    
    # Add last update
    system_table.append(["Last Update", version_data.get('date', 'N/A')])
    
    # Print table
    print(tabulate(system_table, tablefmt="simple"))

def print_connector_status(connector_data, connector_details=None):
    """
    Print external connector status
    """
    if not connector_data or 'results' not in connector_data:
        vectra_auth.print_warning("No connector data available")
        return
    
    results = connector_data.get('results', {})
    details = connector_details.get('results', {}) if connector_details and isinstance(connector_details, dict) else {}
    
    vectra_auth.print_info("===== EXTERNAL CONNECTORS =====")
    
    # Create a table header for connectors
    connector_headers = ["Connector", "Status", "Authentication", "Details"]
    connector_table = []
    
    # Track available but disabled connectors
    disabled_connectors = []
    
    # Add data for each enabled connector
    for connector_name, connector_info in results.items():
        if not isinstance(connector_info, dict):
            continue
            
        conn_status = connector_info.get('connection_status', 'unknown')
        
        # Track disabled connectors
        if conn_status != 'enabled':
            disabled_connectors.append(connector_name)
            continue
            
        # Get authentication status
        auth_status = connector_info.get('auth_status', 'N/A')
        if isinstance(auth_status, dict):
            auth_status_str = ', '.join([f"{k}: {v}" for k, v in auth_status.items()])
        else:
            auth_status_str = str(auth_status)
        
        # Get additional details
        detail_text = ""
        if connector_name in details:
            detail_info = details[connector_name]
            if isinstance(detail_info, dict) and 'details' in detail_info:
                if isinstance(detail_info['details'], dict):
                    detail_text = json.dumps(detail_info['details'], indent=2)
                else:
                    detail_text = str(detail_info['details'])
        
        # Add error information if there are errors
        if 'error_states' in connector_info and connector_info['error_states']:
            if isinstance(connector_info['error_states'], dict):
                error_str = ', '.join([f"{k}: {v}" for k, v in connector_info['error_states'].items()])
                detail_text += f"\nErrors: {error_str}"
        
        # Add lockdown status if available
        if 'lockdown_status' in connector_info:
            detail_text += f"\nLockdown: {connector_info['lockdown_status']}"
            
        # Add row to table
        connector_table.append([connector_name, conn_status, auth_status_str, detail_text])
    
    # Print table
    if connector_table:
        print(tabulate(connector_table, headers=connector_headers, tablefmt="grid"))
    else:
        print("  No enabled connectors found")
        
    # Print available but not configured connectors
    if disabled_connectors:
        print("\nAvailable connectors (not configured):")
        for i, connector in enumerate(sorted(disabled_connectors)):
            print(f"  {i+1}. {connector}")
    else:
        print("\nAll available connectors are configured.")

def print_edr_status(edr_data, edr_details=None):
    """
    Print EDR configuration status
    """
    if not edr_data or 'results' not in edr_data:
        vectra_auth.print_warning("No EDR data available")
        return
    
    results = edr_data.get('results', {})
    details = edr_details.get('results', {}) if edr_details and isinstance(edr_details, dict) else {}
    
    vectra_auth.print_info("===== EDR CONFIGURATIONS =====")
    
    # Create a table header for EDR
    edr_headers = ["EDR Type", "Status", "Authentication", "Details"]
    edr_table = []
    
    # Track available but disabled EDR solutions
    disabled_edrs = []
    
    # Add data for each enabled EDR
    for edr_name, edr_info in results.items():
        if not isinstance(edr_info, dict):
            continue
            
        conn_status = edr_info.get('connection_status', 'unknown')
        
        # Track disabled EDRs
        if conn_status != 'enabled':
            disabled_edrs.append(edr_name)
            continue
            
        # Get authentication status
        auth_status = edr_info.get('auth_status', 'N/A')
        if isinstance(auth_status, dict):
            auth_status_str = ', '.join([f"{k}: {v}" for k, v in auth_status.items()])
        else:
            auth_status_str = str(auth_status)
        
        # Get additional details
        detail_text = ""
        if edr_name in details:
            detail_info = details[edr_name]
            if isinstance(detail_info, dict) and 'details' in detail_info:
                if isinstance(detail_info['details'], list):
                    for detail_item in detail_info['details']:
                        if isinstance(detail_item, dict) and 'text' in detail_item:
                            detail_text += f"{detail_item.get('text', '')}\n"
                elif isinstance(detail_info['details'], dict):
                    detail_text = json.dumps(detail_info['details'], indent=2)
                else:
                    detail_text = str(detail_info['details'])
        
        # Add error information if there are errors
        if 'error_states' in edr_info and edr_info['error_states']:
            if isinstance(edr_info['error_states'], dict):
                error_str = ', '.join([f"{k}: {v}" for k, v in edr_info['error_states'].items()])
                detail_text += f"\nErrors: {error_str}"
        
        # Add lockdown status if available
        if 'lockdown_status' in edr_info:
            detail_text += f"\nLockdown: {edr_info['lockdown_status']}"
            
        # Add row to table
        edr_table.append([edr_name, conn_status, auth_status_str, detail_text])
    
    # Print table
    if edr_table:
        print(tabulate(edr_table, headers=edr_headers, tablefmt="grid"))
    else:
        print("  No enabled EDR configurations found")
        
    # Print available but not configured EDRs
    if disabled_edrs:
        print("\nAvailable EDR solutions (not configured):")
        for i, edr in enumerate(sorted(disabled_edrs)):
            print(f"  {i+1}. {edr}")
    else:
        print("\nAll available EDR solutions are configured.")

def print_network_brain_status(brain_data):
    """
    Print network brain connection status
    """
    if not brain_data or 'results' not in brain_data:
        vectra_auth.print_warning("No network brain data available")
        return
    
    results = brain_data.get('results', {})
    
    vectra_auth.print_info("===== NETWORK BRAIN STATUS =====")
    
    # Create a table for network brain status
    brain_table = []
    
    # Add status
    brain_table.append(["Status", results.get('ping', 'N/A')])
    
    # Add latency
    brain_table.append(["Latency", results.get('latency', 'N/A')])
    
    # Print table
    print(tabulate(brain_table, tablefmt="simple"))

def print_memory_cpu_info(health_data):
    """
    Print memory and CPU usage information
    """
    vectra_auth.print_info("===== SYSTEM RESOURCES =====")
    
    # Print memory information
    if 'memory' in health_data and isinstance(health_data['memory'], dict):
        memory = health_data['memory']
        
        # Create a table for memory info
        memory_table = []
        memory_table.append(["Total Memory", format_bytes(memory.get('total_bytes', 0))])
        memory_table.append(["Used Memory", format_bytes(memory.get('used_bytes', 0))])
        memory_table.append(["Free Memory", format_bytes(memory.get('free_bytes', 0))])
        memory_table.append(["Usage", f"{memory.get('usage_percent', 'N/A')}%"])
        
        print("\nMemory Usage:")
        print(tabulate(memory_table, tablefmt="simple"))
    
    # Print CPU information
    if 'cpu' in health_data and isinstance(health_data['cpu'], dict):
        cpu = health_data['cpu']
        
        # Create a table for CPU info
        cpu_table = []
        cpu_table.append(["User", f"{cpu.get('user_percent', 'N/A')}%"])
        cpu_table.append(["System", f"{cpu.get('system_percent', 'N/A')}%"])
        cpu_table.append(["Nice", f"{cpu.get('nice_percent', 'N/A')}%"])
        cpu_table.append(["Idle", f"{cpu.get('idle_percent', 'N/A')}%"])
        
        print("\nCPU Usage:")
        print(tabulate(cpu_table, tablefmt="simple"))

def print_network_info(health_data):
    """
    Print network interface information
    """
    if 'network' not in health_data:
        return False
        
    network_data = health_data.get('network', {})
    has_data_to_show = False
    
    vectra_auth.print_info("===== NETWORK INFORMATION =====")
    
    # Print interface information
    if 'interfaces' in network_data and isinstance(network_data['interfaces'], list):
        interfaces = network_data['interfaces']
        
        # Create table headers
        interface_headers = ["Interface", "Status", "Speed (Mbps)"]
        interface_table = []
        
        # Add data for each interface
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            name = interface.get('name', 'Unknown')
            status = interface.get('link', 'Unknown')
            speed = interface.get('speed', 'Unknown')
            
            interface_table.append([name, status, speed])
        
        if interface_table:
            print("\nInterfaces:")
            print(tabulate(interface_table, headers=interface_headers, tablefmt="simple"))
            has_data_to_show = True
    
    # Print traffic information
    if 'traffic' in network_data and isinstance(network_data['traffic'], list):
        traffic = network_data['traffic']
        
        # Create table headers
        traffic_headers = ["Interface", "RX (Mbps)", "TX (Mbps)"]
        traffic_table = []
        
        # Add data for each interface
        for traffic_data in traffic:
            if not isinstance(traffic_data, dict):
                continue
            name = traffic_data.get('name', 'Unknown')
            rx = traffic_data.get('rx', 0)
            tx = traffic_data.get('tx', 0)
            
            traffic_table.append([name, rx, tx])
        
        if traffic_table:
            print("\nTraffic:")
            print(tabulate(traffic_table, headers=traffic_headers, tablefmt="simple"))
            has_data_to_show = True
    
    # Print VLAN information if available
    if 'vlans' in health_data and health_data['vlans']:
        print(f"\nVLANs: {health_data['vlans']}")
        has_data_to_show = True
        
    return has_data_to_show

def print_disk_info(health_data):
    """
    Print disk usage information
    """
    if 'disk' not in health_data:
        return False
    
    disk_data = health_data.get('disk', {})
    has_data_to_show = False
    
    vectra_auth.print_info("===== DISK INFORMATION =====")
    
    # Print disk utilization information
    disk_table = []
    if 'disk_utilization' in disk_data and isinstance(disk_data['disk_utilization'], dict):
        # Create table headers
        disk_headers = ["Filesystem", "Total", "Used", "Free", "Usage"]
        
        # Add data for each filesystem
        for fs, usage in disk_data['disk_utilization'].items():
            if not isinstance(usage, dict):
                # Skip if usage is not a dictionary
                continue
                
            total = format_bytes(usage.get('total', 0))
            used = format_bytes(usage.get('used', 0))
            free = format_bytes(usage.get('free', 0))
            usage_pct = f"{usage.get('usage_percentage', 'N/A')}%"
            
            disk_table.append([fs, total, used, free, usage_pct])
        
        if disk_table:
            print("\nDisk Usage:")
            print(tabulate(disk_table, headers=disk_headers, tablefmt="simple"))
            has_data_to_show = True
    
    # Print RAID information if available
    raid_table = []
    
    # Add relevant RAID information
    for key, value in disk_data.items():
        if 'raid' in key.lower():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    raid_table.append([f"{key} - {sub_key}", sub_value])
            else:
                raid_table.append([key, value])
    
    if raid_table:
        print("\nRAID Status:")
        print(tabulate(raid_table, tablefmt="simple"))
        has_data_to_show = True
        
    return has_data_to_show

def print_detection_health(detection_data):
    """
    Print detection model health information
    """
    if not detection_data:
        vectra_auth.print_warning("No detection health data available")
        return
    
    vectra_auth.print_info("===== DETECTION MODEL HEALTH =====")
    
    # Check if there's a check_results field
    check_results = detection_data.get('check_results', [])
    
    if not check_results:
        vectra_auth.print_success("All detection models are healthy")
        return
    
    # Create table for detection health
    detection_headers = ["Model", "Type", "Status", "Message"]
    detection_table = []
    
    # Add data for each check result
    for result in check_results:
        if not isinstance(result, dict):
            continue
            
        name = result.get('name', 'Unknown')
        detection_type = result.get('detection_type', 'Unknown')
        status = result.get('status', 'Unknown')
        message = result.get('message', '')
        
        # Check status and add colored output
        status_formatted = status
        if status.lower() == 'ok':
            status_formatted = f"OK"
        elif status.lower() == 'critical':
            status_formatted = f"CRITICAL"
        
        detection_table.append([name, detection_type, status_formatted, message])
    
    # Print table
    if detection_table:
        print(tabulate(detection_table, headers=detection_headers, tablefmt="grid"))

def print_vectra_match_status(match_status):
    """
    Print Vectra Match status
    """
    if not match_status:
        return False
        
    vectra_auth.print_info("===== VECTRA MATCH STATUS =====")
    
    # Create table headers
    match_headers = ["Device", "Product", "Mode", "Vectra Match Status"]
    match_table = []
    
    # Add data for each device
    for device in match_status:
        device_name = device.get('device_name', 'Unknown')
        product_name = device.get('product_name', 'Unknown')
        mode = device.get('mode', 'Unknown')
        is_enabled = "Enabled" if device.get('is_enabled', False) else "Disabled"
        
        match_table.append([device_name, product_name, mode, is_enabled])
    
    # Print the table
    if match_table:
        print(tabulate(match_table, headers=match_headers, tablefmt="simple"))
        return True
    
    return False

def print_section_separator():
    """Print a visual separator between sections"""
    print("\n" + "-" * 80 + "\n")

def main():
    parser = argparse.ArgumentParser(description='Enhanced Vectra Health Check Script')
    parser.add_argument('--host', help='Vectra platform hostname or IP (overrides config file)')
    parser.add_argument('--env-file', default='cred.env', help='Environment file with credentials (default: cred.env)')
    parser.add_argument('--output', '-o', help='Output file to save the health check results')
    parser.add_argument('--no-details', action='store_true', help='Skip detailed information for connectors and EDR')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode with more verbose error messages')
    args = parser.parse_args()
    
    # Get configuration
    config = vectra_auth.load_config(args.env_file)
    if not config:
        sys.exit(1)
    
    # Override host if provided via command line
    if args.host:
        config['vectra_url'] = f"https://{args.host}/"
    
    base_url = config['vectra_url'].rstrip('/')
    
    # If outputting to a file, redirect stdout
    original_stdout = sys.stdout
    output_file = None
    if args.output:
        try:
            output_file = open(args.output, 'w')
            sys.stdout = output_file
        except Exception as e:
            vectra_auth.print_error(f"Error opening output file: {str(e)}")
            sys.exit(1)
    
    try:
        # Show start message
        print("Starting Vectra health check...")
        start_time = time.time()
        
        # Get auth token from vectra_auth.py
        token_data = vectra_auth.get_token(config, env_file=args.env_file)
        if not token_data:
            vectra_auth.print_error("Authentication failed. Please check your credentials.")
            sys.exit(1)
            
        headers = {
            'Authorization': f'Bearer {token_data["access_token"]}',
            'Content-Type': 'application/json'
        }
        
        # Collection data with progress indicators
        print("Collecting health data...")
        all_data = {}
        
        # Collect health data with error handling
        try:
            all_data['health'] = get_health_data(base_url, headers)
            print("✓ Collected basic health data")
        except Exception as e:
            vectravectra_auth.print_error(f"Failed to collect health data: {str(e)}")
            all_data['health'] = {}
        
        # Collect external connector status
        try:
            all_data['connectors'] = get_external_connectors(base_url, headers)
            print("✓ Collected connector status")
        except Exception as e:
            vectra_auth.print_error(f"Failed to collect connector status: {str(e)}")
            all_data['connectors'] = {}
        
        # Collect external connector details (if requested)
        if not args.no_details:
            try:
                all_data['connector_details'] = get_external_connectors_details(base_url, headers)
                print("✓ Collected connector details")
            except Exception as e:
                vectra_auth.print_error(f"Failed to collect connector details: {str(e)}")
                all_data['connector_details'] = {}
        
        # Collect EDR status
        try:
            all_data['edr'] = get_edr_status(base_url, headers)
            print("✓ Collected EDR status")
        except Exception as e:
            vectra_auth.print_error(f"Failed to collect EDR status: {str(e)}")
            all_data['edr'] = {}
        
        # Collect EDR details (if requested)
        if not args.no_details:
            try:
                all_data['edr_details'] = get_edr_details(base_url, headers)
                print("✓ Collected EDR details")
            except Exception as e:
                vectra_auth.print_error(f"Failed to collect EDR details: {str(e)}")
                all_data['edr_details'] = {}
        
        # Collect network brain status
        try:
            all_data['network_brain'] = get_network_brain_ping(base_url, headers)
            print("✓ Collected network brain status")
        except Exception as e:
            vectra_auth.print_error(f"Failed to collect network brain status: {str(e)}")
            all_data['network_brain'] = {}
        
        # Collect detection health
        try:
            all_data['detection'] = get_detection_health(base_url, headers)
            print("✓ Collected detection health")
        except Exception as e:
            vectra_auth.print_warning(f"Failed to collect detection health (this may be expected): {str(e)}")
            all_data['detection'] = None
        
        # Collect data measurements for reporting purposes
        try:
            all_data['prioritized_entities'] = get_prioritized_hosts(base_url, headers)
            print("✓ Collected metrics data - 1/3")
        except Exception as e:
            vectra_auth.print_error(f"Failed to collect metric 1: {str(e)}")
            all_data['prioritized_entities'] = 0
            
        try:
            all_data['entities_with_detections'] = get_entities_with_detections(base_url, headers)
            print("✓ Collected metrics data - 2/3")
        except Exception as e:
            vectra_auth.print_error(f"Failed to collect metric 2: {str(e)}")
            all_data['entities_with_detections'] = 0
            
        try:
            all_data['entities_in_lockdown'] = get_entities_in_lockdown(base_url, headers)
            print("✓ Collected metrics data - 3/3")
        except Exception as e:
            vectra_auth.print_error(f"Failed to collect metric 3: {str(e)}")
            all_data['entities_in_lockdown'] = 0
            
        # Collect Vectra Match status
        try:
            all_data['vectra_match'] = get_vectra_match_status(base_url, headers)
            print("✓ Collected Vectra Match status")
        except Exception as e:
            vectra_auth.print_error(f"Failed to collect Vectra Match status: {str(e)}")
            all_data['vectra_match'] = []
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        # Print header
        hostname = args.host or config['vectra_url'].replace('https://', '').replace('/', '')
        print("\n" + "="*80)
        print(f"VECTRA HEALTH CHECK REPORT - {hostname}")
        print(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Data collection completed in {elapsed_time:.2f} seconds")
        print("="*80)
        
        # Print each section with error handling (only if there's data to show)
        printed_section = False
        
        # Print system information (if available)
        if check_section_has_data(all_data, 'health') and 'system' in all_data['health']:
            try:
                print_system_info(all_data['health'])
                print_section_separator()
                printed_section = True
            except Exception as e:
                vectra_auth.print_error(f"Error displaying system information: {str(e)}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
        
        # Print network brain status (if available)
        if check_section_has_data(all_data, 'network_brain'):
            try:
                print_network_brain_status(all_data['network_brain'])
                print_section_separator()
                printed_section = True
            except Exception as e:
                vectra_auth.print_error(f"Error displaying network brain status: {str(e)}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
        
        # Print connector status (if available)
        if check_section_has_data(all_data, 'connectors'):
            try:
                print_connector_status(all_data['connectors'], 
                                    all_data.get('connector_details') if not args.no_details else None)
                print_section_separator()
                printed_section = True
            except Exception as e:
                vectra_auth.print_error(f"Error displaying connector status: {str(e)}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
        
        # Print EDR status (if available)
        if check_section_has_data(all_data, 'edr'):
            try:
                print_edr_status(all_data['edr'], 
                              all_data.get('edr_details') if not args.no_details else None)
                print_section_separator()
                printed_section = True
            except Exception as e:
                vectra_auth.print_error(f"Error displaying EDR status: {str(e)}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
        
        # Print memory/CPU information (if available)
        if check_section_has_data(all_data, 'health') and ('memory' in all_data['health'] or 'cpu' in all_data['health']):
            try:
                print_memory_cpu_info(all_data['health'])
                print_section_separator()
                printed_section = True
            except Exception as e:
                vectra_auth.print_error(f"Error displaying memory/CPU information: {str(e)}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
        
        # Print network information (if available and has data)
        if check_section_has_data(all_data, 'health') and check_network_has_data(all_data['health']):
            try:
                section_printed = print_network_info(all_data['health'])
                if section_printed:
                    print_section_separator()
                    printed_section = True
            except Exception as e:
                vectra_auth.print_error(f"Error displaying network information: {str(e)}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
        
        # Print disk information (if available and has data)
        if check_section_has_data(all_data, 'health') and check_disk_has_data(all_data['health']):
            try:
                section_printed = print_disk_info(all_data['health'])
                if section_printed:
                    print_section_separator()
                    printed_section = True
            except Exception as e:
                vectra_auth.print_error(f"Error displaying disk information: {str(e)}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
        
        # Print detection health information (if available)
        if check_section_has_data(all_data, 'detection'):
            try:
                print_detection_health(all_data['detection'])
                print_section_separator()
                printed_section = True
            except Exception as e:
                vectra_auth.print_error(f"Error displaying detection health: {str(e)}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
        
        # Print Vectra Match status (if available)
        if check_section_has_data(all_data, 'vectra_match'):
            try:
                section_printed = print_vectra_match_status(all_data['vectra_match'])
                if section_printed:
                    print_section_separator()
                    printed_section = True
            except Exception as e:
                vectra_auth.print_error(f"Error displaying Vectra Match status: {str(e)}")
                if args.debug:
                    import traceback
                    traceback.print_exc()
                
        # If no sections were printed, show a message
        if not printed_section:
            vectra_auth.print_warning("No health data available to display")
        
        # Print summary
        print("\n" + "="*80)
        vectra_auth.print_success(f"Health check completed!")
        print("="*80 + "\n")
        
    except KeyboardInterrupt:
        vectra_auth.print_warning("\nHealth check interrupted by user.")
    except Exception as e:
        vectra_auth.print_error(f"Error during health check: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Restore stdout if it was redirected
        if output_file:
            sys.stdout = original_stdout
            output_file.close()
            vectra_auth.print_success(f"Health check report saved to {args.output}")

if __name__ == "__main__":
    main()