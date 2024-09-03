# SWOSConnector

`SWOSConnector` is a Python class designed to interact with MikroTik SwitchOS devices via their REST API. It provides an easy-to-use interface for managing and retrieving data from these switches.

## Features

- Connect to MikroTik SwitchOS devices using REST API.
- Retrieve and set various configurations including VLANs, ports, and more.
- Fetch system information, interface statistics, logs, and other data.
- Manage Spanning Tree Protocol (STP), LLDP, DHCP snooping, and more.

## Installation
    You can install the required dependencies using `pip`:

    pip install requests
    
## Usage
    Basic Example
    from swos_connector import SWOSConnector

    url = 'http://192.168.88.1'
    username = 'admin'
    password = 'password'

    with SWOSConnector(url, username, password) as swos:
        system_info = swos.get_system_info()
        print(system_info)
# SWOSConnector API Functions

## System Information
- **`get_system_info()`**: Retrieve basic system information from the SwitchOS device, such as firmware version, model, and uptime.

## Interface Management
- **`get_interface_statistics()`**: Fetch statistics for all interfaces, including data rates, errors, and packet counts.
- **`get_interface_status()`**: Obtain the current status of all interfaces, such as link state and speed.
- **`get_mikrotik_links(port_number=None, port_name=None, output_only=None)`**: Fetches port link information, such as port names, statuses, and configurations.

## Port Configuration
- **`set_mikrotik_switch_port(port_number, port_name=None, enabled=True, auto_neg=True)`**: Configure a specific switch port, including enabling/disabling it, setting the port name, and configuring auto-negotiation.
- **`get_port_statistics()`**: Retrieve detailed statistics about each port, such as packet counts, error counts, etc.
- **`get_port_isolation()`**: Retrieve port isolation settings to understand how traffic is segregated between ports.
- **`get_poe_status()`**: Retrieve the status of Power over Ethernet (PoE) on each port.

## VLAN Management
- **`get_mikrotik_vlan_config()`**: Retrieve the current VLAN configuration of the device.
- **`get_mikrotik_vlan(port_number=None, port_name=None, vlan_id=None, output_only=None)`**: Retrieve VLAN settings for a specific port.
- **`set_mikrotik_vlan(port_number, vlan_mode=None, vlan_receive=None, vlan_id=None)`**: Configure VLAN settings on a specific port, including VLAN mode, VLAN receive mode, and VLAN ID.
- **`get_vlan_membership()`**: Retrieve detailed VLAN membership information for each port.

## Spanning Tree Protocol (STP)
- **`get_stp_status()`**: Get the current status of the Spanning Tree Protocol (STP) on the device.

## Link Layer Discovery Protocol (LLDP)
- **`get_lldp_neighbors()`**: Fetch the LLDP neighbors of the switch, providing details on connected devices.

## DHCP Snooping
- **`get_dhcp_snooping_info()`**: Retrieve information related to DHCP snooping, including trusted ports and snooping statistics.
- **`get_dhcp_snooping_status()`**: Retrieve information about DHCP snooping, including binding tables and status.

## Port Mirroring
- **`get_port_mirroring()`**: Get the current port mirroring configuration, including source and target ports.
- **`get_traffic_mirroring_settings()`**: Retrieve the configuration for traffic mirroring (port mirroring).

## IP Filtering
- **`get_ip_filter_rules()`**: Obtain the current IP filter rules configured on the device.

## Quality of Service (QoS)
- **`get_qos_settings()`**: Retrieve Quality of Service (QoS) settings, such as queue configurations and prioritization.

## Multicast
- **`get_multicast_settings()`**: Retrieve multicast-related settings, such as IGMP snooping status.

## System Logs
- **`get_system_logs()`**: Fetch the system logs from the SwitchOS device, useful for debugging and monitoring.

## MAC Address Table
- **`get_mac_address_table()`**: Retrieve the MAC address table, showing the learned MAC addresses and their corresponding ports.

## Host Information
- **`get_mikrotik_hosts()`**: Retrieve host information from the SwitchOS device, including IP and MAC addresses.

### Instructions for Use:

1. **Replace the placeholder imports** like `from swos_connector import SWOSConnector` with the actual import path for your project.
2. **Add more details** or modify the content based on specific usage or setup steps required for `SWOSConnector`.
3. **Update the License section** if your project uses a different license or add the `LICENSE` file if you haven't already.

This README should give users clear instructions on how to use your `SWOSConnector` class and understand its fun