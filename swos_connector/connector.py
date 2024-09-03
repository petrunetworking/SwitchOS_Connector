import os
import requests
from requests.auth import HTTPDigestAuth
from io import BytesIO
import time
import json
import re
from .exceptions import MikrotikConnectionError
from .parser import convert_mikrotik_link_speed,convert_mikrotik_hex_array,convert_mikrotik_array_hex,convert_mikrotik_vlan_mode,convert_mikrotik_vlan_receive,convert_mikrotik_json
class SWOSConnector:
    """
        Initializes the SWOSConnector.

        :param url: The base URL of the SwitchOS device.
        :param username: Username for authentication.
        :param password: Password for authentication.
        :param retries: Number of retry attempts.
        :param delay: Delay (in seconds) between retries.
        """
    def __init__(self, url, username, password, retries=2, delay=5):
        self.url = url
        self.username = username
        self.password = password
        self.retries = retries
        self.delay = delay

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def send_rest_method(self, method, query, body=None):
        """
        Sends a REST request to the SwitchOS device.

        :param method: HTTP method (GET, POST, etc.).
        :param query: API endpoint for the request.
        :param body: Optional data to send with the request.
        :return: Response object if successful.
        :raises: Exception if all retry attempts fail.
        """
        headers = {
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "text/plain",
            "Origin": f"{self.url}",
            "Referer": f"{self.url}/index.html"
        }

        full_url = f"{self.url}/{query}"

        request_params = dict(
            method=method,
            url=full_url,
            headers=headers,
            auth=HTTPDigestAuth(username=self.username, password=self.password)
        )

        if body is not None:
            request_params['data'] = body

        for attempt in range(self.retries):
            try:
                response = requests.request(**request_params)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                print(f"Attempt {attempt + 1} failed: {e}")
                time.sleep(self.delay)
                if attempt == self.retries - 1:
                    raise MikrotikConnectionError("Maximum retry limit reached. Failed to send REST method.")

    def download_backup(self):
        """
        Downloads the backup from the SwitchOS device.

        :return: BytesIO object containing the backup data.
        :raises: Exception if the download fails after all retries.
        """
        query = 'backup.dl'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        
        if response.status_code == 200 and response.content:
            return BytesIO(response.content)
        else:
            raise MikrotikConnectionError(f"Failed to download the backup. Status Code: {response.status_code}")

    def test_authentication_swos(self):
        """
        Test if the provided username and password are correct and if the address belongs to a SwitchOS device.
        """
        query = 'sysinfo.b'
        method = 'GET'
        try:
            response = self.send_rest_method(method=method, query=query)
            if response.status_code == 200:
                system_info = convert_mikrotik_json(input_object=response.text)
                if system_info['board']=="Switchos":
                    return True, "Authentication successful and device identified as SwitchOS."
                else:
                    return False, "Authentication successful but the device might not be SwitchOS."
            elif response.status_code == 401:
                return False, "Authentication failed. Check the username and password."
            else:
                return False, f"Unexpected response: {response.status_code}"
        except requests.exceptions.RequestException as e:
            return False, f"Connection error: {str(e)}"

    def get_mikrotik_hosts(self):
        """
        Retrieve a list of hosts connected to the MikroTik switch.

        This function queries the MikroTik switch to gather information about all hosts currently connected.

        Returns:
            list: A list of hosts connected to the switch, including details such as IP address and MAC address.

        Example:
            hosts = get_mikrotik_hosts()
        """
        query = '!dhost.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        hosts = convert_mikrotik_json(input_object=response.text)
        links = self.get_mikrotik_links()

        output = []
        for host in hosts:
            mac_address = re.sub(r'(.{2})(?!$)', r'\1:', host['adr'])
            vlan_id = int(host['vid'], 16)
            port_number = int(host['prt'], 16) + 1
            port_name = links[port_number - 1]['port_name']
        
            obj = {
                'mac_address': mac_address,
                'vlan_id': vlan_id,
                'port_name': port_name,
                'port_number': port_number
            }
            output.append(obj)

        return output



    def get_mikrotik_links(self, port_number=None, port_name=None, output_only=None):
        """
        Retrieve information about network links on the MikroTik switch.

        This function fetches details about network links. Parameters can be used to filter the results by port number
        or port name. The `output_only` parameter can be used to control whether only specific types of output are returned.

        Args:
            port_number (int, optional): The port number to filter links by.
            port_name (str, optional): The port name to filter links by.
            output_only (str, optional): Specifies the type of output to return. Options may include 'summary', 'detailed', etc.

        Returns:
            list: A list of network links, including relevant details based on the specified filters.

        Example:
            links = get_mikrotik_links(port_number=1, output_only='summary')
        """
        query = 'link.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        links = convert_mikrotik_json(input_object=response.text)

        total_ports = int(links['prt'], 16)
        port_instance = 0
        output = []

        enabled_ports = convert_mikrotik_hex_array(hex_string=links['en'], pad_length=total_ports)
        link_active = convert_mikrotik_hex_array(hex_string=links['lnk'], pad_length=total_ports)
        auto_neg_ports = convert_mikrotik_hex_array(hex_string=links['an'], pad_length=total_ports)
        duplex_ports = convert_mikrotik_hex_array(hex_string=links['dpx'], pad_length=total_ports)

        while port_instance < total_ports:
            obj = {
                'enabled': enabled_ports[port_instance],
                'port_number': port_instance + 1,
                'port_name': bytes.fromhex(links['nm'][port_instance]).decode('utf-8'),
                'link_speed': convert_mikrotik_link_speed(hex_string=links['spd'][port_instance]),
                'link_active': link_active[port_instance],
                'auto_neg': auto_neg_ports[port_instance],
                'full_duplex': duplex_ports[port_instance],
            }
            port_instance += 1
            output.append(obj)

        output_options = ('port_name', 'enabled', 'auto_neg')
        if output_only in output_options:
            return [item[output_only] for item in output]
        elif port_number:
            return output[port_number - 1]
        elif port_name:
            return [ports for ports in output if ports['port_name'] == port_name]
        return output

    def get_mikrotik_vlan(self, port_number=None, port_name=None, vlan_id=None, output_only=None):
        """
            Retrieve VLAN configuration for a specific port on the MikroTik switch.

            This function returns VLAN settings for the specified port. Filtering can be applied based on port number, port name, 
            and VLAN ID. The `output_only` parameter specifies the type of output to return.

            Args:
                port_number (int, optional): The port number to filter VLAN settings by.
                port_name (str, optional): The port name to filter VLAN settings by.
                vlan_id (int, optional): The VLAN ID to filter by.
                output_only (str, optional): Specifies the type of output to return, such as 'summary' or 'detailed'.

            Returns:
                list: A list of dictionaries containing VLAN configuration details for the specified port.

            Example:
                vlan_config = get_mikrotik_vlan(port_number=1, vlan_id=100)
        """
        query = 'fwd.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        links = self.get_mikrotik_links()
        vlans = convert_mikrotik_json(input_object=response.text)

        total_ports = len(links)
        port_instance = 0
        output = []

        force_vlan = convert_mikrotik_hex_array(hex_string=vlans['fvid'], pad_length=total_ports)

        while port_instance < total_ports:
            obj = {
                'port_number': port_instance + 1,
                'port_name': links[port_instance]['port_name'],
                'vlan_mode': convert_mikrotik_vlan_mode(hex_string=vlans['vlan'][port_instance]),
                'vlan_receive': convert_mikrotik_vlan_receive(hex_string=vlans['vlni'][port_instance]),
                'vlan_id': int(vlans['dvid'][port_instance], 16),
                'force_vlan': force_vlan[port_instance]
            }
            port_instance += 1
            output.append(obj)

        output_options = ('port_name', 'vlan_mode', 'vlan_receive', 'vlan_id', 'force_vlan')
        if output_only in output_options:
            return [item[output_only] for item in output]
        elif port_number:
            return output[port_number - 1]
        elif port_name:
            return [ports for ports in output if ports['port_name'] == port_name]
        elif vlan_id:
            return [ports for ports in output if ports['vlan_id'] == vlan_id]
        return output


    def get_mikrotik_vlan_config(self):
        """
        Retrieve the complete VLAN configuration from the MikroTik switch.

        This function fetches the full VLAN configuration, including details of all VLANs and their settings.

        Returns:
            list: A list of dictionaries with the complete VLAN configuration of the switch.

        Example:
            vlan_config = get_mikrotik_vlan_config()
        """
        query = 'vlan.b'
        method = 'GET'
        response = self.send_rest_method(url=self.url, query=query, method=method)
        vlans = self.convert_mikrotik_json(input_object=response.text)

        vlan_instance = 0
        output = []

        for vlan in vlans:
            obj = {
                "vlan_id": int(vlans[vlan_instance]['vid'], 16),
                'port_isolation': int(vlans[vlan_instance]['piso'], 16),
                'learning': int(vlans[vlan_instance]['lrn'], 16),
                'mirror': int(vlans[vlan_instance]['mrr'], 16),
                'igmp_snoop': int(vlans[vlan_instance]['igmp'], 16),
                'members': self.convert_mikrotik_hex_array(hex_string=vlans[vlan_instance]['mbr'], pad_length=26)
            }
            vlan_instance += 1
            output.append(obj)

        return output

    def set_mikrotik_switch_port(self, port_number, port_name=None, enabled=True, auto_neg=True):
        """
        Configure settings for a specific MikroTik switch port.

        This function updates the configuration of a switch port, including enabling or disabling the port and setting 
        auto-negotiation.

        Args:
            port_number (int): The number of the port to configure.
            port_name (str, optional): The name to assign to the port.
            enabled (bool, optional): Whether the port should be enabled. Defaults to True.
            auto_neg (bool, optional): Whether auto-negotiation should be enabled. Defaults to True.

        Returns:
            None: This function does not return a value.

        Example:
            set_mikrotik_switch_port(1, port_name='Port1', enabled=True, auto_neg=False)
        """
        query = 'link.b'
        response = self.send_rest_method(url=self.url, query=query, method='GET')
        mikrotik_config = self.convert_mikrotik_json(input_object=response.text)

        new_mikrotik_config = ''
        name_count = 1
        speed_count = 1

        get_mikrotik_link_params = dict(
            url=self.url,
            username=self.username,
            password=self.password
        )

        port_names = self.get_mikrotik_links(**get_mikrotik_link_params, output_only='port_name')
        port_enabled = self.get_mikrotik_links(**get_mikrotik_link_params, output_only='enabled')
        port_auto_neg = self.get_mikrotik_links(**get_mikrotik_link_params, output_only='auto_neg')

        array_port_number = port_number - 1

        if port_name:
            new_port_name = port_name
            if new_port_name not in port_names:
                new_port_name_hex = new_port_name.encode('utf-8').hex()
                mikrotik_config['nm'][array_port_number] = new_port_name_hex

        if port_enabled[array_port_number] != enabled:
            new_port_enabled = list(port_enabled)
            new_port_enabled[array_port_number] = enabled

            new_port_enabled_hex = self.convert_mikrotik_array_hex(array=new_port_enabled)
            mikrotik_config['en'] = new_port_enabled_hex

        if port_auto_neg[array_port_number] != auto_neg:
            new_port_auto_neg = list(port_auto_neg)
            new_port_auto_neg[array_port_number] = auto_neg

            new_port_auto_neg_hex = self.convert_mikrotik_array_hex(array=new_port_auto_neg)
            mikrotik_config['an'] = new_port_auto_neg_hex

        new_mikrotik_config += f"{{en:{mikrotik_config['en']},nm:["
        for name_hex in mikrotik_config['nm']:
            if name_count <= (len(mikrotik_config['nm']) - 1):
                new_mikrotik_config += f"'{name_hex}',"
                name_count += 1
            else:
                new_mikrotik_config += f"'{name_hex}'"
        new_mikrotik_config += f"],an:{mikrotik_config['an']},spdc:["
        for speed_hex in mikrotik_config['spdc']:
            if speed_count <= (len(mikrotik_config['spdc']) - 1):
                new_mikrotik_config += f"'{speed_hex}',"
                speed_count += 1
            else:
                new_mikrotik_config += f"'{speed_hex}'"
        new_mikrotik_config += f"],dpxc:{mikrotik_config['dpxc']},fctc:{mikrotik_config['fctc']},fctr:{mikrotik_config['fctr']}}}"

        self.send_rest_method(url=self.url, query=query, method='POST', body=new_mikrotik_config)

    def set_mikrotik_vlan(self, port_number, vlan_mode=None, vlan_receive=None, vlan_id=None):
        """
        Configure VLAN settings for a specific MikroTik port.

        This function sets the VLAN mode, VLAN reception settings, and VLAN ID for a specified port. It updates the 
        VLAN configuration through a REST API call.

        Args:
            port_number (int): The number of the port to configure.
            vlan_mode (str, optional): The VLAN mode to apply, such as 'access' or 'trunk'.
            vlan_receive (str, optional): How VLANs are received on the port, such as 'none' or 'all'.
            vlan_id (int, optional): The VLAN ID to assign to the port. Relevant when `vlan_mode` is 'access' or similar.

        Returns:
            None: This function does not return a value.

        Example:
            set_mikrotik_vlan(1, vlan_mode='trunk', vlan_receive='all', vlan_id=100)
        """
        query = 'fwd.b'
        response = self.send_rest_method(url=self.url, query=query, method='GET')
        mikrotik_config = self.convert_mikrotik_json(input_object=response.text)

        get_mikrotik_vlan_params = dict(
            url=self.url,
            username=self.username,
            password=self.password
        )

        array_port_number = port_number - 1

        vlan_mode_count = 1
        vlan_receive_count = 1
        vlan_id_count = 1

        vlan_mode_data = self.get_mikrotik_vlan(**get_mikrotik_vlan_params, output_only='vlan_mode')[array_port_number]
        vlan_receive_data = self.get_mikrotik_vlan(**get_mikrotik_vlan_params, output_only='vlan_receive')[array_port_number]
        vlan_id_data = self.get_mikrotik_vlan(**get_mikrotik_vlan_params, output_only='vlan_id')[array_port_number]

        if vlan_mode:
            if vlan_mode_data != vlan_mode:
                new_vlan_mode = convert_mikrotik_vlan_mode(string=vlan_mode)
                mikrotik_config['vlan'][array_port_number] = new_vlan_mode

        if vlan_receive:
            if vlan_receive_data != vlan_receive:
                new_vlan_receive = convert_mikrotik_vlan_receive(string=vlan_receive)
                mikrotik_config['vlni'][array_port_number] = new_vlan_receive

        if vlan_id:
            if vlan_id_data != vlan_id:
                padding = 6
                new_vlan_id = f"{vlan_id:#0{padding}x}"
                mikrotik_config['dvid'][array_port_number] = new_vlan_id

        new_mikrotik_config = '{vlan:['
        for vlan_mode_hex in mikrotik_config['vlan']:
            if vlan_mode_count <= (len(mikrotik_config['vlan']) - 1):
                new_mikrotik_config += f"{vlan_mode_hex},"
                vlan_mode_count += 1
            else:
                new_mikrotik_config += f"{vlan_mode_hex}"

        new_mikrotik_config += '],vlni:['
        for vlan_receive_hex in mikrotik_config['vlni']:
            if vlan_receive_count <= (len(mikrotik_config['vlni']) - 1):
                new_mikrotik_config += f"{vlan_receive_hex},"
                vlan_receive_count += 1
            else:
                new_mikrotik_config += f"{vlan_receive_hex}"

        new_mikrotik_config += '],dvid:['
        for vlan_id_hex in mikrotik_config['dvid']:
            if vlan_id_count <= (len(mikrotik_config['dvid']) - 1):
                new_mikrotik_config += f"{vlan_id_hex},"
                vlan_id_count += 1
            else:
                new_mikrotik_config += f"{vlan_id_hex}"
        
        new_mikrotik_config += ']}'

        self.send_rest_method(url=self.url, query=query, method='POST', body=new_mikrotik_config)
    def get_port_statistics(self):
        """
        Retrieve detailed statistics about each port on the MikroTik switch.

        This function returns information such as packet counts, error counts, and other performance metrics for each port.

        Returns:
            list: A list of dictionaries with port statistics, including packet counts, error counts, and more.
        """
        query = 'stats.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        stats = convert_mikrotik_json(input_object=response.text)

        output = []
        for stat in stats:
            obj = {
                'port_number': int(stat['prt'], 16) + 1,
                'rx_bytes': int(stat['rxb'], 16),
                'tx_bytes': int(stat['txb'], 16),
                'rx_errors': int(stat['rxe'], 16),
                'tx_errors': int(stat['txe'], 16),
                'rx_drops': int(stat['rxd'], 16),
                'tx_drops': int(stat['txd'], 16),
            }
            output.append(obj)

        return output

    def get_system_info(self):
        """
        Retrieve general information about the device, such as firmware version, model, uptime, etc.
        This function provides details such as firmware version, model, uptime, and other basic system information.

        Returns:
           dict: A dictionary containing general information about the device.
        """
        query = 'sysinfo.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        system_info = convert_mikrotik_json(input_object=response.text)

        return {
            'model': system_info['model'],
            'firmware_version': system_info['fwver'],
            'uptime': int(system_info['uptime'], 16),
            'serial_number': system_info['serial'],
            'board_name': system_info['board']
        }

    def get_stp_status(self):
        """
        Retrieve information about the Spanning Tree Protocol, including the status of each port.
        This function provides details on the status of STP for each port on the switch, including whether ports are
        in blocking or forwarding state.

        Returns:
            list: A list of dictionaries with STP status information for each port.
        """
        query = 'stp.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        stp = convert_mikrotik_json(input_object=response.text)

        output = []
        for port in stp['ports']:
            obj = {
                'port_number': int(port['prt'], 16) + 1,
                'stp_state': port['state'],
                'stp_cost': int(port['cost'], 16),
                'stp_priority': int(port['priority'], 16),
            }
            output.append(obj)

        return output

    def get_dhcp_snooping_status(self):
        """
        Retrieve information about DHCP snooping, including binding tables and status.
        This function provides details on DHCP snooping configuration, including binding tables and overall status.

        Returns:
            list: A list of dictionaries containing DHCP snooping information, such as binding tables and status.
        """
        query = 'dhcp.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        dhcp_snooping = convert_mikrotik_json(input_object=response.text)

        output = []
        for entry in dhcp_snooping['bindings']:
            obj = {
                'mac_address': re.sub(r'(.{2})(?!$)', r'\1:', entry['mac']),
                'ip_address': entry['ip'],
                'vlan_id': int(entry['vid'], 16),
                'port_number': int(entry['prt'], 16) + 1,
                'lease_time': int(entry['time'], 16)
            }
            output.append(obj)

        return output

    def get_traffic_mirroring_settings(self):
        """
        Retrieve the configuration for traffic mirroring (port mirroring).
        This function provides details on how traffic mirroring is configured on the switch, including source and destination ports.

        Returns:
            dict: A dictionary containing traffic mirroring settings.
        """
        query = 'mirror.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        mirror = convert_mikrotik_json(input_object=response.text)

        return {
            'mirror_source': mirror['source'],
            'mirror_target': mirror['target'],
            'mirror_enabled': mirror['enabled'] == '1'
        }
    def get_qos_settings(self):
        """
        Retrieve Quality of Service (QoS) settings, such as queue configurations and prioritization.
        This function returns details on QoS configurations, including queue setups and prioritization rules.

        Returns:
            list: A list of dictionaries with QoS settings, including queue configurations and prioritization.
        """
        query = 'qos.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        qos_settings = convert_mikrotik_json(input_object=response.text)

        output = []
        for queue in qos_settings['queues']:
            obj = {
                'queue_id': int(queue['id'], 16),
                'priority': int(queue['priority'], 16),
                'bandwidth_limit': int(queue['limit'], 16),
            }
            output.append(obj)

        return output

    def get_vlan_membership(self):
        """
        Retrieve detailed VLAN membership information for each port.

        This function provides a detailed view of VLAN memberships for each port on the switch.

        Returns:
            list: A list of dictionaries containing VLAN membership details for each port.
        """
        query = 'vlanmbr.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        vlan_membership = convert_mikrotik_json(input_object=response.text)

        output = []
        for member in vlan_membership['members']:
            obj = {
                'vlan_id': int(member['vid'], 16),
                'port_number': int(member['prt'], 16) + 1,
                'tagged': bool(int(member['tagged'], 16)),
            }
            output.append(obj)

        return output

    def get_port_security(self):
        """
        Retrieve port security settings, such as MAC address filtering and port blocking.

        This function provides information on port security configurations, including MAC address filtering and port blocking.

        Returns:
            list: A list with port security settings.
        """
        query = 'portsec.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        port_security = convert_mikrotik_json(input_object=response.text)

        output = []
        for security in port_security['ports']:
            obj = {
                'port_number': int(security['prt'], 16) + 1,
                'mac_filtering': security['macfilter'] == '1',
                'port_blocking': security['blocked'] == '1',
                'allowed_mac_addresses': convert_mikrotik_hex_array(security['allowedmac']),
            }
            output.append(obj)

        return output

    def get_poe_status(self):
        """
        Retrieve the status of PoE (Power over Ethernet) on each port.
        This function provides information on PoE status for each port, including whether PoE is enabled and power levels.

        Returns:
            list: A list of dictionaries with PoE status for each port.
        """
        query = 'poe.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        poe_status = convert_mikrotik_json(input_object=response.text)

        output = []
        for port in poe_status['ports']:
            obj = {
                'port_number': int(port['prt'], 16) + 1,
                'poe_enabled': port['enabled'] == '1',
                'power_consumption': int(port['power'], 16),  # in milliwatts
            }
            output.append(obj)

        return output

    def get_port_isolation(self):
        """
        Retrieve port isolation settings to understand how traffic is segregated between ports.
        This function provides details on how traffic is isolated between ports, including any configured isolation rules.

        Returns:
            list: A list of dictionaries containing port isolation settings.
        """
        query = 'portiso.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        port_isolation = convert_mikrotik_json(input_object=response.text)

        output = []
        for isolation in port_isolation['ports']:
            obj = {
                'port_number': int(isolation['prt'], 16) + 1,
                'isolated': isolation['isolated'] == '1',
                'isolated_ports': convert_mikrotik_hex_array(isolation['isolatedports']),
            }
            output.append(obj)

        return output
    def get_system_info(self):
        """
        Retrieve basic system information such as firmware version, device model, and uptime.
        This function provides details such as firmware version, model, uptime, and other basic system information.

        Returns:
            dict: A dictionary containing general information about the device.
        
        """
        query = 'system.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        system_info = convert_mikrotik_json(input_object=response.text)

        return {
            'firmware_version': system_info['fwver'],
            'device_model': system_info['model'],
            'uptime': system_info['uptime']
        }

    def get_interface_statistics(self):
        """
        Retrieve statistics for each interface, including transmitted and received packets, errors, and collisions.
        This function provides detailed statistics for each interface, including transmitted and received packets, errors, and collisions.

        Returns:
            list: A list of dictionaries containing interface statistics.
        """
        query = 'stat.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        interface_stats = convert_mikrotik_json(input_object=response.text)

        output = []
        for stat in interface_stats['interfaces']:
            obj = {
                'port_number': int(stat['prt'], 16) + 1,
                'rx_packets': int(stat['rxpkts'], 16),
                'tx_packets': int(stat['txpkts'], 16),
                'rx_errors': int(stat['rxerrs'], 16),
                'tx_errors': int(stat['txerrs'], 16),
                'collisions': int(stat['coll'], 16)
            }
            output.append(obj)

        return output

    def get_stp_status(self):
        """
        Retrieve the current status and configuration of the Spanning Tree Protocol.
        This function provides details on the status of STP for each port on the switch, including whether ports are
        in blocking or forwarding state.

        Returns:
            dict: A dictionary with STP status information for each port.
        """
        query = 'stp.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        stp_status = convert_mikrotik_json(input_object=response.text)

        return {
            'enabled': stp_status['enabled'] == '1',
            'bridge_priority': int(stp_status['brpriority'], 16),
            'bridge_id': stp_status['bridgeid'],
            'root_id': stp_status['rootid'],
            'root_path_cost': int(stp_status['rootpathcost'], 16),
            'root_port': int(stp_status['rootport'], 16) + 1
        }

    def get_lldp_neighbors(self):
        """
        Retrieve LLDP neighbor information, useful for network topology discovery.
         This function provides details about neighboring devices discovered through LLDP, useful for network topology discovery.

        Returns:
            list: A list of dictionaries, each containing information about an LLDP neighbor.
        """
        query = 'lldp.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        lldp_neighbors = convert_mikrotik_json(input_object=response.text)

        output = []
        for neighbor in lldp_neighbors['neighbors']:
            obj = {
                'port_number': int(neighbor['prt'], 16) + 1,
                'neighbor_port_id': neighbor['portid'],
                'neighbor_chassis_id': neighbor['chassisid'],
                'neighbor_system_name': neighbor['sysname'],
                'neighbor_system_description': neighbor['sysdesc']
            }
            output.append(obj)

        return output

    def get_dhcp_snooping_info(self):
        """
        Retrieve DHCP snooping configuration and status, including trusted ports and detected rogue DHCP servers.
        This function provides information about DHCP snooping, including trusted ports and detected rogue DHCP servers.

        Returns:
            list: A list of dictionaries with DHCP snooping configuration and status details.
        """
        query = 'dhcps.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        dhcp_snooping_info = convert_mikrotik_json(input_object=response.text)

        output = []
        for snoop in dhcp_snooping_info['snooping']:
            obj = {
                'port_number': int(snoop['prt'], 16) + 1,
                'trusted': snoop['trusted'] == '1',
                'rogue_servers_detected': int(snoop['rogue'], 16)
            }
            output.append(obj)

        return output

    def get_port_mirroring(self):
        """
        Retrieve the current port mirroring settings, including source and destination ports.
        This function provides details about port mirroring configurations, including source and destination ports.

        Returns:
            dict: A dictionary with port mirroring settings.
        """
        query = 'mirror.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        port_mirroring = convert_mikrotik_json(input_object=response.text)

        return {
            'mirror_enabled': port_mirroring['enabled'] == '1',
            'source_port': int(port_mirroring['srcprt'], 16) + 1,
            'destination_port': int(port_mirroring['dstprt'], 16) + 1
        }

    def get_ip_filter_rules(self):
        """
        Retrieve IP filter rules, such as access control lists (ACLs) configured on the switch.
        This function provides details about IP filtering rules, such as access control lists (ACLs).

        Returns:
            list: A list of dictionaries, each representing an IP filter rule.
        """
        query = 'acl.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        ip_filter_rules = convert_mikrotik_json(input_object=response.text)

        output = []
        for rule in ip_filter_rules['rules']:
            obj = {
                'rule_id': int(rule['id'], 16),
                'source_ip': rule['srcip'],
                'destination_ip': rule['dstip'],
                'action': rule['action'],
                'log': rule['log'] == '1'
            }
            output.append(obj)

        return output

    def get_multicast_settings(self):
        """
        Retrieve multicast-related settings, such as IGMP snooping and multicast filtering.
        This function provides information on multicast settings, including IGMP snooping and multicast filtering.

        Returns:
            dict: A dictionary with multicast-related settings.
        """
        query = 'mc.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        multicast_settings = convert_mikrotik_json(input_object=response.text)

        return {
            'igmp_snooping_enabled': multicast_settings['igmp_snooping'] == '1',
            'multicast_filtering_enabled': multicast_settings['mc_filtering'] == '1',
            'multicast_groups': convert_mikrotik_hex_array(multicast_settings['groups'])
        }

    def get_system_logs(self):
        """
        Retrieve the system logs to analyze historical events and troubleshoot issues.
        This function fetches historical system logs, which can be used to analyze events and troubleshoot issues.

        Returns:
            list: A list of dictionaries, each representing a system log entry.
        """
        query = 'log.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        system_logs = convert_mikrotik_json(input_object=response.text)

        output = []
        for log in system_logs['logs']:
            obj = {
                'timestamp': log['time'],
                'severity': log['severity'],
                'message': log['message']
            }
            output.append(obj)

        return output

    def get_mac_address_table(self):
        """
        Retrieve the MAC address table, showing which MAC addresses are learned on which ports.
        This function provides the MAC address table, showing which MAC addresses are learned on which ports.

        Returns:
            list: A list of dictionaries with MAC addresses and associated ports.
        """
        query = 'fdb.b'
        method = 'GET'
        response = self.send_rest_method(method=method, query=query)
        mac_address_table = convert_mikrotik_json(input_object=response.text)

        output = []
        for entry in mac_address_table['entries']:
            obj = {
                'mac_address': entry['mac'],
                'port_number': int(entry['prt'], 16) + 1,
                'vlan_id': int(entry['vid'], 16)
            }
            output.append(obj)

        return output