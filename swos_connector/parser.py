
import re
import json
def convert_mikrotik_link_speed(hex_string):
        swos_link_speeds = {
            '0x01': 0.1,
            '0x02': 1.0,
            '0x07': 0.0,
            '0x04': 0.0,
            '0x03': 10.0
        }
        return swos_link_speeds.get(hex_string, 0.0)

def convert_mikrotik_hex_array(hex_string, pad_length):
        output = []
        binary = f'{int(hex_string, 16):0>{pad_length}b}'
        for element in binary:
            output.append(element == '1')
        output.reverse()
        return output

def convert_mikrotik_array_hex(array, padding=8):
        binary_string = ''.join(['1' if item else '0' for item in reversed(array)])
        padding = padding + 2
        return f"{int(binary_string, 2):#0{padding}x}"

def convert_mikrotik_vlan_mode(hex_string=None, string=None):
        vlan_modes = {
            '0x00': 'Disabled',
            '0x01': 'Optional',
            '0x02': 'Enabled',
            '0x03': 'Strict'
        }
        if hex_string:
            return vlan_modes.get(hex_string)
        if string:
            return {v: k for k, v in vlan_modes.items()}.get(string)

def convert_mikrotik_vlan_receive(hex_string=None, string=None):
        vlan_receive = {
            '0x00': 'Any',
            '0x01': 'Only Tagged',
            '0x02': 'Only Untagged'
        }
        if hex_string:
            return vlan_receive.get(hex_string)
        if string:
            return {v: k for k, v in vlan_receive.items()}.get(string)
def convert_mikrotik_json(input_object):
        json_dump = input_object

        word_regex = r"(\w+)"
        single_quote_regex = r"(\')"
        double_double_quote_regex = r'\"{2}(\w+)\"{2}'

        json_dump = re.sub(word_regex, r'"\1"', json_dump)
        json_dump = re.sub(single_quote_regex, r'"', json_dump)
        json_dump = re.sub(double_double_quote_regex, r'"\1"', json_dump)
        json_dump = re.sub('],}', '}]', json_dump)

        json_output = json.loads(json_dump)
        return json_output