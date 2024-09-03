from swos_connector.connector import SWOSConnector

def get_system(url,username,password):
    with SWOSConnector(url, username, password) as swos:
        system_info = swos.get_system_info()
        return system_info

url = 'http://192.168.88.1'
username = 'admin'
password = 'password'
print(get_system(url,username,password))