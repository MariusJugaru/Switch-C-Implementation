#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

input_path = "./configs"

BLOCKING = 0
LISTENING = 1
DESIGNATED_PORT = 2

# init stp
port_type = {}

port_name_id = {}

own_bridge_ID = None
root_bridge_ID = None
root_path_cost = 0
root_port = None
is_root = True

# add a mac address in the mac table
def add_mac_addr(mac_table, mac_addr, port):
    if mac_addr not in mac_table:
        mac_table[mac_addr] = port

# get mac address port
def get_mac_port(mac_table, mac_addr):
    if mac_addr not in mac_table:
        return None
    return mac_table[mac_addr]

# checks if the mac addr isn't a broadcast addr
def is_unicast(mac_addr):
    return mac_addr.lower() != "ff:ff:ff:ff:ff:ff" 

# add entry in vlan table
def add_vlan_entry(vlan_table, interface, value):
    vlan_table[interface] = value

def get_interface_vlan(vlan_table, interface):
    interface_name = get_interface_name(interface)
    if interface_name in vlan_table:
        return vlan_table[interface_name]

# read router config from file
# returns priority and vlan table
def read_router_config(input_file):
    priority = None
    vlan_table = {}

    with open(input_file , 'r') as file:
        priority = int(file.readline())

        for line in file:
            interface, val = line.split()
            add_vlan_entry(vlan_table, interface, val)

    return priority, vlan_table

# create a bdpu frame
def create_bpdu_frame(src_mac, root_bridge_id_param, root_path_cost_param, bridge_id_param):
    # ethernet header    
    dest_mac = b'\x01\x80\xc2\x00\x00\x00'
    #src_mac
    length = struct.pack("!H", 38)

    ethernet_header = dest_mac + src_mac + length

    # llc header
    dsap = b'\x42'
    ssap = b'\x42'
    control = b'\x03'

    llc_header = dsap + ssap + control

    # bdpu header
    protocol_id = struct.pack("!H", 0)
    protocol_version_id = struct.pack("!B", 0)
    bdpu_type = struct.pack("!B", 0)

    bdpu_header = protocol_id + protocol_version_id + bdpu_type

    # bdpu config
    bdpu_flags = struct.pack("!B", 0)
    root_bridge_id = root_bridge_id_param
    root_path_cost = struct.pack("!I", root_path_cost_param)
    bridge_id = bridge_id_param
    port_id = struct.pack("!H", 0)
    message_age = struct.pack("!H", 0)
    max_age = struct.pack("!H", 0)
    hello_time = struct.pack("!H", 0)
    forward_delay = struct.pack("!H", 0)

    bdpu_config = bdpu_flags + root_bridge_id + root_path_cost + bridge_id + port_id + message_age + max_age + hello_time + forward_delay
    
    return ethernet_header + llc_header + bdpu_header + bdpu_config


def parse_bpdu_header(data):
    root_bridge_id = data[22:30]
    root_path_cost = int(struct.unpack('!I', data[30:34])[0])
    bridge_id = data[34:42]

    return root_bridge_id, root_path_cost, bridge_id


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        if root_bridge_ID == own_bridge_ID:
            bdpu_data = create_bpdu_frame(get_switch_mac(), own_bridge_ID, root_path_cost, own_bridge_ID)
            
            for i in port_type.keys():
                send_to_link(port_name_id[i], len(bdpu_data), bdpu_data)
        time.sleep(1)

def main():
    global own_bridge_ID
    global root_bridge_ID
    global port_type
    global port_name_id
    global root_path_cost
    global root_port
    global is_root

    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # init mac table
    mac_table = {}

    # init vlan table
    vlan_table = {}

    # init priority
    priority = None

    for i in interfaces:
        port_name_id[get_interface_name(i)] = i

    priority, vlan_table = read_router_config(input_path + f"/switch{switch_id}.cfg")

    # set each trunk port to blocking
    for key, val in vlan_table.items():
        if val == 'T':
            port_type[key] = BLOCKING

    own_bridge_ID  = struct.pack('!H', priority) + get_switch_mac()
    root_bridge_ID = own_bridge_ID
    root_path_cost = int(0)

    if own_bridge_ID == root_bridge_ID:
        for port in port_type.keys():
            port_type[port] = DESIGNATED_PORT
    
    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        if dest_mac == dest_mac == b'\x01\x80\xc2\x00\x00\x00':
            ethertype = b'\x00\x00'

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        # print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # print(port_type)

        if get_interface_name(interface) in port_type and port_type[get_interface_name(interface)] == BLOCKING:
            data = None
            continue


        if ethertype == b'\x00\x00':
            root_bdpu, cost_bdpu, bridge_bdpu = parse_bpdu_header(data)

            if root_bdpu < root_bridge_ID:
                root_bridge_ID = root_bdpu
                root_path_cost = cost_bdpu + 10
                root_port = interface
                
                if is_root:
                    is_root = False
                    for port_aux in port_type.keys():
                        port_type[port_aux] = BLOCKING
                    port_type[get_interface_name(root_port)] = DESIGNATED_PORT

                if port_type[get_interface_name(root_port)] == BLOCKING:
                    port_type[get_interface_name(root_port)] = LISTENING

                for port_aux in port_type.keys():
                    port_interface = port_name_id[port_aux]
                    bdpu_data = create_bpdu_frame(get_switch_mac(), root_bdpu, root_path_cost, own_bridge_ID)
                    if port_interface != interface:
                        send_to_link(port_interface, len(bdpu_data), bdpu_data)

            elif root_bdpu == root_bridge_ID:
                if interface == root_port and cost_bdpu + 10 < root_path_cost:
                    root_path_cost = cost_bdpu + 10
                elif root_port != interface:
                    if cost_bdpu > root_path_cost:
                        if port_type[interface] != DESIGNATED_PORT:
                            port_type[interface] = DESIGNATED_PORT
            elif bridge_bdpu == own_bridge_ID:
                port_type[interface] = BLOCKING
            else:
                continue
                
            if own_bridge_ID == root_bridge_ID:
                for port_aux in port_type.keys():
                    port_type[port_aux] = DESIGNATED_PORT
                
            continue

        # TODO: Implement forwarding with learning
        
        add_mac_addr(mac_table, src_mac, interface)

        if vlan_id == -1:
            src_vlan = get_interface_vlan(vlan_table, interface)
        else:
            src_vlan = str(vlan_id)
        
        if is_unicast(dest_mac):
            port = get_mac_port(mac_table, dest_mac)
            
            if dest_mac in mac_table:
                dst_vlan = get_interface_vlan(vlan_table, port)

                # access
                if src_vlan == dst_vlan:
                    if vlan_id == -1:
                        send_to_link(port, length, data)
                    else:
                        untagged_frame = data[0:12] + data[16:]
                        send_to_link(port, length - 4, untagged_frame)
                
                # trunk
                if dst_vlan == 'T':
                    if vlan_id == -1:
                        tagged_frame = data[0:12] + create_vlan_tag(int(src_vlan)) + data[12:]
                        send_to_link(port, length + 4, tagged_frame)
                    else:
                        send_to_link(port, length, data)
            else:
                # mac entry doesn't exist, broadcast the frame
                for i in interfaces:
                    if i != interface:
                        # send only to interfaces of the same VLAN or trunk
                        dst_vlan = get_interface_vlan(vlan_table, i)
                        
                        # access
                        if src_vlan == dst_vlan:
                            if vlan_id == -1:
                                send_to_link(i, length, data)
                            else:
                                untagged_frame = data[0:12] + data[16:]
                                send_to_link(i, length - 4, untagged_frame)

                        # trunk
                        if dst_vlan == 'T' and port_type[get_interface_name(i)] == DESIGNATED_PORT:
                            if vlan_id == -1:
                                tagged_frame = data[0:12] + create_vlan_tag(int(src_vlan)) + data[12:]
                                send_to_link(i, length + 4, tagged_frame)
                            else:
                                send_to_link(i, length, data)
        else:
            for i in interfaces:
                if i != interface:
                    dst_vlan = get_interface_vlan(vlan_table, i)

                    # access
                    if src_vlan == dst_vlan:
                        if vlan_id == -1:
                            send_to_link(i, length, data)
                        else:
                            # remove VLAN header
                            untagged_frame = data[0:12] + data[16:]
                            send_to_link(i, length - 4, untagged_frame)
                    
                    # trunk
                    if dst_vlan == 'T'  and port_type[get_interface_name(i)] == DESIGNATED_PORT:
                        if vlan_id == -1:
                            # add vlan header
                            tagged_frame = data[0:12] + create_vlan_tag(int(src_vlan)) + data[12:]
                            send_to_link(i, length + 4, tagged_frame)
                        else:
                            # already has the vlan header
                            send_to_link(i, length, data)

        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # print(mac_table)

if __name__ == "__main__":
    main()
