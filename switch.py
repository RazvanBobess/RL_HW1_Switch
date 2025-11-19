#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

mac_table = {}
switch_mac = b''
switch_port_status = {}
switch_priority = 0

ppdu_seq_num = 0
ppdu_root_mac = b''
ppdu_root_priority = 0
ppdu_root_path_cost = 0
ppdu_root_id = 0

def parser_vlan(file_name, vlan_config):
    global switch_priority

    with open(file_name, 'r') as f:
        lines = f.readlines()
        switch_priority = int(lines[0].strip())

        for line in lines[1:]:
            parts = line.strip().split()
            port_name = parts[0]
            vlan_id = parts[1]
            if vlan_id != 'T':
                vlan_id = int(vlan_id)

            vlan_config[port_name] = vlan_id

    return vlan_config

def send_on_trunk_or_not_ports(out_itf, data, in_conf, src_mac, vlan_config):
    itf_name = get_interface_name(out_itf)

    out_conf = vlan_config[itf_name]
    nibble_src = calculate_mac_nibble(src_mac)

    if in_conf != 'T' and out_conf == 'T':
        vlan_id = in_conf
        temp_data = data[0:12] + create_vlan_tag(nibble_src, vlan_id) + data[12:]
        send_to_link(out_itf, len(temp_data), temp_data)
        return

    if in_conf == 'T' and out_conf != 'T':

        out_vlan_id = out_conf

        frame_vlan_ext = data[12:16]
        out_vlan_ext = create_vlan_tag(nibble_src, out_vlan_id)

        if out_vlan_ext != frame_vlan_ext:
            return

        untagged_data = data[0:12] + data[16:]
        send_to_link(out_itf, len(untagged_data), untagged_data)
        return

    if in_conf == 'T' and out_conf == 'T':
        send_to_link(out_itf, len(data), data)
        return

    if in_conf != 'T' and out_conf != 'T':
        if in_conf != out_conf:
            return
        send_to_link(out_itf, len(data), data)


def calculate_mac_nibble(mac_address):
    mac_address = mac_address.replace(':', '')
    nibble_sum = 0
    for char in mac_address:
        nibble_sum += int(char, 16)
    return nibble_sum

def extract_vlan_id_from_tag(frame):
    vlan_tag = frame[12:16]
    vlan_tci = vlan_tag[2:4]
    vlan_id = int.from_bytes(vlan_tci, byteorder='big') & 0x0FFF
    return vlan_id

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]

    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    vlan_tci = -1
    # Check for VLAN tag (0x8200 in network byte order is b'\x82\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id, vlan_tci

def create_vlan_tag(ext_id, vlan_id):
    # Use EtherType = 8200h for our custom 802.1Q-like protocol.
    # PCP and DEI bits are used to extend the original VID.
    #
    # The ext_id should be the sum of all nibbles in the MAC address of the
    # host attached to the _access_ port. Ignore the overflow in the 4-bit
    # accumulator.
    #
    # NOTE: Include these 4 extensions bits only in the check for unicast
    #       frames. For multicasts, assume that you're dealing with 802.1Q.
    return struct.pack('!H', 0x8200) + \
           struct.pack('!H', ((ext_id & 0xF) << 12) | (vlan_id & 0x0FFF))

def function_on_different_thread():
    while True:
        time.sleep(1)

def build_hpdu_frame(src_mac):
    dst_mac = b"\xff\xff\xff\xff\xff\xff"
    ethertype = 0x0800

    frame = struct.pack("!6s6sHB", dst_mac, src_mac, ethertype, 0xFF)
    return frame

def send_hpdu_thread(interfaces):
    global switch_mac
    while True:
        frame = build_hpdu_frame(switch_mac)
        for i in interfaces:
            send_to_link(i, len(frame), frame)
        time.sleep(1)

def is_unicast(mac_address):
    first_byte = (int)(mac_address.split(':')[0], 16)
    return (first_byte & 1) == 0

def create_LLH_header():
    dsap = 0x42
    ssap = 0x42
    control_field = 0x03

    llh_header = struct.pack('!BBB', dsap, ssap, control_field)
    return llh_header

def create_PPDU_header():
    global ppdu_seq_num

    prot_ID = 0x0002
    prot_version = 0x0
    ppdu_type = 0x80

    ppdu_header = struct.pack('!HBBI', prot_ID, prot_version, ppdu_type, ppdu_seq_num)
    return ppdu_header

def create_PPDU_CONFIG_hdr():
    global ppdu_root_path_cost, ppdu_root_id, switch_mac

    flags = 0
    message_age = 0

    bridge_priority = 0x8000
    bridge_mac = switch_mac
    max_age = 40
    hello_time = 2
    fwd_delay = 4

    # Port_ID = priority(4 bits) | p_num(12 bits)
    port_id = 128

    path_cost = ppdu_root_path_cost

    # when we first create the switch, its root bridge id is its own id
    # I will update it when I receive a packet with lower bridge id
    bridge_id = (bridge_priority << 48) | int.from_bytes(bridge_mac, byteorder='big')

    frame = struct.pack('!B8sI8sHHHHH', flags, ppdu_root_id, path_cost, bridge_id, port_id, message_age, max_age, hello_time, fwd_delay)
    return frame

def create_PPDU_hdr(src_mac):

    dst_mac = struct.pack('!6B', 0x01, 0x80, 0xC2, 0x00, 0x00, 0x10)

    llc_hdr = create_LLH_header()
    ppdu_hdr = create_PPDU_header()
    ppdu_config_hdr = create_PPDU_CONFIG_hdr()

    llc_len = len(llc_hdr) + len(ppdu_hdr) + len(ppdu_config_hdr)

    ppdu_hdr = struct.pack('!6s6sH3s8s31s', dst_mac, src_mac, llc_len, llc_hdr, ppdu_hdr, ppdu_config_hdr)
    return ppdu_hdr

def conf_recv_ppdu(data):

    # unpack the header fields from the byte array
    aux_dest_mac = data[0:6]
    aux_src_mac = data[6:12]

    llen = int.from_bytes(data[12:14], byteorder='big')
    aux_llc_header = data[14:17]
    aux_ppdu_header = data[17:22]
    aux_ppdu_config_header = data[22:53]

    # unpack PPDU_CONFIG header
    aux_root_id = aux_ppdu_config_header[1:9]
    aux_root_p_cost = int.from_bytes(aux_ppdu_config_header[9:13], byteorder='big')
    aux_bridge_id = aux_ppdu_config_header[13:21]
    aux_port_id = int.from_bytes(aux_ppdu_config_header[21:23], byteorder='big')
    aux_bridge_prio = int.from_bytes(aux_bridge_id[0:2], byteorder='big')
    aux_bridge_mac = aux_bridge_id[2:8]

    return aux_bridge_id, aux_bridge_prio, aux_bridge_mac, aux_root_p_cost

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    # print("# Starting switch with id {}".format(switch_id), flush=True)
    # print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    global switch_mac, switch_priority, ppdu_root_mac, ppdu_root_priority, ppdu_root_path_cost, ppdu_root_id

    # Printing interface names
    # for i in interfaces:
    #     print(get_interface_name(i))

    switch_mac = get_switch_mac()
    vlan_config = {}

    vlan_config = parser_vlan("./configs/switch" + switch_id + ".cfg", vlan_config)

    ppdu_root_path_cost = 0
    ppdu_root_mac = get_switch_mac()
    ppdu_root_priority = switch_priority
    ppdu_root_id = (ppdu_root_priority << 48) | int.from_bytes(ppdu_root_mac, byteorder='big')

    t = threading.Thread(target=send_hpdu_thread, args=(interfaces,), daemon=True)
    t.start()

    # print(f"[INFO] Print switch id for config file {switch_id}", flush=True)

    while True:
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id, vlan_tci = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        mac_table[src_mac] = interface

        in_conf = vlan_config[get_interface_name(interface)]
        if is_unicast(dest_mac):
            if dest_mac in mac_table:
                out_itf = get_interface_name(mac_table[dest_mac])

                #config the vlan
                out_conf = vlan_config[out_itf]
                aux_data = data[:]

                if in_conf != 'T' and out_conf != 'T' and in_conf != out_conf:
                    return

                if in_conf != 'T' and out_conf == 'T':
                    aux_data = data[0:12] + create_vlan_tag(calculate_mac_nibble(src_mac), in_conf) + data[12:]
                
                elif in_conf == 'T' and out_conf != 'T':
                    frame_vlan_id = extract_vlan_id_from_tag(data)

                    if out_conf != frame_vlan_id:
                        return

                    aux_data = data[0:12] + data[16:]

                send_to_link(mac_table[dest_mac], len(aux_data), aux_data)
            else:
                for i in interfaces:
                    if i != interface:
                        aux_data = data[:]
                        send_on_trunk_or_not_ports(i, aux_data, in_conf, src_mac, vlan_config)
        else:
            for i in interfaces:
                if i != interface:
                    aux_data = data[:]
                    send_on_trunk_or_not_ports(i, aux_data, in_conf, src_mac, vlan_config)

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
