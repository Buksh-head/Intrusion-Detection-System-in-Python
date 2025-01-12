import sys
import time
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP

detected = {}

def parse_ids_rule(line):
    if line.startswith("#"):
        return None

    # alert <protocol> <source IP> <source port> -> <dest IP> <dest port> (options)
    action, protocol, src_ip, src_port, arrow, dest_ip, dest_port, options = line.split(' ', 7)
    options = options.strip('()').split(';')
    options_dict = {}

    for ids_opt in options:
        if ids_opt:
            key, value = ids_opt.split(':', 1)
            options_dict[key.strip()] = value.strip().strip('"')

    return {
        'action': action,
        'protocol': protocol,
        'src_ip': src_ip,
        'src_port': src_port,
        'dest_ip': dest_ip,
        'dest_port': dest_port,
        'options': options_dict
    }


def check_packet(packet, rule):
    protocol = rule['protocol'].upper()
    ip_layer = packet[IP]  
    transport_layer = None
    if protocol == "TCP" and packet.haslayer(TCP):
        transport_layer = packet[TCP]
    elif protocol == "UDP" and packet.haslayer(UDP):
        transport_layer = packet[UDP]
    elif protocol == "ICMP" and packet.haslayer(ICMP):
        transport_layer = packet[ICMP]
    elif protocol == "IP":
        transport_layer = ip_layer  

    if not transport_layer:
        return False

    src_ip_same = (rule['src_ip'] == 'any' or ip_layer.src == rule['src_ip'])
    dest_ip_same = (rule['dest_ip'] == 'any' or ip_layer.dst == rule['dest_ip'])
    
    if src_ip_same and dest_ip_same:
        if 'flags' in rule['options'] and protocol == 'TCP':
            given_flag = rule['options']['flags']
            packet_flags = transport_layer.flags
            # A (ACK) = 0x10, S (SYN) = 0x02, F (FIN) = 0x01, R (RST) = 0x04
            if given_flag == 'A' and packet_flags != 0x10: 
                return False
            if given_flag == 'S' and packet_flags != 0x02: 
                return False
            if given_flag == 'F' and packet_flags != 0x01:  
                return False
            if given_flag == 'R' and packet_flags != 0x04:
                return False
            if given_flag == 'A+' and not (packet_flags & 0x10):  
                return False
            if given_flag == 'S+' and not (packet_flags & 0x02):  
                return False
            if given_flag == 'F+' and not (packet_flags & 0x01): 
                return False
            if given_flag == 'R+' and not (packet_flags & 0x04):  
                return False
            
            
        if 'content' in rule['options'] and packet.haslayer('Raw'):
            payload = str(packet['Raw'].load)
            if rule['options']['content'] not in payload:
                return False
  
        if 'detection_filter' in rule['options']:
            keys_rule = (rule['protocol'], rule['src_ip'], rule['src_port'], rule['dest_ip'], rule['dest_port'])
            if not detect_filter(keys_rule, rule['options']['detection_filter'], packet):
                return False
            
        return True
    
    return False

def detect_filter(keys_rule, detect_filter, packet):
    count_str, seconds_str = detect_filter.replace('count ', '').replace('seconds ', '').split(', ')
    threshold = int(count_str)
    time_window = int(seconds_str)
    now = float(packet.time)

    if keys_rule not in detected:
        detected[keys_rule] = {'count': 1, 'first_seen': now}
        return False

    first_seen = detected[keys_rule]['first_seen']
    count = detected[keys_rule]['count']

    if now - first_seen >= time_window:
        detected[keys_rule] = {'count': 1, 'first_seen': now}
        return False
    else:
        detected[keys_rule]['count'] += 1
        count = detected[keys_rule]['count']

        if count > threshold:
            return True

    return False

def log_alert(message, timestamp):
    with open('IDS_log.txt', 'a') as log_file:
        log_file.write(f'{timestamp} - Alert: {message}\n')

def main():
    if len(sys.argv) != 3:
        print("Usage: IDS.py <path_to_the_IDS_rules> <path_to_the_pcap_file>")
        sys.exit(1)

    rules_file = sys.argv[1]
    pcap_file = sys.argv[2]

    rules = []
    
    with open('IDS_log.txt', 'w') as log_file:
        log_file.write('')

    with open(rules_file, 'r') as x:
        for line in x:
            rule = parse_ids_rule(line.strip())
            if rule:
                rules.append(rule)

    packets = rdpcap(pcap_file)

    for packet in packets:
        for rule in rules:
            if check_packet(packet, rule):
                packet_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(packet.time)))
                log_alert(rule['options'].get('msg', 'Alert'), time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

if __name__ == "__main__":
    main()