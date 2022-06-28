from sys import argv
import socket
import dpkt


def detect_anomaly(packet_capture):
    """
    Process a dpkt packet capture to determine if any syn scan is detected. For every IP address address that are
    detected as suspicious. We define "suspicious" as having sent more than three times as many SYN packets as the
    number of SYN+ACK packets received.
    :param packet_capture: dpkt packet capture object for processing
    """

    # Creates a dictionary where the keys are the IP addresses and the values are
    # arrays where the first element is the number of sent SYN packets and the second
    # element is the number of received SYN-ACK packets
    ipDict = {}

    for ts, buf in packet_capture:
        try:
            # Attempts to parse the current buffer as a TCP packet and
            # skips any other non-TCP packets
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data

            # Converts the source and destination IP addresses into
            # human-readable strings
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)


            # Checks if the packet only has a TCP SYN flag; if so, then
            # the source IP address's SYN request count is incremented in 
            # the dictionary
            if (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
                if (src in ipDict):
                    ipDict[src][0] += 1
                else:
                    ipDict[src] = [1, 0]
            # Checks if the packet has both TCP SYN flag and a TCP ACK flag; 
            # if so, then the destination IP address's SYN+ACK receive count
            # is incremented in the dictionary
            elif (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK):
                if (dst in ipDict):
                    ipDict[dst][1] += 1
                else:
                    ipDict[dst] = [0, 1]
        except: continue

    # Loops through all of the IP addresses in the array to print out
    # the ones that seem to be performing a SYN scan
    for ip in ipDict:
        if (ipDict[ip][0] > 3 * ipDict[ip][1]):
            print(ip)
    

# parse the command line argument and open the file specified
if __name__ == '__main__':
    if len(argv) != 2:
        print('usage: python detector.py capture.pcap')
        exit(-1)

    with open(argv[1], 'rb') as f:
        pcap_obj = dpkt.pcap.Reader(f)
        detect_anomaly(pcap_obj)