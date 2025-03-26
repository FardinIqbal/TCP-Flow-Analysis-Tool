#!/usr/bin/env python3
import dpkt
import socket
import sys
from collections import defaultdict

# Predefined IP addresses for the sender and receiver
SENDER_IP = '130.245.145.12'
RECEIVER_IP = '128.208.2.198'


def inet_to_str(inet):
    """
    Convert a binary IP address to its string representation.

    Args:
        inet (bytes): Binary IPv4/IPv6 address

    Returns:
        str: Human-readable IP address string
    """
    try:
        return socket.inet_ntoa(inet)  # For IPv4 addresses
    except:
        return socket.inet_ntop(socket.AF_INET6, inet)  # For IPv6 addresses


def analyze_pcap_tcp(filename):
    """
    Analyze TCP flows in a packet capture file.

    This function reads a PCAP file and extracts detailed information about
    TCP flows between the predefined sender and receiver.

    Args:
        filename (str): Path to the PCAP file to analyze
    """
    # Open and read the PCAP file
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        # Data structures to store analysis information
        flows = {}  # Store complete flow information
        flow_states = {}  # Track TCP connection states
        rtt_estimates = {}  # Store round-trip time estimates
        retransmissions = defaultdict(list)  # Track packet retransmissions
        ack_counts = defaultdict(lambda: defaultdict(int))  # Count ACKs for duplicate detection

        # Process each packet in the capture file
        for timestamp, buffer in pcap:
            try:
                # Parse the Ethernet frame
                ethernet_frame = dpkt.ethernet.Ethernet(buffer)

                # Skip non-IP packets
                if not isinstance(ethernet_frame.data, dpkt.ip.IP):
                    continue

                ip_packet = ethernet_frame.data

                # Skip non-TCP packets
                if not isinstance(ip_packet.data, dpkt.tcp.TCP):
                    continue

                tcp_segment = ip_packet.data
                source_ip = inet_to_str(ip_packet.src)
                destination_ip = inet_to_str(ip_packet.dst)

                # Determine packet direction and create flow identifier
                if source_ip == SENDER_IP and destination_ip == RECEIVER_IP:
                    # Sender to receiver direction
                    flow_id = (tcp_segment.sport, source_ip, tcp_segment.dport, destination_ip)
                    direction = 'sender_to_receiver'
                elif source_ip == RECEIVER_IP and destination_ip == SENDER_IP:
                    # Receiver to sender direction (use same flow_id format for consistency)
                    flow_id = (tcp_segment.dport, destination_ip, tcp_segment.sport, source_ip)
                    direction = 'receiver_to_sender'
                else:
                    # Skip packets not between our target hosts
                    continue

                # Initialize new flows with default values
                if flow_id not in flows:
                    flows[flow_id] = {
                        'start_time': None,  # Flow start timestamp
                        'end_time': None,  # Flow end timestamp
                        'transactions': [],  # List of all packet transactions
                        'total_bytes': 0,  # Total bytes transferred
                        'window_scale': 0,  # TCP window scaling factor
                        'syn_time': None,  # Time when SYN was sent
                        'cwnd_estimates': [],  # Congestion window size estimates
                        'retransmissions': {  # Retransmission counters by type
                            'triple_dup': 0,  # Triple duplicate ACKs
                            'timeout': 0,  # Timeout retransmissions
                            'other': 0  # Other retransmission types
                        },
                        'seq_seen': set(),  # Set of sequence numbers seen
                        'last_seq_time': {}  # Last time a sequence number was seen
                    }
                    flow_states[flow_id] = 'INIT'  # Initial connection state

                # Extract TCP window scaling option if present
                if tcp_segment.opts:
                    options = dpkt.tcp.parse_opts(tcp_segment.opts)
                    for option_type, option_data in options:
                        if option_type == 3:  # Window scale option (RFC 1323)
                            if len(option_data) > 0:
                                flows[flow_id]['window_scale'] = ord(option_data)

                # Process packets from sender to receiver
                if direction == 'sender_to_receiver':
                    # Detect SYN packet (connection initiation)
                    if tcp_segment.flags & dpkt.tcp.TH_SYN and not (tcp_segment.flags & dpkt.tcp.TH_ACK):
                        flow_states[flow_id] = 'SYN_SENT'
                        flows[flow_id]['start_time'] = timestamp
                        flows[flow_id]['syn_time'] = timestamp
                        flows[flow_id]['total_bytes'] += len(tcp_segment)

                    # Detect FIN packet (connection termination)
                    if tcp_segment.flags & dpkt.tcp.TH_FIN:
                        flow_states[flow_id] = 'FIN_SENT'

                    # Count bytes for throughput calculation
                    if flow_states[flow_id] != 'INIT':
                        flows[flow_id]['total_bytes'] += len(tcp_segment)

                    # Detect retransmissions (same sequence number seen again with data)
                    if tcp_segment.seq in flows[flow_id]['seq_seen'] and len(tcp_segment.data) > 0:
                        retransmissions[flow_id].append((timestamp, tcp_segment.seq, tcp_segment.ack))

                        # Classify retransmission type
                        if tcp_segment.seq in flows[flow_id]['last_seq_time']:
                            time_difference = timestamp - flows[flow_id]['last_seq_time'][tcp_segment.seq]
                            # Estimate retransmission timeout as 2x RTT
                            retransmission_timeout = rtt_estimates.get(flow_id, 1) * 2

                            if time_difference > retransmission_timeout:
                                # Retransmission likely due to timeout
                                flows[flow_id]['retransmissions']['timeout'] += 1
                            else:
                                # Check if caused by triple duplicate ACKs
                                if ack_counts[flow_id][tcp_segment.seq] >= 3:
                                    flows[flow_id]['retransmissions']['triple_dup'] += 1
                                else:
                                    # Other retransmission causes
                                    flows[flow_id]['retransmissions']['other'] += 1

                    # Track sequence numbers and their timestamps
                    if len(tcp_segment.data) > 0:
                        flows[flow_id]['seq_seen'].add(tcp_segment.seq)
                        flows[flow_id]['last_seq_time'][tcp_segment.seq] = timestamp

                # Process packets from receiver to sender
                elif direction == 'receiver_to_sender':
                    # Detect SYN-ACK packet (connection establishment)
                    if tcp_segment.flags & dpkt.tcp.TH_SYN and tcp_segment.flags & dpkt.tcp.TH_ACK:
                        flow_states[flow_id] = 'SYN_RCVD'

                        # Calculate initial RTT from SYN to SYN-ACK
                        if flows[flow_id]['syn_time']:
                            round_trip_time = timestamp - flows[flow_id]['syn_time']
                            rtt_estimates[flow_id] = round_trip_time

                    # Count ACKs for detecting triple duplicates
                    if tcp_segment.flags & dpkt.tcp.TH_ACK:
                        ack_counts[flow_id][tcp_segment.ack] += 1

                # Record transaction details for all packets
                flows[flow_id]['transactions'].append({
                    'ts': timestamp,
                    'seq': tcp_segment.seq,
                    'ack': tcp_segment.ack,
                    'win': tcp_segment.win,
                    'direction': direction,
                    'data_len': len(tcp_segment.data)
                })

                # Update flow end time with each packet
                flows[flow_id]['end_time'] = timestamp

            except Exception as e:
                # Skip packets that cause parsing errors
                continue

        # Estimate congestion window sizes for each flow
        for flow_id, flow in flows.items():
            if flow_states[flow_id] == 'INIT':
                continue  # Skip flows that never established

            # Sort transactions chronologically
            flow['transactions'].sort(key=lambda x: x['ts'])

            # Find when connection was established
            established_index = 0
            for i, transaction in enumerate(flow['transactions']):
                if transaction['direction'] == 'sender_to_receiver' and flow_states[flow_id] == 'SYN_RCVD':
                    established_index = i
                    break

            # Estimate congestion window sizes using RTT intervals
            if flow_id in rtt_estimates:
                round_trip_time = rtt_estimates[flow_id]
                window_start_time = flow['start_time']

                # Calculate first 3 congestion windows
                for i in range(3):
                    window_end_time = window_start_time + round_trip_time
                    packets_in_window = 0

                    # Count data packets in each RTT window
                    for transaction in flow['transactions']:
                        if (transaction['direction'] == 'sender_to_receiver' and
                                window_start_time <= transaction['ts'] < window_end_time and
                                transaction['data_len'] > 0):
                            packets_in_window += 1

                    # Record window size if packets were sent
                    if packets_in_window > 0:
                        flow['cwnd_estimates'].append(packets_in_window)

                    # Move to next window
                    window_start_time = window_end_time

                    # Stop if we've reached the end of the flow
                    if window_start_time > flow['end_time']:
                        break

        # Display analysis results
        print_analysis(flows, flow_states)


def print_analysis(flows, flow_states):
    """
    Print formatted analysis results for all TCP flows.

    Args:
        flows (dict): Dictionary containing flow information
        flow_states (dict): Dictionary tracking flow states
    """
    # Identify flows initiated by the sender
    sender_flows = [flow_id for flow_id, state in flow_states.items() if state != 'INIT']

    print(f"TCP FLOWS INITIATED FROM SENDER ({SENDER_IP}):")
    print(f"Number of TCP flows: {len(sender_flows)}")

    # Print detailed information for each flow
    for flow_index, flow_id in enumerate(sender_flows, 1):
        flow = flows[flow_id]
        source_port, source_ip, destination_port, destination_ip = flow_id

        print(f"\nFLOW {flow_index} {'=' * 40}")
        print(f"Source: {source_ip}:{source_port}")
        print(f"Destination: {destination_ip}:{destination_port}")

        # Extract first two data transactions after connection setup
        first_two_transactions = []
        connection_setup_complete = False

        for transaction in flow['transactions']:
            if not connection_setup_complete and transaction[
                'direction'] == 'sender_to_receiver' and 'ack' in transaction:
                connection_setup_complete = True
                continue

            if connection_setup_complete and transaction['direction'] == 'sender_to_receiver':
                first_two_transactions.append(transaction)
                if len(first_two_transactions) == 2:
                    break

        # Display first two transactions in a more readable format
        print("\n** Initial Transactions (after handshake):")
        for i, transaction in enumerate(first_two_transactions, 1):
            # Apply window scaling factor to get actual window size
            actual_window_size = transaction['win'] << flow['window_scale']
            print(f"  Transaction {i}:")
            print(f"    Sequence: {transaction['seq']:,}")
            print(f"    Ack: {transaction['ack']:,}")
            print(f"    Window Size: {actual_window_size:,} bytes")

        # Display congestion window estimates in a table-like format
        print("\n** Congestion Window Sizes:")
        for window_index, window_size in enumerate(flow['cwnd_estimates']):
            print(f"  Window {window_index + 1}: {window_size} packets")

        # Display retransmission statistics with better formatting
        total_retransmissions = sum(flow['retransmissions'].values())
        print(f"\n** Retransmission Analysis:")
        print(f"  Total: {total_retransmissions}")
        if total_retransmissions > 0:
            triple_dup = flow['retransmissions']['triple_dup']
            timeout = flow['retransmissions']['timeout']
            other = flow['retransmissions']['other']

            triple_dup_pct = (triple_dup / total_retransmissions) * 100 if total_retransmissions > 0 else 0
            timeout_pct = (timeout / total_retransmissions) * 100 if total_retransmissions > 0 else 0
            other_pct = (other / total_retransmissions) * 100 if total_retransmissions > 0 else 0

            print(f"  Triple Duplicate ACKs: {triple_dup} ({triple_dup_pct:.1f}%)")
            print(f"  Timeout: {timeout} ({timeout_pct:.1f}%)")
            print(f"  Other: {other} ({other_pct:.1f}%)")
        else:
            print("  No retransmissions detected")

        # Calculate and display throughput with better formatting
        if flow['end_time'] and flow['start_time']:
            flow_duration = flow['end_time'] - flow['start_time']
            throughput_mbps = (flow['total_bytes'] * 8) / flow_duration / 1000000
            print(f"\n** Performance:")
            print(f"  Throughput: {throughput_mbps:.2f} Mbps")
            print(f"  Duration: {flow_duration:.3f} seconds")
            print(f"  Total Data: {flow['total_bytes']:,} bytes")

    print("\n" + "=" * 50)
    print(f"TOTAL FLOWS ANALYZED: {len(sender_flows)}")


def main():
    """
    Main entry point for the script.
    Validates command line arguments and initiates PCAP analysis.
    """
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    pcap_file_path = sys.argv[1]
    analyze_pcap_tcp(pcap_file_path)


if __name__ == "__main__":
    main()
