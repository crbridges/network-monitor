import os
import socket
import struct
import threading
import time
import zlib
import random
import string
import requests
import ntplib
import dns.resolver
import dns.exception
from socket import gaierror
from time import ctime
from typing import Tuple, Optional, Any


def calculate_icmp_checksum(data: bytes) -> int:
    """
    Calculate the checksum for the ICMP packet. The checksum is calculated by summing the 16-bit words of the entire packet,
    carrying any overflow bits around, and then complementing the result.
    :param data: The data for which the checksum is to be calculated.
    :return: int The calculated checksum.
    """

    # Initializes checksum to 0
    s = 0

    # Iterate over the data in 16-bit chunks and calculate total sum
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1])
        s += w

    # Add the overflow back into the sum.
    s = (s >> 16) + (s & 0xffff)

    # Takes one's complement of the result
    s = ~s & 0xffff

    return s


def create_icmp_packet(icmp_type: int = 8, icmp_code: int = 0, sequence_number: int = 1, data_size: int = 192) -> bytes:
    """
    Creates an ICMP (Internet Control Message Protocol) packet with specified parameters.

    :param icmp_type: int type of the ICMP packet. Default is 8 (Echo Request).
    :param icmp_code: int code of the ICMP packet. Default is 0.
    :param sequence_number: int sequence number of the ICMP packet. Default is 1.
    :param data_size: int size of the data payload in the ICMP packet. Default is 192 bytes.

    :return: bytes object representing the complete ICMP packet.
    """

    # Get the current thread identifier and process identifier.
    thread_id = threading.get_ident()
    process_id = os.getpid()

    # Generate a unique ICMP identifier using CRC32 over the concatenation of thread_id and process_id.
    icmp_id = zlib.crc32(f"{thread_id}{process_id}".encode()) & 0xffff

    # Create the ICMP header fields .
    header: bytes = struct.pack('bbHHh', icmp_type, icmp_code, 0, icmp_id, sequence_number)

    # Create random data payload for the ICMP packet.
    random_char: str = random.choice(string.ascii_letters + string.digits)
    data: bytes = (random_char * data_size).encode()

    # Calculate the checksum of the header and data.
    chksum: int = calculate_icmp_checksum(header + data)

    # Recreate the ICMP header with the correct checksum.
    header = struct.pack('bbHHh', icmp_type, icmp_code, socket.htons(chksum), icmp_id, sequence_number)

    # Return the complete ICMP packet by concatenating the header and data.
    return header + data


def ping(host: str, ttl: int = 64, timeout: int = 1, sequence_number: int = 1) -> Tuple[Any, float] | Tuple[Any, None]:
    """
    Send an ICMP Echo Request to a specified host and measure the round-trip time.

    :param host : string of IP address or hostname of the target host.
    :param ttl :  int Time-To-Live for the ICMP packet.
    :param timeout : int time in seconds that the function will wait for a reply before giving up.
    :param sequence_number : int sequence number for the ICMP packet.

    :return: tuple containing the address of the replier and the total ping time in milliseconds.
    """

    # Create a raw socket with the Internet Protocol (IPv4) and ICMP.
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        # Set the Time-To-Live (TTL) for the ICMP packet.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # Set the timeout for the socket's blocking operations (e.g., recvfrom).
        sock.settimeout(timeout)

        # Create an ICMP Echo Request packet.
        packet: bytes = create_icmp_packet(icmp_type=8, icmp_code=0, sequence_number=sequence_number)

        # Send the ICMP packet to the target host.
        sock.sendto(packet, (host, 1))

        # Record the current time to measure the round-trip time later.
        start: float = time.time()

        try:
            # Wait to receive data from the socket (up to 1024 bytes).
            data, addr = sock.recvfrom(1024)

            # Record the time when the reply is received.
            end: float = time.time()

            # Calculate the round-trip time in milliseconds.
            total_ping_time = (end - start) * 1000

            # Return the address of the replier and the total ping time.
            return addr, total_ping_time
        except socket.timeout:
            # If no reply is received within the timeout period, return None for the ping time.
            return None, None


def traceroute(host: str, max_hops: int = 30, pings_per_hop: int = 1, verbose: bool = False) -> str:
    """
    Perform a traceroute to the specified host, with multiple pings per hop.

    :param host: string IP address or hostname of the target host.
    :param max_hops: int maximum number of hops to try before stopping.
    :param pings_per_hop: int number of pings to perform at each hop.
    :param verbose : boolean -  If True, print additional details during execution.

    :return: str results of the traceroute, including statistics for each hop.
    """
    # Header row for the results
    results = [f"{'Hop':>3} {'Address':<15} {'Min (ms)':>8}   {'Avg (ms)':>8}   {'Max (ms)':>8}   {'Count':>5}"]

    # Loop through each TTL (Time-To-Live) value from 1 to max_hops.
    for ttl in range(1, max_hops + 1):
        # Print verbose output if enabled.
        if verbose:
            print(f"pinging {host} with ttl: {ttl}")

        # List to store ping response times for the current TTL.
        ping_times = []

        # Perform pings_per_hop number of pings for the current TTL.
        for _ in range(pings_per_hop):
            # Ping the host with the current TTL and sequence number.
            addr, response = ping(host, ttl=ttl, sequence_number=ttl)

            # If a response is received (not None), append it to ping_times.
            if response is not None:
                ping_times.append(response)

        # If there are valid ping responses, calculate and format the statistics.
        if ping_times:
            min_time = min(ping_times)  # Minimum ping time.
            avg_time = sum(ping_times) / len(ping_times)  # Average ping time.
            max_time = max(ping_times)  # Maximum ping time.
            count = len(ping_times)  # Count of successful pings.

            # Append the formatted results for this TTL to the results list.
            results.append(f"{ttl:>3} {addr[0] if addr else '*':<15} {min_time:>8.2f}ms {avg_time:>8.2f}ms {max_time:>8.2f}ms {count:>5}")
        else:
            # If no valid responses, append a row of asterisks and zero count.
            results.append(f"{ttl:>3} {'*':<15} {'*':>8}   {'*':>8}   {'*':>8}   {0:>5}")

        # Print the last entry in the results if verbose mode is enabled.
        if verbose and results:
            print(f"\tResult: {results[-1]}")

        # If the address of the response matches the target host, stop the traceroute.
        if addr and addr[0] == host:
            break

    # Join all results into a single string with newline separators and return.
    return '\n'.join(results)


def check_server_http(url: str) -> Tuple[bool, Optional[int]]:
    """
    Check if an HTTP server is up by making a request to the provided URL.

    :param url: str URL of the server (including http://)
    :return: tuple (True/False, status code)
             True if server is up (status code < 400), False otherwise
    """
    try:
        # Making a GET request to the server
        response: requests.Response = requests.get(url)

        # Checks http status code
        is_up: bool = response.status_code < 400

        # Returning a tuple: (True/False, status code)
        return is_up, response.status_code

        # Returns False if exception or error occurs
    except requests.RequestException:
        return False, None


def check_server_https(url: str, timeout: int = 5) -> Tuple[bool, Optional[int], str]:
    """
    Check if an HTTPS server is up by making a request to the provided URL.

    :param url: str URL of the server (including https://)
    :param timeout: int timeout for the request in seconds. Default is 5 seconds.
    :return: tuple (True/False for server status, status code, description)
    """
    try:
        # Setting custom headers to mimic a web browser.
        headers: dict = {'User-Agent': 'Mozilla/5.0'}

        # Making a GET request to the server with the specified URL and timeout.
        response: requests.Response = requests.get(url, headers=headers, timeout=timeout)

        # Checks https status code
        is_up: bool = response.status_code < 400

        # Returning a tuple: (server status, status code, descriptive message)
        return is_up, response.status_code, "Server is up"

    # Returns False if exception or error occurs
    except requests.ConnectionError:
        return False, None, "Connection error"

    except requests.Timeout:
        # returns exception is raised if the server does not send any data in the allotted time (specified by timeout).
        return False, None, "Timeout occurred"

    except requests.RequestException as e:
        # returns exception for any error not covered by the specific exceptions above.
        return False, None, f"Error during request: {e}"


def check_ntp_server(server: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if an NTP server is up and returns its status and time.

    Args:
    server (str): The hostname or IP address of the NTP server to check.

    Returns:
    Tuple[bool, Optional[str]]: A tuple containing a boolean indicating the server status
                                 (True if up, False if down) and the current time as a string
                                 if the server is up, or None if it's down.
    """
    # Create an NTP client instance
    client = ntplib.NTPClient()

    try:
        # Request time from the NTP server
        # 'version=3' specifies the NTP version to use for the request
        response = client.request(server, version=3)

        # If request is successful, return True and the server time
        # 'ctime' converts the time in seconds since the epoch to a readable format
        return True, ctime(response.tx_time)
    except (ntplib.NTPException, gaierror):
        # If an exception occurs (server is down or unreachable), return False and None
        return False, None


def check_dns_server_status(server, query, record_type) -> (bool, str):
    """
    Check if a DNS server is up and return the DNS query results for a specified domain and record type.

    :param server: DNS server name or IP address
    :param query: Domain name to query
    :param record_type: Type of DNS record (e.g., 'A', 'AAAA', 'MX', 'CNAME')
    :return: Tuple (status, query_results)
    """
    try:
        # Set the DNS resolver to use the specified server
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [socket.gethostbyname(server)]

        # Perform a DNS query for the specified domain and record type
        query_results = resolver.resolve(query, record_type)
        results = [str(rdata) for rdata in query_results]

        return True, results

    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer, socket.gaierror) as e:
        # Return False if there's an exception (server down, query failed, or record type not found)
        return False, str(e)


def check_tcp_port(ip_address: str, port: int) -> (bool, str):
    """
    Checks the status of a specific TCP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The TCP port number to check.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open, False otherwise.
           The string provides a description of the port status.

    Description:
    This function attempts to establish a TCP connection to the specified port on the given IP address.
    If the connection is successful, it means the port is open; otherwise, the port is considered closed or unreachable.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_STREAM socket type (TCP).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely. Here, 3 seconds is used as a reasonable timeout duration.
            s.settimeout(3)

            # Attempt to connect to the specified IP address and port.
            # If the connection is successful, the port is open.
            s.connect((ip_address, port))
            return True, f"Port {port} on {ip_address} is open."

    except socket.timeout:
        # If a timeout occurs, it means the connection attempt took too long, implying the port might be filtered or the server is slow to respond.
        return False, f"Port {port} on {ip_address} timed out."

    except socket.error:
        # If a socket error occurs, it generally means the port is closed or not reachable.
        return False, f"Port {port} on {ip_address} is closed or not reachable."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check port {port} on {ip_address} due to an error: {e}"


def check_udp_port(ip_address: str, port: int, timeout: int = 3) -> (bool, str):
    """
    Checks the status of a specific UDP port on a given IP address.

    Args:
    ip_address (str): The IP address of the target server.
    port (int): The UDP port number to check.
    timeout (int): The timeout duration in seconds for the socket operation. Default is 3 seconds.

    Returns:
    tuple: A tuple containing a boolean and a string.
           The boolean is True if the port is open (or if the status is uncertain), False if the port is definitely closed.
           The string provides a description of the port status.

    Description:
    This function attempts to send a UDP packet to the specified port on the given IP address.
    Since UDP is a connectionless protocol, the function can't definitively determine if the port is open.
    It can only confirm if the port is closed, typically indicated by an ICMP 'Destination Unreachable' response.
    """

    try:
        # Create a socket object using the AF_INET address family (IPv4) and SOCK_DGRAM socket type (UDP).
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Set a timeout for the socket to avoid waiting indefinitely.
            s.settimeout(timeout)

            # Send a dummy packet to the specified IP address and port.
            # As UDP is connectionless, this does not establish a connection but merely sends the packet.
            s.sendto(b'', (ip_address, port))

            try:
                # Try to receive data from the socket.
                # If an ICMP 'Destination Unreachable' message is received, the port is considered closed.
                s.recvfrom(1024)
                return False, f"Port {port} on {ip_address} is closed."

            except socket.timeout:
                # If a timeout occurs, it's uncertain whether the port is open or closed, as no response is received.
                return True, f"Port {port} on {ip_address} is open or no response received."

    except Exception as e:
        # Catch any other exceptions and return a general failure message along with the exception raised.
        return False, f"Failed to check UDP port {port} on {ip_address} due to an error: {e}"

if __name__ == "__main__":

    # Ping Usage Example
    print("Ping Example:")
    ping_addr, ping_time = ping("8.8.8.8")
    print(f"Google DNS (ping): {ping_addr[0]} - {ping_time:.2f} ms" if (ping_addr and ping_time is not None) else "Google DNS (ping): Request timed out or no reply received")

    # Traceroute Usage Example
    # Note: This function is included as an extra to round out the ICMP examples.
    print("\nTraceroute Example:")
    print("Google DNS (traceroute):")
    print(traceroute("8.8.8.8"))

    # HTTP/HTTPS Usage Examples
    print("\nHTTP/HTTPS Examples:")
    http_url = "http://example.com"
    http_server_status, http_server_response_code = check_server_http(http_url)
    print(f"HTTP URL: {http_url}, HTTP server status: {http_server_status}, Status Code: {http_server_response_code if http_server_response_code is not None else 'N/A'}")

    https_url = "https://example.com"
    https_server_status, https_server_response_code, description = check_server_https(https_url)
    print(f"HTTPS URL: {https_url}, HTTPS server status: {https_server_status}, Status Code: {https_server_response_code if https_server_response_code is not None else 'N/A'}, Description: {description}")

    # NTP Usage Example
    print("\nNTP Example:")
    ntp_server = 'pool.ntp.org'  # Replace with your NTP server
    ntp_server_status, ntp_server_time = check_ntp_server(ntp_server)
    print(f"{ntp_server} is up. Time: {ntp_server_time}" if ntp_server_status else f"{ntp_server} is down.")

    # DNS Usage Examples
    print("\nDNS Examples:")
    dns_server = "8.8.8.8" # Google's public DNS server

    dns_queries = [
        ('google.com', 'A'),        # IPv4 Address
        ('google.com', 'MX'),       # Mail Exchange
        ('google.com', 'AAAA'),     # IPv6 Address
        ('google.com', 'CNAME'),    # Canonical Name
        ('yahoo.com', 'A'),         # IPv4 Address
    ]

    for dns_query, dns_record_type in dns_queries:
        dns_server_status, dns_query_results = check_dns_server_status(dns_server, dns_query, dns_record_type)
        print(f"DNS Server: {dns_server}, Status: {dns_server_status}, {dns_record_type} Records Results: {dns_query_results}")


    # TCP Port Usage Example
    print("\nTCP Port Example:")
    tcp_port_server = "google.com"
    tcp_port_number = 80
    tcp_port_status, tcp_port_description = check_tcp_port(tcp_port_server, tcp_port_number)
    print(f"Server: {tcp_port_server}, TCP Port: {tcp_port_number}, TCP Port Status: {tcp_port_status}, Description: {tcp_port_description}")

    # UDP Port Usage Example
    print("\nUDP Port Example:")
    udp_port_server = "8.8.8.8"
    udp_port_number = 53
    udp_port_status, udp_port_description = check_udp_port(udp_port_server, udp_port_number)
    print(f"Server: {udp_port_server}, UDP Port: {udp_port_number}, UDP Port Status: {udp_port_status}, Description: {udp_port_description}")


