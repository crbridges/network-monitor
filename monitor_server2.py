import pickle
from typing import NoReturn
import select
import typing
from network_monitor_services import *
import datetime


class MessageHandler(threading.Thread):

    def __init__(self, host: str = '127.0.0.1', port = 1234) -> NoReturn:
        super().__init__()
        self.host: str = host
        self.port: int = port
        self.message_list = []
        self.reconnect: bool = True
        self.condition: threading.Condition = threading.Condition()


    def run(self, server_ip: str = '127.0.0.1', server_port: int = 6555, client_id: str = "ALPHA") -> None:
        """

        :param server_ip:
        :param server_port:
        :param client_id:
        :return:
        """
        # client_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        with self.condition:
            while self.reconnect:
                client_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                try:
                    # Disable Nagle algorithm to send small packets immediately
                    client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                    # Enable SO_KEEPALIVE to send keepalive messages for detecting dead connections.
                    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                    # Establish a connection to the server
                    client_socket.connect((server_ip, server_port))
                    print(f"Connected to server at {server_ip}:{server_port} with customized TCP socket options.")

                    # client_socket.sendall(pickle.dumps({"name": client_id}))

                    while True:
                        for message in self.message_list:
                            client_socket.sendall(message.encode())
                            time.sleep(.1)
                            self.message_list.remove(message)



                except Exception as e:
                    print(f"Error configuring TCP socket for MessageHandler: {e}")
                finally:
                    client_socket.close()
                    print("Connection to server closed.")

                time.sleep(3)


    def add_message(self, message):
        self.message_list.append(message)


class Server:
    """
    Creates a monitor servers that waits for incoming connections from management client.
    Accepts lists across a TCP socket containing commands to set up new services, control existing services,
    and to stop the server.
    """
    def __init__(self, message_handler: MessageHandler, host: str = '127.0.0.1', port: int = 6666) -> NoReturn:
        self.host: str = host
        self.port: int = port
        self.ping_task = None
        self.task_list: list = []
        self.message_handler = message_handler
        self.status = "UNCONNECTED"
        self.monitor_id = None


    def start(self) -> NoReturn:
        """
        Starts running a nonblocking TCP socket in order to accept connections from management client.
        :return: none
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setblocking(False)

            s.bind((self.host, self.port))
            s.listen(5)
            print(f"Server Listening on {self.host}:{self.port}")

            sockets_list: typing.List[socket.socket] = [s]

            while True:
                # Use select to handle socket I/O without blocking
                # It waits for at least one of the sockets to be ready for processing
                read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

                for notified_socket in read_sockets:
                    if notified_socket == s:
                        # Accept new connection
                        client_socket, client_address = s.accept()
                        print(f"Accepted new connection from {client_address}")
                        sockets_list.append(client_socket)
                    else:
                        # Recieve data from a client socket
                        message: bytes = notified_socket.recv(1024)

                        if message:
                            # Unpickles list from management client
                            data = pickle.loads(message)
                            if not data:
                                break
                            # If data in an integer, extract ID number assigned by management client
                            elif type(data[0]) is int:
                                print(f"ID OF MONITOR SERVICE: {data[0]}")
                                self.status = "CONNECTED"
                                self.monitor_id = data[0]
                                notified_socket.sendall(f"{time_stamp()} {data[0]} monitor connected & ID assigned".encode())
                            # If data is a status request, return current status to management client
                            elif data[0] == "STATUS":
                                print("Status Check sent")
                                status = []
                                for service in self.task_list:
                                    status.append(f"Service {service.service_id}: {service.status}")
                                notified_socket.sendall(f"{self.monitor_id} monitor connected. {status}".encode())
                            # Creates new service if requested by manangement service
                            elif data[0] in ["PING", "HTTP", "HTTPS", "DNS", "NTP", "TCP", "UDP"]:
                                print(data)
                                notified_socket.sendall(f"{time_stamp()} {data[0]} task {data[3]} started on monitor {self.monitor_id} with {data}".encode())
                                service_task = ServiceTask(data, self.message_handler, self.monitor_id)
                                self.task_list.append(service_task)
                                service_task.start()
                            # Pauses all current services
                            elif data[0] == 'PAUSE':
                                for service in self.task_list:
                                    service.pause()
                                    service.status = "PAUSED"
                                notified_socket.sendall(b'All tasks paused')
                            # Resumes all paused services
                            elif data[0] == 'RESUME':
                                for service in self.task_list:
                                    service.resume()
                                    service.status = "ACTIVE"
                                notified_socket.sendall(b'All tasks resumed')
                            # Stops all active services
                            elif data[0] == 'SHUTDOWN':
                                for service in self.task_list:
                                    service.stop()
                                    service.status = "STOPPED"
                                notified_socket.sendall(b'Server shutting down')
                                break
                        else:
                            # Close empty connection
                            print(f"Closing connection to {notified_socket.getpeername()}")
                            sockets_list.remove(notified_socket)
                            notified_socket.close()

                # Handle come socket exceptions just in case
                for notified_socket in exception_sockets:
                    sockets_list.remove(notified_socket)
                    notified_socket.close()


class ServiceTask(threading.Thread):
    """
    Creates a service task for monitor server with a given interval and returns the service results to the
    message handler.
    """
    def __init__(self, service, message_handler, monitor_id) -> NoReturn:
        super().__init__()
        self.service = service
        self.message_handler = message_handler
        self.paused: bool = False
        self.stopped: bool = False
        self.condition: threading.Condition = threading.Condition()
        self.service_id = service[3]
        self.monitor_id = monitor_id
        self.status = "ACTIVE"

    def run(self) -> NoReturn:
        """
        Creates a new service and begins running the process.
        :return: none
        """
        while not self.stopped:
            with self.condition:
                if self.paused:
                    self.condition.wait()
                else:
                    match self.service[0]:
                        case "PING":
                            self.message_handler.add_message(f"Monitor: {self.monitor_id} Service: {self.service_id} {run_ping(self.service)}")
                        case "HTTP":
                            self.message_handler.add_message(f"Monitor: {self.monitor_id} Service: {self.service_id} {run_http(self.service)}")
                        case "HTTPS":
                            self.message_handler.add_message(f"Monitor: {self.monitor_id} Service: {self.service_id} {run_https(self.service)}")
                        case "DNS":
                            self.message_handler.add_message(f"Monitor: {self.monitor_id} Service: {self.service_id} {run_dns(self.service)}")
                        case "NTP":
                            self.message_handler.add_message(f"Monitor: {self.monitor_id} Service: {self.service_id} {run_ntp(self.service)}")
                        case "TCP":
                            self.message_handler.add_message(f"Monitor: {self.monitor_id} Service: {self.service_id} {run_tcp(self.service)}")
                        case "UDP":
                            self.message_handler.add_message(f"Monitor: {self.monitor_id} Service: {self.service_id} {run_udp(self.service)}")

            # Sets service interval based on parameter from management service
            time.sleep(self.service[2])

    def pause(self) -> NoReturn:
        """
        Pauses a service.
        :return: none
        """
        self.paused = True

    def resume(self) -> NoReturn:
        """
        Resumes a service.
        :return: none
        """
        with self.condition:
            self.paused = False
            self.condition.notify()

    def stop(self) -> NoReturn:
        """
        Stops a service.
        :return: none
        """
        self.stopped = True
        if self.paused:
            self.resume()


def run_ping(service_data):
    """
    Runs a ping service request.
    :param service_data: parameter list for ping task
    :return: string of ping results
    """
    ping_addr, ping_time = ping(service_data[1])

    if ping_addr and ping_time is not None:
        status = f"{time_stamp()} {service_data[1]} DNS (ping): {ping_addr[0]} - {ping_time:.2f} ms"
    else:
        status = f"{time_stamp()} {service_data[0]} DNS (ping): Request timed out or no reply received"

    print(status)
    return status


def run_http(service_data):
    """
    Runs an http service request.
    :param service_data: parameter list for http task
    :return: string of http results
    """
    http_server_status, http_server_response_code = check_server_http(service_data[1])

    status = (f"{time_stamp()}HTTP URL: {service_data[1]}, HTTP server status: {http_server_status}, "
              f"Status Code: {http_server_response_code if http_server_response_code is not None else 'N/A'}")

    print(status)
    return status


def run_https(service_data):
    """
    Runs an https service request.
    :param service_data: parameter list for https task
    :return: string of https results
    """
    https_server_status, https_server_response_code, description = check_server_https(service_data[1])

    status = (
        f"{time_stamp()} HTTPS URL: {service_data[1]}, HTTPS server status: {https_server_status}, "
        f"Status Code: {https_server_response_code if https_server_response_code is not None else 'N/A'}, "
        f"Description: {description}")

    print(status)
    return status


def run_dns(service_data):
    """
    Runs a dns service request.
    :param service_data: parameter list for dns task
    :return: string of dns results
    """
    dns_server = "8.8.8.8"  # Google's public DNS server

    dns_record_types = [
        'A',  # IPv4 Address
        'MX',  # Mail Exchange
        'AAAA',  # IPv6 Address
        'CNAME',  # Canonical Name
        'A'  # IPv4 Address
    ]
    results = ""
    for dns_record_type in dns_record_types:
        dns_server_status, dns_query_results = check_dns_server_status(dns_server, service_data[1], dns_record_type)
        results += (f"{time_stamp()} DNS Server: {dns_server}, Status: {dns_server_status}, {dns_record_type} "
                    f"Records Results: {dns_query_results}\n")

    print(results)
    return results


def run_ntp(service_data):
    """
    Runs an ntp service request.
    :param service_data: parameter list for ntp task
    :return: string of ntp results
    """
    ntp_server_status, ntp_server_time = check_ntp_server(service_data[1])

    if ntp_server_status:
        results = f"{time_stamp()} {service_data[1]} is up. Time: {ntp_server_time}"
    else:
        results = f"{time_stamp()} {service_data[1]} is down."

    print(results)
    return results


def run_tcp(service_data, tcp_port=80):
    """
    Runs a tcp service request.
    :param service_data: parameter list for tcp task
    :return: string of tcp results
    """
    tcp_port_status, tcp_port_description = check_tcp_port(service_data[1], tcp_port)

    results = (f"{time_stamp()} Server: {service_data[1]}, TCP Port: {tcp_port}, "
               f"TCP Port Status: {tcp_port_status}, Description: {tcp_port_description}")

    print(results)
    return results


def run_udp(service_data, udp_port=53):
    """
    Runs a udp service request.
    :param service_data: parameter list for udp task
    :return: string of udp results
    """
    udp_port_status, udp_port_description = check_udp_port(service_data[1], udp_port)

    results = (f"{time_stamp()} Server: {service_data[1]}, UDP Port: {udp_port}, "
               f"UDP Port Status: {udp_port_status}, Description: {udp_port_description}")

    print(results)
    return results


def time_stamp():
    """
    Creates a timestamp for print statements.
    :return: string of current time
    """
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":

    handler = MessageHandler()
    handler.start()

    server = Server(handler)
    server.start()
