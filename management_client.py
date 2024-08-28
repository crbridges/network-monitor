import pickle
import socket
import time
from typing import NoReturn
import threading
import typing
import select

# Service list for monitor. Should be formatted as ["SERVICE_NAME", "SERVER_ADDRESS", INTERVAL]
M1_SERVICES = [
    ["PING", "127.0.0.1", 60],
    ["HTTP", "example.com", 60],
    ["HTTPS", "example.com", 60],
    ["DNS", "amazon.com", 50],
    ["NTP", "pool.ntp.org", 50],
    ["TCP", "google.com", 50],
    ["UDP", "google.com", 10],
            ]

M2_SERVICES = [
    ["PING", "127.0.0.1", 60],
    ["PING", "amazon.com", 30],
    ["PING", "example.com", 30],
            ]

M3_SERVICES = [
    ["PING", "127.0.0.1", 60],
    ["PING", "amazon.com", 10],
    ["PING", "example.com", 5],
            ]

# List of monitors with their associated service list, IP, port
MONITORS = {
    "m_1": {"services": M1_SERVICES, "IP": '127.0.0.1', "port": 6543},
    "m_2": {"services": M2_SERVICES, "IP": '127.0.0.1', "port": 6666},
    "m_3": {"services": M3_SERVICES, "IP": '127.0.0.1', "port": 3456},
}


class MonitorControlClient(threading.Thread):
    """
    Creates a class responsible for transferring monitor services from management service across TCP socket.
    Data is sent as a list with an appended unique ID number for each service.
    """
    def __init__(self, id_generator, services, host: str = '127.0.0.1', port: int = 6543) -> NoReturn:
        super().__init__()
        self.host: str = host
        self.port: int = port
        self.id_generator = id_generator
        self.services = services

    def send_command(self, command: list) -> NoReturn:
        """
        Sends a list across TCP socket.
        :param command: list to be send
        :return: none
        """
        try:
            # Creates socket to send list with TCP keepalive mechanisms
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                s.connect((self.host, self.port))
                s.sendall(pickle.dumps(command))
                response = s.recv(1024)
                print(f"Server response: {response.decode('ascii')}")
        except Exception as e:
            print(f"Error configuring TCP socket: {e}")

    def start(self) -> NoReturn:
        # Appends a unique ID number to each service parameter list and send across TCP socket
        for service in self.services:
            service_id = next(self.id_generator)
            service.append(service_id)
            self.send_command(service)


class MessageServer(threading.Thread):
    def __int__(self):
        super().__init__()
        self.condition: threading.Condition = threading.Condition()

    def run(self):
        self.start_non_blocking_tcp_server()

    def start_non_blocking_tcp_server(self, server_ip: str = '127.0.0.1', server_port: int = 6555) -> None:
        """

        :param server_ip:
        :param server_port:
        :return:
        """
        # Create a TCP/IP socket
        server_socket: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set a socket to non-blocking mode
        server_socket.setblocking(False)

        # Bind socket to server address and port
        server_socket.bind((server_ip, server_port))

        # Listen for incoming connections
        server_socket.listen(5)
        print(f"Non-blocking TCP Sever listening on {server_ip}:{server_port}")

        # List of sockets for select.select()
        sockets_list: typing.List[socket.socket] = [server_socket]

        try:
            while True:
                # Use select to handle socket I/O without blocking
                # It waits for at least one of the sockets to be ready for processing
                read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

                for notified_socket in read_sockets:
                    if notified_socket == server_socket:
                        # Accept new connection
                        client_socket, client_address = server_socket.accept()
                        print(f"Accepted new connection from {client_address}")
                        sockets_list.append(client_socket)
                    else:
                        # Recieve data from a client socket
                        try:
                            message: bytes = notified_socket.recv(1024)

                            if message:
                                # A readable client socket has data
                                print(f"Received message from {notified_socket.getpeername()}: {message.decode()}")
                            else:
                                # Close empty connection
                                print(f"Closing connection to {notified_socket.getpeername()}")
                                sockets_list.remove(notified_socket)
                                notified_socket.close()

                        except Exception as e:
                            print(f"EXCEPTION {e}")
                            notified_socket.close()
                            sockets_list.remove(notified_socket)

                # Handle come socket exceptions just in case
                for notified_socket in exception_sockets:
                    sockets_list.remove(notified_socket)
                    notified_socket.close()

        except Exception as e:
            print(f"Error configuring TCP socket: {e}")

        finally:
            server_socket.close()


class MonitorInitializer(threading.Thread):
    def __init__(self, id_generator, port = 6543):
        super().__init__()
        self.host = '127.0.0.1'
        self.port = port
        self.monitor_id = next(id_generator)
        self.status = "NOT CONNECTED"
        self.condition: threading.Condition = threading.Condition()

    def start(self) -> NoReturn:
        command = [self.monitor_id]

        with self.condition:
            while self.status == "NOT CONNECTED":
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                        s.connect((self.host, self.port))
                        s.sendall(pickle.dumps(command))

                        response = s.recv(1024)
                        print(f"Server response: {response.decode('ascii')}")
                        self.status = "CONNECTED"
                except Exception as e:
                    self.status = "NOT CONNECTED"
                    print(f"Error configuring TCP socket: {e}")
                    print(f"Monitor {self.monitor_id} disconnected - attempting to reconnect in 2s.")
                    time.sleep(2)

    def send_command(self, command: str) -> NoReturn:
        """
        Sends a list across TCP socket.
        :param command: list to be sent
        :return: none
        """
        try:
            # Creates socket to send list with TCP keepalive mechanisms
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                s.connect((self.host, self.port))
                s.sendall(pickle.dumps([command]))
                response = s.recv(1024)
                print(f"Server response: {response.decode('ascii')}")
        except Exception as e:
            print(f"Error configuring TCP socket: {e}")

    async def update_status(self, session) -> NoReturn:
        # Takes user input to control services on monitor server
        with patch_stdout():
            command = (await session.prompt_async("Enter command (STATUS, PAUSE, RESUME, or SHUTDOWN): \n")).upper()
            if command in ["STATUS", "PAUSE", "RESUME", "SHUTDOWN"]:
                self.send_command(command)
            else:
                print("Invalid command. Please enter STATUS, PAUSE, RESUME, or SHUTDOWN.")


def sequential_generator(start_index):
    """Generates all numbers from start_index up to infinity"""
    num = start_index
    while num >= 0:
        yield num
        num += 1


from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
import asyncio


async def handle_commands():
    session: PromptSession = PromptSession()

    while True:
        with patch_stdout():
            command = await session.prompt_async("What server would you like to control? ")

            try:
                await server_list[int(command)-1].update_status(session)
            except Exception as e:
                print("Invalid server number.")


if __name__ == "__main__":
    server_list =[]
    id_generator1 = sequential_generator(1000)
    id_generator2 = sequential_generator(2000)

    message_server = MessageServer()
    message_server.start()

    for index, monitor in enumerate(MONITORS.values()):
        id_generator = sequential_generator((index+1) * 1000)
        print(monitor)
        status_connection = MonitorInitializer(id_generator, port=monitor['port'])
        status_connection.start()
        service_connection = MonitorControlClient(id_generator, monitor['services'], port=monitor['port'])
        service_connection.start()

        server_list.append(status_connection)

    # Runs command handler for monitor control
    asyncio.run(handle_commands())
