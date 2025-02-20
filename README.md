# Network Monitoring System

This network monitoring system consists of a server and client application. The server accepts connections from multiple monitor clients and runs service tasks like Ping, HTTP, DNS, etc. Each client can submit tasks to be monitored, while the server handles and manages the monitoring processes.

---

## Server Setup

The server runs as a non-blocking TCP socket server. By default, it listens on `127.0.0.1` at port `6543`. The server accepts connections from clients that are running the `client.py` script.

Adding a Service

You can start a service task (such as PING, HTTP, HTTPS, etc.) by sending a message from the management client. Here is a sample JSON message sent from the client to the server:
```bash
{
  "command": "start",
  "service": "PING",
  "host": "example.com",
  "interval": 60,
  "service_id": 1
}
```

This message will trigger the server to start a Ping service on example.com with a 60-second interval.

To run the server:

```bash
python monitor_server1.py
```
Once the server starts, it will listen for incoming connections and handle service requests sent by the client.


## Client Setup

The client connects to the server using a TCP socket and sends monitoring tasks. By default, it connects to 127.0.0.1 and port 1234.

You can modify the port number if needed by updating the script.

Start the Client

To start the client, execute the client.py script. By default, it will connect to the server at 127.0.0.1 and port 1234.

```bash
python management_client.py
```

The client will connect to the server and begin interacting based on the logic inside the client code (e.g., sending monitoring tasks).

---

## Service Tasks

The following service tasks are available for monitoring:

1. **Ping**: Performs a ping request to a specified server.
2. **HTTP**: Performs an HTTP request to a specified URL and checks the server's response.
3. **HTTPS**: Performs an HTTPS request to a specified URL and checks the server's response.
4. **DNS**: Performs a DNS query to a given DNS server for different record types (`A`, `MX`, `AAAA`, `CNAME`).
5. **NTP**: Checks the time from an NTP server.
6. **TCP**: Checks the status of a TCP port on a server.
7. **UDP**: Checks the status of a UDP port on a server.

## Service Control

The client can control the following service operations:

- **Start Service**: Start a new service on the server (Ping, HTTP, HTTPS, DNS, etc.).
- **Pause Service**: Pause all currently running services.
- **Resume Service**: Resume all paused services.
- **Shutdown Server**: Stop all active services and shut down the server.

---
