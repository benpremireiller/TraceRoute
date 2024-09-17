# Traceroute

Ping and trace the route to networks!

## Description

This traceroute tool leverages low-level sockets and network requests to trace the path packets take from your machine to a target host. It provides a detailed breakdown of each hop in the network route, including the IP addresses and response times of intermediary routers. This program is a lightweight alternative to traditional traceroute utilities, written purely in Python for learning and customization.

## Features

- Ping a network using either an IP address or domain name.
- Trace the network route to an IP address.
- Display network statistics, including round-trip time (RTT) and packet loss.

## Requirements

- Python 3.x

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/TraceRoute.git

2. Navigate to the project directory:
   ```
   cd TraceRoute

## Usage

First, initialize the helper library using:

    icmpHelperPing = IcmpHelperLibrary()

Ping an IP address or domain using:
    
    IcmpHelperPing.sendPing("IP Address/domain")

Trace route to an IP address or domain using:

    IcmpHelperPing.traceRoute("IP Address/domain")


## Contact

Benjamin Premi-Reiller

Project Link: [https://github.com/benpremireiller/TraceRoute](https://github.com/benpremireiller/TraceRoute)
