
# dos-tools

## Introduction

`dos-tools` is a powerful collection of tools designed for conducting Denial of Service (DoS) attacks in a legal and controlled penetration testing environment. The suite consists of three main utilities: `xi-tcp`, `xi-udp`, and `overload`. The name "xi" stands for "Xerxes Improved," paying homage to the original `xerxes.c` DoS tool that inspired this project.

These tools are intended for security professionals, researchers, and system administrators to evaluate the robustness and resilience of their networks and servers against various types of DoS attacks.

> **WARNING:** These tools should only be used in environments where you have explicit permission to perform penetration testing. Unauthorized use of these tools is illegal and unethical.

## Tools Overview

### 1. `xi-tcp`

`xi-tcp` is a TCP-based DoS attack tool designed to overwhelm a target server with a large number of TCP requests. The tool includes features such as IP spoofing to mask the true origin of the attack traffic, increasing its effectiveness.

### 2. `xi-udp`

`xi-udp` is a UDP-based DoS attack tool that sends a flood of UDP packets to the target server. Like `xi-tcp`, it supports IP spoofing to conceal the source of the attack, making it more challenging for the target to defend against.

### 3. `overload`

`overload` is a multi-vector DoS attack tool that combines several different types of attacks, including HTTP floods, TCP SYN floods, UDP floods, and Slowloris attacks. This tool is designed to apply sustained pressure on the target server by using multiple attack vectors simultaneously, making it particularly difficult to mitigate.

## Files Overview

- **xi-tcp.c**: The source code for the `xi-tcp` utility.
- **xi-udp.c**: The source code for the `xi-udp` utility.
- **overload.c**: The source code for the `overload` utility.
- **user_agents.txt**: A file containing a list of user agents to be used in HTTP-based attacks, enabling the tool to simulate a wide range of client types.
- **dns_servers.txt**: A file containing a list of DNS servers to be used in DNS amplification attacks, allowing for a distributed attack approach.
- **Makefile**: A makefile to compile the tools and install the necessary files.
- **README.md**: This document.

## Installation

### Prerequisites

Before compiling, ensure that you have the following installed on your system:

- GCC (GNU Compiler Collection)
- `libnet` library for IP spoofing capabilities
- `libpcap` library if needed for packet capturing

### Compilation

To compile the tools, run the following command in the directory where the files are located:

```
make
```

This will generate the following executables:

    xi-tcp
    xi-udp
    overload

### Installation

To install the binaries and necessary files, run:

```sh
sudo make install
```

This command will copy the executables to `/usr/local/bin/` and the configuration files (`user_agents.txt` and `dns_servers.txt`) to `/usr/share/dos-tools/`.

### Uninstallation

To uninstall the tools and remove all related files, run:

```sh
sudo make uninstall
```

## Usage Instructions

### xi-tcp

Usage:

```sh
xi-tcp <target_host> <target_port>
```

Example:

```sh
xi-tcp example.com 80
```

This command will start a TCP flood attack on the specified target.

### xi-udp

Usage:

```sh
xi-udp <target_host> <target_port>
```

Example:

```sh
xi-udp example.com 53
```

This command will start a UDP flood attack on the specified target.

### overload

Usage:

```sh
overload <target_ip>
```

Example:

```sh
overload 123.123.123.123
```

This command will start the specified type of attack on the target.

## Configuration Files

- **user_agents.txt**: This file contains a list of user agents that will be randomly used in HTTP-based attacks. You can customize this file by adding or removing user agents to better simulate different clients.
- **dns_servers.txt**: This file contains a list of DNS servers that will be used in DNS amplification attacks. Ensure this file is properly configured with valid DNS servers to maximize the attack's impact.

## Strategies for Using the Tools

These tools can be used individually or in combination to thoroughly test a target's defenses:

- **Combined Attack**: Using `overload` to launch multiple types of attacks simultaneously can overwhelm a target's mitigation strategies, making it more difficult to defend against.
- **Distributed Attack**: By using different source IPs (via IP spoofing) in `xi-tcp` and `xi-udp`, you can simulate a distributed attack, which can be harder for the target to mitigate due to the dispersed nature of the traffic.
- **Persistent Attack**: Running `overload` in a loop or with high thread counts can apply sustained pressure on the target, useful for stress testing the server's long-term resilience.

## Inspiration

This toolkit was inspired by the original `xerxes.c` DoS tool, which served as a foundational example of how to perform TCP-based denial of service attacks. `dos-tools` expands on this idea, adding modern features and additional attack vectors to create a comprehensive DoS testing toolkit.

Always remember to use these tools responsibly and within the bounds of the law.
