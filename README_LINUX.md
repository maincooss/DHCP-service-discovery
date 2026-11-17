# DHCP Service Discovery for Linux x86_64

`dhcp_linux.c` is the Linux x86_64 source. The existing `dhcp.cpp` remains the
Windows version and is not changed by the Linux port.

The Linux version preserves the Windows program's core behavior and displayed
DHCP fields:

- Enumerates network interfaces and scans active interfaces sequentially.
- Sends DHCP Discover packets in 2-second windows, repeating a window when it
  finds a new server.
- Displays server identity and DHCP offer parameters in adaptive-width tables.
- For each DHCP offer, removes that interface's ARP neighbor entry and sends
  six ARP probes, 100 ms apart. Captured reply source MAC addresses are used to
  distinguish servers sharing an IP address.
- Reads IEEE `(hex)` entries from `oui.txt` beside the executable. If missing,
  downloads the unmodified file from IEEE into that directory. It does not use
  a built-in OUI table.

## Build

On an x86_64 Linux system with GCC:

```sh
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -m64 dhcp_linux.c -o dhcp_linux
```

`curl` is needed only on the first run when `oui.txt` is not beside the
executable. The executable directory must be writable for that initial
download. Alternatively, place the unmodified IEEE `oui.txt` there before
running.

## Run

The scanner uses UDP port 68, binds sockets to individual interfaces, and
creates raw packet sockets for ARP. Run it as root:

```sh
sudo ./dhcp_linux
```

Root is also needed to remove ARP neighbor entries. Without the required
network capabilities, DHCP scanning or same-IP/different-MAC detection may be
unavailable. The program reports permission and socket errors rather than
silently claiming a complete scan.

Use a UTF-8 terminal locale for aligned Chinese table output.
