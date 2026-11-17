# DHCP Service Discovery for macOS arm64

`dhcp_macos.c` is the native macOS source for Apple Silicon Macs. It is
separate from the existing Windows and Linux source files.

The macOS version retains the scanner's main behavior and output:

- Enumerates and prints network interfaces, then scans active interfaces
  sequentially.
- Sends DHCP Discover packets in repeated 15-second windows, continuing a
  window when it finds a new server. Interfaces with IPv4 use an interface-
  bound UDP socket; interfaces without IPv4 use raw BPF frames.
- Displays server identity and DHCP offer fields in adaptive-width tables.
- Uses the captured OFFER's Ethernet source MAC when available, checks the
  macOS ARP cache before clearing it, then sends six ARP probes, 100 ms apart.
  BPF captures ARP replies to find additional devices that share the server
  IP.
- Reads the unmodified IEEE `(hex)` entries from `oui.txt` beside the
  executable. If missing, it downloads the file from IEEE; there is no built-in
  OUI table.

## Build on an Apple Silicon Mac

Use the Xcode Command Line Tools' Clang:

```sh
clang -std=c11 -O2 -Wall -Wextra -Wpedantic -arch arm64 dhcp_macos.c -o dhcp_macos
```

The source uses macOS system APIs and requires no additional link libraries.
`curl` is needed only for the first run when `oui.txt` is absent, and the
executable's directory must be writable for that download.

## Run

The scanner binds UDP port 68 for interfaces with IPv4, and uses macOS BPF for
raw DHCP and ARP packets. It also removes ARP entries. Run it with
administrator privileges:

```sh
sudo ./dhcp_macos
```

Use a UTF-8 terminal locale for aligned Chinese table output.
The UDP port may already be held by the macOS DHCP client; if binding fails,
the program reports the interface and error.
