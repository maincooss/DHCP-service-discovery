# DHCP-service-discovery

Discovers DHCP servers on active IPv4 network adapters on Windows. The program
prints every adapter at startup, scans active adapters sequentially, and gives
each adapter repeated 2-second scan windows while new servers are being
found. It reports the DHCP offer's server identifier, assigned address, subnet
mask, gateway, DNS servers, lease, and response time. Tables are printed after
scanning and sized to their contents, with server identity and DHCP parameters
shown separately to reduce terminal line wrapping. DHCP table headers use
distinct console colors, with the discovery-number header colored consistently
in both tables.

Results are deduplicated by adapter, DHCP server IP, and resolved MAC address.
For each DHCP offer, the scanner deletes that server IP's ARP neighbor entry
on the active adapter and repeats `SendARP` six times with 100 ms spacing,
allowing multiple devices advertising the same server IP to be recorded when
their MAC addresses respond during the probes. ARP cache deletion may require
running as Administrator; probe races mean a competing MAC can still be
missed. Vendor names come only from standard `(hex)` entries in `oui.txt`.
The program looks for this file beside the executable and, if it is missing,
downloads it from `https://standards-oui.ieee.org/oui/oui.txt` into that same
directory. There is no built-in OUI table. If the download or parsing fails,
vendors display as unknown; DHCP vendor-class and hostname options are still
shown when present. Put the executable in a writable directory with internet
access on the first run, or place the unmodified `oui.txt` beside it.

The scanner binds the DHCP client port (UDP 68), which may require elevated
permissions or conflict with the Windows DHCP client service. Administrator
privileges also improve ARP cache deletion. When building in Visual Studio,
use the `/utf-8` compiler option so UTF-8 source and console text are handled
consistently.
