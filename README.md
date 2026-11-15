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

Results are deduplicated by adapter, DHCP server IP, and resolved MAC address,
so different responders that share a server IP can be retained when their MAC
addresses can be distinguished. MAC resolution uses the Windows neighbor table
(`SendARP`) and is best-effort; routed/relayed servers or conflicting IP
addresses may not yield a unique MAC. Vendor names use a small built-in OUI
table as a fallback. The program loads standard `(hex)` entries from a
read-only `oui.txt`, searching the working directory, executable directory,
and executable parent directories; it never edits the database. DHCP
vendor-class and hostname options supplement the OUI match when present.

The scanner binds the DHCP client port (UDP 68), which may require elevated
permissions or conflict with the Windows DHCP client service. When building
in Visual Studio, use the `/utf-8` compiler option so UTF-8 source and console
text are handled consistently.
