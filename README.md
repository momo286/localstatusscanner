# localstatusscanner
Inspired by:
https://github.com/doctorfree/MMM-MacAddressScan

Trying to do the same thing in Python and Flask

## C ARP watcher

`arp_watcher.c` listens for ARP packets on a network interface and prints
MAC addresses seen within the last five minutes. The output is enriched with
friendly names loaded from `mac_names.conf` if present.

### Build

```
gcc arp_watcher.c -lpcap -o arp_watcher
```

### Run

The program accepts an optional network interface name. If omitted, the default
interface discovered by `libpcap` is used.

```
./arp_watcher [interface]
```

Configure name lookups by adding entries to `mac_names.conf` using the format:

```
aa:bb:cc:dd:ee:ff Friendly Name
```
