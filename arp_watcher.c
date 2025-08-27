#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define MAX_DEVICES 1024
#define MAC_ADDRSTRLEN 18
#define NAME_LEN 128
#define TIME_WINDOW 300

struct device {
    char mac[MAC_ADDRSTRLEN];
    time_t last_seen;
};

struct name_entry {
    char mac[MAC_ADDRSTRLEN];
    char name[NAME_LEN];
};

static struct device devices[MAX_DEVICES];
static int device_count = 0;

static struct name_entry names[MAX_DEVICES];
static int name_count = 0;

static void load_names(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("fopen");
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || strlen(line) < 17)
            continue;
        char mac[MAC_ADDRSTRLEN];
        char name[NAME_LEN];
        if (sscanf(line, "%17s %127[^\n]", mac, name) == 2) {
            name[strcspn(name, "\r\n")] = '\0';
            strncpy(names[name_count].mac, mac, MAC_ADDRSTRLEN);
            strncpy(names[name_count].name, name, NAME_LEN);
            name_count++;
            if (name_count >= MAX_DEVICES)
                break;
        }
    }
    fclose(f);
}

static const char *lookup_name(const char *mac) {
    for (int i = 0; i < name_count; i++) {
        if (strcasecmp(names[i].mac, mac) == 0)
            return names[i].name;
    }
    return NULL;
}

static void prune_devices() {
    time_t now = time(NULL);
    int j = 0;
    for (int i = 0; i < device_count; i++) {
        if (now - devices[i].last_seen <= TIME_WINDOW) {
            devices[j++] = devices[i];
        }
    }
    device_count = j;
}

static void print_devices() {
    time_t now = time(NULL);
    printf("Devices seen in last 5 minutes:\n");
    for (int i = 0; i < device_count; i++) {
        if (now - devices[i].last_seen <= TIME_WINDOW) {
            const char *name = lookup_name(devices[i].mac);
            if (name)
                printf("%s (%s)\n", devices[i].mac, name);
            else
                printf("%s\n", devices[i].mac);
        }
    }
    printf("\n");
}

static void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    (void)header;
    const struct ether_header *eth_header = (const struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_ARP)
        return;
    const struct ether_arp *arp_packet = (const struct ether_arp *)(packet + sizeof(struct ether_header));

    char mac[MAC_ADDRSTRLEN];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp_packet->arp_sha[0], arp_packet->arp_sha[1], arp_packet->arp_sha[2],
             arp_packet->arp_sha[3], arp_packet->arp_sha[4], arp_packet->arp_sha[5]);

    time_t now = time(NULL);
    int found = 0;
    for (int i = 0; i < device_count; i++) {
        if (strcasecmp(devices[i].mac, mac) == 0) {
            devices[i].last_seen = now;
            found = 1;
            break;
        }
    }
    if (!found && device_count < MAX_DEVICES) {
        strncpy(devices[device_count].mac, mac, MAC_ADDRSTRLEN);
        devices[device_count].last_seen = now;
        device_count++;
    }
    prune_devices();
    print_devices();
}

int main(int argc, char *argv[]) {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (argc > 1)
        dev = argv[1];
    else
        dev = pcap_lookupdev(errbuf);
    if (!dev) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    load_names("mac_names.conf");

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "arp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    printf("Listening on %s for ARP packets...\n", dev);
    pcap_loop(handle, -1, handle_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}

