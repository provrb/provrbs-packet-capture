#include <stdio.h>
#include <npcap/pcap.h>

int main() {

    pcap_if_t* dev;
    char devErrBuff[PCAP_ERRBUF_SIZE];

    if ( pcap_findalldevs(&dev, &devErrBuff) != 0 ) {
        printf("There was an error finding all devices.\n");
        return -1;
    }

    pcap_if_t* tmp = dev->next;

    while ( tmp->next != NULL ) {
        printf(tmp->description);
        printf("\n");

        tmp = tmp->next;
    }

    return 0;
}
