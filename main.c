#include <stdio.h>
#include <stdlib.h> /* exit & defines */
#include <unistd.h> /* fork */
#include <stdint.h>
#include <errno.h>
#include <string.h> /* strerror */

#include <pcap.h>

/* pf header stuff */
#include <net/if.h>
#include <net/if_pflog.h>

/* IP header */
#include <netinet/in_systm.h> /* how is THIS required? */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

/* TCP header */
#include <netinet/tcp.h>

/* utility */
#include <arpa/inet.h>

#include <syslog.h>

/* string lookups */
#include "str.h"

#define PROGNAME "pfloggerd"
#define VERSION "1.0"
#define LOGDEVICE "pflog0"
#define LOGDEVMAX 10

char errbuf[PCAP_ERRBUF_SIZE];

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

void usage()
{
	printf("Packet filter to syslog bridge, v%s\n\nUsage: %s [-h] [-i <logdevice>]\n", VERSION, PROGNAME);
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	pcap_t *ldev;
	pid_t child;

	extern char *optarg;
	extern int optind;
	int ch, iflag=0;
	char lflag[LOGDEVMAX];

	while ((ch=getopt(argc, argv, "hi:")) != -1) {
		switch (ch) {
			case 'i':
				iflag=1;
				strncpy(lflag, optarg, LOGDEVMAX);
				break;
			case 'h':
				usage();
				break;
		}
	}

	if (!iflag)
		strncpy(lflag, LOGDEVICE, LOGDEVMAX);

	argc-=optind;
	argv+=optind;

	/* open pflog device */

	if ((ldev=pcap_open_live(LOGDEVICE, 160, 1, 1, (char *)&errbuf))==NULL) {
		fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
		return 1;
	}

	switch ((child=fork())) {
		case 0:
			break;
		case -1:
			fprintf(stderr, "fork(): %s\n", strerror(errno));
			return 1;
		default:
			return 0;
	}

	pcap_loop(ldev, -1, packet_handler, NULL); 

	pcap_close(ldev);

	return 0;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	struct pfloghdr		*pf;
	struct ip		*ip;
	struct ip6_hdr		*ip6;
	struct tcphdr		*tcp; /* or udp, since the ports are the same */
	char			ip_src[INET6_ADDRSTRLEN];
	char			ip_dst[INET6_ADDRSTRLEN];
	u_int8_t		proto;
	u_int16_t		port_src, port_dst;

	u_int8_t		dir;
	u_int8_t		action;
	u_int8_t		reason;
	u_int8_t		flags=0;

	pf=(struct pfloghdr *)bytes;

	action=pf->action;
	reason=pf->reason;
	dir=pf->dir;

	/* skip pf header */
	bytes+=PFLOG_HDRLEN;
	ip=(struct ip *)bytes;

	if (ip->ip_v == 4) {
		inet_ntop(AF_INET, &ip->ip_src, ip_src, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip->ip_dst, ip_dst, INET6_ADDRSTRLEN);

		proto=ip->ip_p;

		bytes+=(ip->ip_hl*4);	/* skip ip header */
	} else if (ip->ip_v == 6) {
		ip6=(struct ip6_hdr *)bytes;
		inet_ntop(AF_INET6, &ip6->ip6_src, ip_src, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &ip6->ip6_dst, ip_dst, INET6_ADDRSTRLEN);

		proto=ip6->ip6_nxt;

		bytes+=40;		/* skip ip header */
	} else {
		/* unknown IP version */
	}

	if (proto == 6) {		/* TCP */
		tcp=(struct tcphdr *)bytes;

		port_src=tcp->th_sport;
		port_dst=tcp->th_dport;

		flags=tcp->th_flags;
	} else if (proto == 17) {	/* UDP */
		tcp=(struct tcphdr *)bytes;

		port_src=tcp->th_sport;
		port_dst=tcp->th_dport;
	} else {
		/* unknown protocol */
	}

	/* action, reason, dir, ip_src, ip_dst, port_src, port_dst, proto */

	syslog(LOG_NOTICE, "%s %s:%d -> %s:%d %s %s %s (0x%x)\n",
		str_get(TABLE_PROTO, proto), ip_src, ntohs(port_src),
		ip_dst, ntohs(port_dst), str_get(TABLE_ACTION, action),
		str_get(TABLE_DIR, dir), str_get(TABLE_REASON, reason), flags);
}

