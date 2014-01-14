#include <stdio.h>
#include <stdlib.h> /* exit & defines */
#include <unistd.h> /* fork */
#include <stdint.h>
#include <errno.h>
#include <string.h> /* strerror */
#include <limits.h> /* _POSIX_PATH_MAX */

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
#define VERSION "1.3"
#define LOGDEFDEV "pflog0"
#define LOGDEVMAX 10

#define PID_PATH_MAX _POSIX_PATH_MAX
/* XXX this might not work everywhere */
#define PID_STR_MAX sizeof(pid_t)*8

short debug=0;

char errbuf[PCAP_ERRBUF_SIZE];

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

void usage()
{
	printf("Packet filter to syslog bridge, v%s\n\n"
		"Usage: %s [-dh] [-p <pidfile>] [-i <logdevice>]\n\n"
		"-d             debug (does not detach from console)\n"
		"-h             this help\n"
		"-p <pidfile>   use <pidfile> to store server pid\n"
		"-i <logdevice> read <logdevice> instead of %s\n",
		VERSION, PROGNAME, LOGDEFDEV);
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	pcap_t *ldev;
	pid_t child;

	extern char *optarg;
	extern int optind;
	int ch, iflag=0, pflag=0;
	char iarg[LOGDEVMAX];
	char parg[PID_PATH_MAX];

	char pidstr[PID_STR_MAX];
	FILE *pidfile;

	while ((ch=getopt(argc, argv, "dfhi:p:")) != -1) {
		switch (ch) {
			case 'd':
				debug=1;
				break;
			case 'p':
				pflag=1;
				strncpy(parg, optarg, PID_PATH_MAX);
				break;
			case 'i':
				iflag=1;
				strncpy(iarg, optarg, LOGDEVMAX);
				break;
			case 'h':
				usage();
				break;
		}
	}

	if (!iflag)
		strncpy(iarg, LOGDEFDEV, LOGDEVMAX);

	argc-=optind;
	argv+=optind;

	/* open pflog device */

	if ((ldev=pcap_open_live(iarg, 160, 1, 1000, (char *)&errbuf))==NULL) {
		fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
		return 1;
	}

	if (pflag) {
		if ((pidfile=fopen(parg, "w"))==NULL) {
			fprintf(stderr, "Can't open pidfile `%s'\n", parg);
			return -1;
		}
	}

	if (!debug) {
		switch ((child=fork())) {
			case 0:
				break;
			case -1:
				fprintf(stderr, "fork(): %s\n", strerror(errno));
				return 1;
			default:
				if (pflag) {
					sprintf(pidstr, "%d", child);

					if (fwrite(pidstr, strlen(pidstr), 1, pidfile)!=1) { /* rv:count */
						fclose(pidfile);
						return -1;
					}

					fclose(pidfile);
				}
				return 0;
		}
	}

	if (pcap_loop(ldev, -1, packet_handler, NULL) < 0) { 
		syslog(LOG_ALERT, "Error in main packet loop: %s", errbuf);
	}

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
	char			*flagstr=NULL;
	const char		*fstr;
	u_int16_t		fc;
	u_int8_t		fsize=0;

	if (debug) {
		fprintf(stderr, "In packet_handler()\n");
	}

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

		fc=1;
		do {
			if (tcp->th_flags & fc) {
				fstr=str_get(TABLE_TCPFLAGS, fc);
				fsize=strlen(fstr);
				if (flagstr == NULL) {
					flagstr=(char *)malloc(fsize+1);
					bzero(flagstr, fsize+1);
				} else {
					flagstr=(char *)realloc(flagstr, strlen(flagstr)+fsize+2);
					strncat(flagstr, "/", 1);
				}
				strncat(flagstr, fstr, fsize);
			}
			fc=fc<<1;
		} while (fc<=0x80);
		/* XXX tcp flags are unlikely to change */

	} else if (proto == 17) {	/* UDP */
		tcp=(struct tcphdr *)bytes;

		port_src=tcp->th_sport;
		port_dst=tcp->th_dport;
	} else {
		/* unknown protocol */
	}

	if (debug) {
		fprintf(stderr, "%s: %s%s%s %s:%d -> %s:%d %s %s %s\n",
			pf->ifname,
			str_get(TABLE_PROTO, proto),
			(proto == 6 ? " " : ""),
			(proto == 6 ? flagstr : ""),
			ip_src,
			ntohs(port_src),
			ip_dst,
			ntohs(port_dst), 
			str_get(TABLE_ACTION, action),
			str_get(TABLE_DIR, dir),
			str_get(TABLE_REASON, reason));
	}

	syslog(LOG_NOTICE, "%s: %s%s%s %s:%d -> %s:%d %s %s %s\n",
		pf->ifname,
		str_get(TABLE_PROTO, proto),
		(proto == 6 ? " " : ""),
		(proto == 6 ? flagstr : ""),
		ip_src,
		ntohs(port_src),
		ip_dst,
		ntohs(port_dst), 
		str_get(TABLE_ACTION, action),
		str_get(TABLE_DIR, dir),
		str_get(TABLE_REASON, reason));

	if (flagstr != NULL)
		free(flagstr);
}

