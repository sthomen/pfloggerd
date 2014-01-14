#ifndef _STR_H_
#define _STR_H_

#include <sys/types.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

struct string_tok {
	u_int16_t id;
	const char *string;
};

#ifdef _STR_C

struct string_tok string_dir[] = {
	{ PF_INOUT,	"in/out" },
	{ PF_IN,	"in" },
	{ PF_OUT,	"out" }
};

struct string_tok string_reason[] = {
	{ PFRES_MATCH, "match" }, 
	{ PFRES_BADOFF, "bad-offset" }, 
	{ PFRES_FRAG, "fragment" }, 
	{ PFRES_SHORT, "short" }, 
	{ PFRES_NORM, "normalize" }, 
	{ PFRES_MEMORY, "memory" }, 
	{ PFRES_TS, "bad-timestamp" }, 
	{ PFRES_CONGEST, "congestion" }, 
	{ PFRES_IPOPTIONS, "ip-option" },
	{ PFRES_PROTCKSUM, "proto-cksum" },
	{ PFRES_BADSTATE, "state-mismatch" }, 
	{ PFRES_STATEINS, "state-insert" }, 
	{ PFRES_MAXSTATES, "state-limit" }, 
	{ PFRES_SRCLIMIT, "src-limit" }, 
	{ PFRES_SYNPROXY, "synproxy" }
};

struct string_tok string_action[] = {
	{ PF_PASS,		"pass" },
	{ PF_DROP,		"drop" },
	{ PF_SCRUB,		"scrub" },
	{ PF_NOSCRUB,		"noscrub" },
	{ PF_NAT,		"NAT" },
	{ PF_NONAT,		"No NAT" },
	{ PF_BINAT,		"BINAT" },
	{ PF_NOBINAT,		"No BINAT" },
	{ PF_RDR,		"RDR" },
	{ PF_NORDR,		"No RDR" },
	{ PF_SYNPROXY_DROP,	"SYNproxy drop" }
};

struct string_tok string_proto[] = {
	{ IPPROTO_IP,		"IP" },
	{ IPPROTO_ICMP,		"ICMP" },
	{ IPPROTO_IGMP,		"IGMP" },
	{ IPPROTO_GGP,		"GGP" },
	{ IPPROTO_IPV4,		"IPv4" },
	{ IPPROTO_IPIP,		"IPIP" },
	{ IPPROTO_TCP,		"TCP" },
	{ IPPROTO_EGP,		"EGP" },
	{ IPPROTO_PUP,		"PUP" },
	{ IPPROTO_UDP,		"UDP" },
	{ IPPROTO_IDP,		"IDP" },
	{ IPPROTO_TP,		"TP" },
	{ IPPROTO_IPV6,		"IPv6" },
	{ IPPROTO_ROUTING,	"IP6 route header" },
	{ IPPROTO_FRAGMENT,	"IP6 fragment" },
	{ IPPROTO_RSVP,		"RSVP" },
	{ IPPROTO_GRE,		"GRE" },
	{ IPPROTO_ESP,		"ESP" },
	{ IPPROTO_AH,		"AH" },
	{ IPPROTO_MOBILE,	"IP Mobility" },
	{ IPPROTO_IPV6_ICMP,	"IPv6 ICMP" },
	{ IPPROTO_ICMPV6,	"ICMPv6" },
	{ IPPROTO_NONE,		"IP6 none" },
	{ IPPROTO_DSTOPTS,	"IP6 dstop" },
	{ IPPROTO_EON,		"EON" },
	{ IPPROTO_ETHERIP,	"ETHERIP" },
	{ IPPROTO_ENCAP,	"ENCAP" },
	{ IPPROTO_PIM,		"PIM" },
	{ IPPROTO_IPCOMP,	"IPComp" },
	{ IPPROTO_VRRP,		"VRRP" },
	{ IPPROTO_CARP,		"CARP" }
};

struct string_tok string_tcpflags[] = {
	{ TH_FIN, "FIN" },
	{ TH_SYN, "SYN" },
	{ TH_RST, "RST" },
	{ TH_PUSH, "PSH" },
	{ TH_ACK, "ACK" },
	{ TH_URG, "URG" },
	{ TH_ECE, "ECE" },
	{ TH_CWR, "CWR" }
};

#endif /* _STR_C */

#define STR_DIR_MAX 2
#define STR_REASON_MAX 15
#define STR_ACTION_MAX 10
#define STR_PROTO_MAX 30
#define STR_TCPFLAGS_MAX 7

const char *str_get(int table, int index);

#define TABLE_ACTION 0
#define TABLE_REASON 1
#define TABLE_PROTO 2
#define TABLE_DIR 3
#define TABLE_TCPFLAGS 4

#endif /* _STR_H_ */
