#include <strings.h>
#define _STR_C
#include "str.h"

const char *str_get(int table, int id)
{
	int i;

	switch (table) {
		case TABLE_ACTION:
			for (i=0;i<=STR_ACTION_MAX;i++)
				if (string_action[i].id == id)
					return string_action[i].string;
			break;
		case TABLE_REASON:
			for (i=0;i<=STR_REASON_MAX;i++)
				if (string_reason[i].id == id)
					return string_reason[i].string;
			break;
		case TABLE_PROTO:
			for (i=0;i<=STR_PROTO_MAX;i++)
				if (string_proto[i].id == id)
					return string_proto[i].string;
			break;
		case TABLE_DIR:
			for (i=0;i<=STR_DIR_MAX;i++)
				if (string_dir[i].id == id)
					return string_dir[i].string;
			break;
		case TABLE_TCPFLAGS:
			for (i=0;i<=STR_TCPFLAGS_MAX;i++)
				if (string_tcpflags[i].id == id)
					return string_tcpflags[i].string;
			break;
	}
	return "<string not found>";
}

