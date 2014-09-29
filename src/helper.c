/*
 * $Id$
 *
 * Copyright (C) 2002-2004 Fhg Fokus
 * Copyright (C) 2004-2005 Nils Ohlmeier
 *
 * This file belongs to sipsak, a free sip testing tool.
 *
 * sipsak is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * sipsak is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include "sipsak.h"

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#ifdef HAVE_UNISTD_H
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# include <unistd.h>
#endif
#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif
#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_RULI_H
# include <ruli.h>
#endif
#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif
#ifdef HAVE_CARES_H
# ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
# endif
# include <ares.h>
# ifndef NS_RRFIXEDSZ
#  define NS_RRFIXEDSZ 10
#  define NS_QFIXEDSZ  4
#  define NS_HFIXEDSZ  12
# endif
 int caport;
 unsigned long caadr;
 char *ca_tmpname;
 ares_channel channel;

#endif // HAVE_CARES_H

#define INT_DIGITS10 ((CHAR_BIT * sizeof(int) - 1) / 3 + 2)

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "helper.h"
#include "exit_code.h"

/* returns 1 if the string an IP address otherwise zero */
int is_ip(char *str) {
	int i = 0;
	int dotcount = 0;

	/*try understanding if this is a valid ip address
	we are skipping the values of the octets specified here.
	for instance, this code will allow 952.0.320.567 through*/
	while (*str != '\0')
	{
		for (i = 0; i < 3; i++, str++)
			if (isdigit((int)*str) == 0)
				break;
		if (*str != '.')
			break;
		str++;
		dotcount++;
	}

	/* three dots with upto three digits in before, between and after ? */
	if (*str == '\0' && dotcount == 3 && i > 0 && i <= 3)
		return 1;
	else
		return 0;
}

/* take either a dot.decimal string of ip address or a
domain name and returns a NETWORK ordered long int containing
the address. i chose to internally represent the address as long for speedier
comparisions.

any changes to getaddress have to be patched back to the net library.
contact: farhan@hotfoon.com

  returns zero if there is an error.
  this is convenient as 0 means 'this' host and the traffic of
  a badly behaving dns system remains inside (you send to 0.0.0.0)
*/

int getaddress(char *host, int rport, int transport, struct addrinfo *ret) {
	struct addrinfo *result;
	struct addrinfo *res;
	int error;

	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = transport == SIP_TCP_TRANSPORT ? SOCK_STREAM : SOCK_DGRAM
	};

	if (rport) {
		char strport[INT_DIGITS10];
		snprintf(strport, INT_DIGITS10, "%i", rport);
		error = getaddrinfo(host, strport, &hints, &result);
	} else {
		error = getaddrinfo(host, "sip", &hints, &result);
	}

	/* resolve the domain name into a list of addresses */
	if (error != 0) {
		if (error == EAI_SYSTEM) {
			perror("getaddrinfo");
		} else {
			fprintf(stderr, "error in getaddrinfo for %s: %s\n", host, gai_strerror(error));
		}
		return -1;
	}

	/* loop over all returned results and do inverse lookup */
	for (res = result; res != NULL; res = res->ai_next) {
		char hostname[NI_MAXHOST];

		error = getnameinfo(res->ai_addr, res->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, 0);
		if (error != 0) {
			fprintf(stderr, "error in getnameinfo: %s\n", gai_strerror(error));
			continue;
		} if (*hostname != '\0') {
			memset(ret, 0, sizeof(struct addrinfo));
			memcpy(ret, res, sizeof(struct addrinfo));

			ret->ai_addr = malloc(res->ai_addrlen);
			memcpy(ret->ai_addr, res->ai_addr, res->ai_addrlen);
			break;
		}
	}

	freeaddrinfo(result);
	return 0;
}

#ifdef HAVE_CARES_H
static const unsigned char *parse_rr(const unsigned char *aptr, const unsigned char *abuf, int alen) {
	char *name;
	long len;
	int status, type, dnsclass, dlen;
	struct in_addr addr;

	dbg("ca_tmpname: %s\n", ca_tmpname);
	status = ares_expand_name(aptr, abuf, alen, &name, &len);
	if (status != ARES_SUCCESS) {
		printf("error: failed to expand query name\n");
		exit_code(2, __PRETTY_FUNCTION__, "failed to expand query name");
	}
	aptr += len;
	if (aptr + NS_RRFIXEDSZ > abuf + alen) {
		printf("error: not enough data in DNS answer 1\n");
		free(name);
		return NULL;
	}
	type = DNS_RR_TYPE(aptr);
	dnsclass = DNS_RR_CLASS(aptr);
	dlen = DNS_RR_LEN(aptr);
	aptr += NS_RRFIXEDSZ;
	if (aptr + dlen > abuf + alen) {
		printf("error: not enough data in DNS answer 2\n");
		free(name);
		return NULL;
	}
	if (dnsclass != CARES_CLASS_C_IN) {
		printf("error: unsupported dnsclass (%i) in DNS answer\n", dnsclass);
		free(name);
		return NULL;
	}
	if ((ca_tmpname == NULL && type != CARES_TYPE_SRV) ||
		(ca_tmpname != NULL &&
		 	(type != CARES_TYPE_A && type != CARES_TYPE_CNAME))) {
		printf("error: unsupported DNS response type (%i)\n", type);
		free(name);
		return NULL;
	}
	if (type == CARES_TYPE_SRV) {
		free(name);
		caport = DNS__16BIT(aptr + 4);
		dbg("caport: %i\n", caport);
		status = ares_expand_name(aptr + 6, abuf, alen, &name, &len);
		if (status != ARES_SUCCESS) {
			printf("error: failed to expand SRV name\n");
			return NULL;
		}
		dbg("SRV name: %s\n", name);
		if (is_ip(name)) {
			caadr = inet_addr(name);
			free(name);
		}
		else {
			ca_tmpname = name;
		}
	}
	else if (type == CARES_TYPE_CNAME) {
		if ((ca_tmpname != NULL) &&
				(STRNCASECMP(ca_tmpname, name, strlen(ca_tmpname)) == 0)) {
			ca_tmpname = malloc(strlen(name));
			if (ca_tmpname == NULL) {
				printf("error: failed to allocate memory\n");
				exit_code(2, __PRETTY_FUNCTION__, "memory allocation failure");
			}
			strcpy(ca_tmpname, name);
			free(name);
		}
		else {
			free(name);
			status = ares_expand_name(aptr, abuf, alen, &name, &len);
			if (status != ARES_SUCCESS) {
				printf("error: failed to expand CNAME\n");
				return NULL;
			}
			dbg("CNAME: %s\n", name);
			if (is_ip(name)) {
				caadr = inet_addr(name);
				free(name);
			}
			else {
				ca_tmpname = name;
			}
		}
	}
	else if (type == CARES_TYPE_A) {
		if (dlen == 4 && STRNCASECMP(ca_tmpname, name, strlen(ca_tmpname)) == 0) {
			memcpy(&addr, aptr, sizeof(struct in_addr));
			caadr = addr.s_addr;
		}
		free(name);
	}
	return aptr + dlen;
}

static const unsigned char *skip_rr(const unsigned char *aptr, const unsigned char *abuf, int alen) {
	int status, dlen;
	long len;
	char *name;

	dbg("skipping rr section...\n");
	status = ares_expand_name(aptr, abuf, alen, &name, &len);
	aptr += len;
	dlen = DNS_RR_LEN(aptr);
	aptr += NS_RRFIXEDSZ;
	aptr += dlen;
	free(name);
	return aptr;
}

static const unsigned char *skip_query(const unsigned char *aptr, const unsigned char *abuf, int alen) {
	int status;
	long len;
	char *name;

	dbg("skipping query section...\n");
	status = ares_expand_name(aptr, abuf, alen, &name, &len);
	aptr += len;
	aptr += NS_QFIXEDSZ;
	free(name);
	return aptr;
}

static void cares_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
	int i;
	unsigned int ancount, nscount, arcount;
	const unsigned char *aptr;

	dbg("cares_callback: status=%i, alen=%i\n", status, alen);
	if (status != ARES_SUCCESS) {
		if (verbose > 1)
			printf("ares failed: %s\n", ares_strerror(status));
		return;
	}

	ancount = DNS_HEADER_ANCOUNT(abuf);
	nscount = DNS_HEADER_NSCOUNT(abuf);
	arcount = DNS_HEADER_ARCOUNT(abuf);

	dbg("ancount: %i, nscount: %i, arcount: %i\n", ancount, nscount, arcount);

	/* safety check */
	if (alen < NS_HFIXEDSZ)
		return;
	aptr = abuf + NS_HFIXEDSZ;

	aptr = skip_query(aptr, abuf, alen);

	for (i = 0; i < ancount && caadr == 0; i++) {
		if (ca_tmpname == NULL)
			aptr = parse_rr(aptr, abuf, alen);
		else
			aptr = skip_rr(aptr, abuf, alen);
	}
	if (caadr == 0 && aptr != NULL) {
		for (i = 0; i < nscount; i++) {
			aptr = skip_rr(aptr, abuf, alen);
		}
		for (i = 0; i < arcount && caadr == 0; i++) {
			aptr = parse_rr(aptr, abuf, alen);
		}
	}
}

static int srv_ares(char *host, char *srv, int proto, struct addrinfo *res) {
	int nfds, count, srvh_len;
	char *srvh;
	fd_set read_fds, write_fds;
	struct timeval *tvp, tv;
	int ret = -1;

	caport = 0;
	ca_tmpname = NULL;
	dbg("starting ARES query\n");

	srvh_len = strlen(host) + strlen(srv) + 2;
	srvh = malloc(srvh_len);
	if (srvh == NULL) {
		printf("error: failed to allocate memory (%i) for ares query\n", srvh_len);
		exit_code(2, __PRETTY_FUNCTION__, "memory allocation failure");
	}
	memset(srvh, 0, srvh_len);
	strncpy(srvh, srv, strlen(srv));
	memcpy(srvh + strlen(srv), ".", 1);
	strcpy(srvh + strlen(srv) + 1, host);
	dbg("hostname: '%s', len: %i\n", srvh, srvh_len);

	ares_query(channel, srvh, CARES_CLASS_C_IN, CARES_TYPE_SRV, cares_callback, (char *) NULL);
	dbg("ares_query finished, waiting for result...\n");
	/* wait for query to complete */
	while (1) {
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		nfds = ares_fds(channel, &read_fds, &write_fds);
		if (nfds == 0)
			break;
		tvp = ares_timeout(channel, NULL, &tv);
		count = select(nfds, &read_fds, &write_fds, NULL, tvp);
		if (count < 0 && errno != EINVAL) {
			perror("ares select");
			exit_code(2, __PRETTY_FUNCTION__, "ares DNS resolution failure");
		}
		ares_process(channel, &read_fds, &write_fds);
	}
	dbg("ARES answer processed\n");
	if (caadr == 0 && ca_tmpname != NULL) {
		ret = getaddress(ca_tmpname, caport, proto, res);
	}
	if (ca_tmpname != NULL)
		free(ca_tmpname);
	free(srvh);
	return ret;
}
#endif // HAVE_CARES_H

#ifdef HAVE_RULI_H
inline unsigned long srv_ruli(char *host, int *port, char *srv) {
	int srv_code;
	int ruli_opts = RULI_RES_OPT_SEARCH | RULI_RES_OPT_SRV_NOINET6 | RULI_RES_OPT_SRV_NOSORT6 | RULI_RES_OPT_SRV_NOFALL;
#ifdef RULI_RES_OPT_SRV_CNAME
	ruli_opts |= RULI_RES_OPT_SRV_CNAME;
#endif

	ruli_sync_t *sync_query = ruli_sync_query(srv, host, *port, ruli_opts);

	/* sync query failure? */
	if (!sync_query) {
		printf("DNS SRV lookup failed for: %s\n", host);
		exit_code(2, __PRETTY_FUNCTION__, "DNS SRV lookup failed");
	}

	srv_code = ruli_sync_srv_code(sync_query);
	/* timeout? */
	if (srv_code == RULI_SRV_CODE_ALARM) {
		printf("Timeout during DNS SRV lookup for: %s\n", host);
		ruli_sync_delete(sync_query);
		exit_code(2, __PRETTY_FUNCTION__, "timeout during DNS SRV lookup");
	}
	/* service provided? */
	else if (srv_code == RULI_SRV_CODE_UNAVAILABLE) {
		printf("SRV service not provided for: %s\n", host);
		ruli_sync_delete(sync_query);
		exit_code(2, __PRETTY_FUNCTION__, "missing service in DNS SRV reply");
	}
	else if (srv_code) {
		int rcode = ruli_sync_rcode(sync_query);
		if (verbose > 1)
			printf("SRV query failed for: %s, srv_code=%d, rcode=%d\n", host, srv_code, rcode);
		ruli_sync_delete(sync_query);
		return 0;
	}

	ruli_list_t *srv_list = ruli_sync_srv_list(sync_query);

	int srv_list_size = ruli_list_size(srv_list);

	if (srv_list_size < 1) {
		if (verbose > 1)
			printf("No SRV record: %s.%s\n", srv, host);
		return 0;
	}

	ruli_srv_entry_t *entry = (ruli_srv_entry_t *) ruli_list_get(srv_list, 0);
	ruli_list_t *addr_list = &entry->addr_list;
	int addr_list_size = ruli_list_size(addr_list);

	if (addr_list_size < 1) {
		printf("missing addresses in SRV lookup for: %s\n", host);
		ruli_sync_delete(sync_query);
		exit_code(2, __PRETTY_FUNCTION__, "missing address in DNS SRV reply");
	}

	*port = entry->port;
	ruli_addr_t *addr = (ruli_addr_t *) ruli_list_get(addr_list, 0);
	return addr->addr.ipv4.s_addr;
}
#endif // HAVE_RULI_H

int getsrvaddress(char *host, int *port, char *srv, int proto, struct addrinfo *res) {
#ifdef HAVE_RULI_H
	/* return srv_ruli(host, port, srv, res); */
	return 0;
#else
# ifdef HAVE_CARES_H // HAVE_RULI_H
	return srv_ares(host, srv, proto, res);
# else // HAVE_CARES_H
	return 0;
# endif
#endif
}

/* Finds the SRV records for the given host. It returns the target IP
 * address and fills the port and transport if a suitable SRV record
 * exists. Otherwise it returns 0. The function follows 3263: first
 * TLS, then TCP and finally UDP. */
int getsrvadr(char *host, struct addrinfo *res) {
	int ret = -1;

#ifdef HAVE_SVR

#ifdef HAVE_CARES_H
	int status;
	int optmask = ARES_OPT_FLAGS;
	struct ares_options options;

	options.flags = ARES_FLAG_NOCHECKRESP;
	options.servers = NULL;
	options.nservers = 0;

	status = ares_init_options(&channel, &options, optmask);
	if (status != ARES_SUCCESS) {
		printf("error: failed to initialize ares\n");
		exit_code(2, __PRETTY_FUNCTION__, "failed to init ares lib");
	}
#endif

#ifdef WITH_TLS_TRANSP
	printf("TLS transport not yet supported\n");
	exit_code(2);
#endif
	ret = getsrvaddress(host, service, SRV_SIP_TCP, SIP_TCP_TRANSPORT, res);
	if (ret >= 0) {
		if (verbose > 1)
			printf("using SRV record: %s.%s:%i\n", SRV_SIP_TLS, host, srvport);
	}
	else {
		ret = getsrvaddress(host, service, SRV_SIP_UDP, SIP_UDP_TRANSPORT, res);
		if (ret >= 0) {
			if (verbose > 1)
				printf("using SRV record: %s.%s:%s\n", SRV_SIP_UDP, host, service);
		}
	}
#ifdef WITH_TLS_TRANSP
	}
#endif

#ifdef HAVE_CARES_H
	ares_destroy(channel);
#endif

#endif // HAVE_SRV

	return ret;
}

/* because the full qualified domain name is needed by many other
   functions it will be determined by this function.
*/
void get_fqdn(int family){
	char hname[100], dname[100], hlp[18];

	memset(&hname, 0, sizeof(hname));
	memset(&dname, 0, sizeof(dname));
	memset(&hlp, 0, sizeof(hlp));

	if (hostname) {
		strncpy(hname, hostname, 100);
	} else if (gethostname(hname, sizeof(hname)) < 0) {
		exit_code(2, __PRETTY_FUNCTION__, "failed to determine hostname");
	}

	struct addrinfo *res, *p;
	int error;

	struct addrinfo hints = {
		.ai_family = numeric ? family : AF_UNSPEC,
		.ai_flags  = AI_CANONNAME
	};

	error = getaddrinfo(hname, NULL, &hints, &res);
	if (error) {
		fprintf(stderr, "error: getaddrinfo failed: %s\n", gai_strerror(error));
		exit_code(2, __PRETTY_FUNCTION__, "failed to get addrinfo");
	}

	for (p = res; p != NULL; p = p->ai_next) {
		if (!numeric && p->ai_canonname) {
			strncpy(fqdn, p->ai_canonname, FQDN_SIZE);
			break;
		} else if (numeric) {
			size_t offset = 0;

			if (numeric && res->ai_family == AF_INET6) {
				fqdn[0] = '[';
				offset = 1;
			}

			error = getnameinfo(res->ai_addr, res->ai_addrlen,
								fqdn + offset, FQDN_SIZE, NULL, 0,
								numeric ? NI_NUMERICHOST : 0);
			if (error) {
				fprintf(stderr, "error: getnameinfo failed: %s\n", gai_strerror(error));
				exit_code(2, __PRETTY_FUNCTION__, "getnameinfo failed");
			}

			// fqdn is more than large enough to store the longest valid
			// ipv6 address
			if (numeric && res->ai_family == AF_INET6) {
				strcat(fqdn, "]");
			}
			break;
		}
	}

	if (res == NULL) {
		exit_code(2, __PRETTY_FUNCTION__, "cannot resolve local hostname");
	}

	freeaddrinfo(res);

	if (verbose > 2)
		printf("fqdnhostname: %s\n", fqdn);
}

/* this function searches for search in mess and replaces it with
   replacement */
void replace_string(char *mess, char *search, char *replacement) {
	char *backup, *insert;

	insert=STRCASESTR(mess, search);
	if (insert==NULL){
		if (verbose > 2)
			fprintf(stderr, "warning: could not find this '%s' replacement string in "
					"message\n", search);
	}
	else {
		while (insert){
			backup=str_alloc(strlen(insert)+1);
			strcpy(backup, insert+strlen(search));
			strcpy(insert, replacement);
			strcpy(insert+strlen(replacement), backup);
			free(backup);
			insert=STRCASESTR(mess, search);
		}
	}
}

/* checks if the strings contains special double marks and then
 * replace all occurences of this strings in the message */
void replace_strings(char *mes, char *strings) {
	char *pos, *atr, *val, *repl, *end;
	char sep;

	pos=atr=val=repl = NULL;
	dbg("replace_strings entered\nstrings: '%s'\n", strings);
	if ((isalnum(*strings) != 0) &&
		(isalnum(*(strings + strlen(strings) - 1)) != 0)) {
		replace_string(req, "$replace$", replace_str);
	}
	else {
		sep = *strings;
		dbg("sep: '%c'\n", sep);
		end = strings + strlen(strings);
		pos = strings + 1;
		while (pos < end) {
			atr = pos;
			pos = strchr(atr, sep);
			if (pos != NULL) {
				*pos = '\0';
				val = pos + 1;
				pos = strchr(val, sep);
				if (pos != NULL) {
					*pos = '\0';
					pos++;
				}
			}
			dbg("atr: '%s'\nval: '%s'\n", atr, val);
			if ((atr != NULL) && (val != NULL)) {
				repl = str_alloc(strlen(val) + 3);
				if (repl == NULL) {
					printf("failed to allocate memory\n");
					exit_code(2, __PRETTY_FUNCTION__, "memory allocation failure");
				}
				sprintf(repl, "$%s$", atr);
				replace_string(mes, repl, val);
				free(repl);
			}
			dbg("pos: '%s'\n", pos);
		}
	}
	dbg("mes:\n'%s'\n", mes);
}

/* insert \r in front of all \n if it is not present allready
 * and and a trailing \r\n is not present */
void insert_cr(char *mes) {
	char *lf, *pos, *backup;

	pos = mes;
	lf = strchr(pos, '\n');
	while ((lf != NULL) && (lf >= mes+1) && (*(--lf) != '\r')) {
		backup=str_alloc(strlen(lf)+2);
		strcpy(backup, lf+1);
		*(lf+1) = '\r';
		strcpy(lf+2, backup);
		free(backup);
		pos = lf+3;
		lf = strchr(pos, '\n');
	}
	lf = STRCASESTR(mes, "\r\n\r\n");
	if (lf == NULL) {
		lf = mes + strlen(mes);
		sprintf(lf, "\r\n");
	}
}

/* sipmly swappes the content of the two buffers */
void swap_buffers(char *fst, char *snd) {
	char *tmp;

	if (fst == snd)
		return;
	tmp = str_alloc(strlen(fst)+1);
	strcpy(tmp, fst);
	strcpy(fst, snd);
	strcpy(snd, tmp);
	free(tmp);
}

void swap_ptr(char **fst, char **snd) {
	char *tmp;

	tmp = *fst;
	*fst = *snd;
	*snd = tmp;
}

/* trashes one character in buff randomly */
void trash_random(char *message) {
	int r;
	float t;
	char *position;

	t=(float)rand()/RAND_MAX;
	r=(int)(t * (float)strlen(message));
	position=message+r;
	r=(int)(t*(float)255);
	*position=(char)r;
	if (verbose > 2)
		printf("request:\n%s\n", message);
}

/* this function is taken from traceroute-1.4_p12
   which is distributed under the GPL and it returns
   the difference between to timeval structs */
double deltaT(struct timeval *t1p, struct timeval *t2p) {
	register double dt;

	dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
			(double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
	return (dt);
}

/* returns one if the string contains only numbers otherwise zero */
int is_number(char *number) {
	int digit = 1;
	if (strlen(number) == 0) {
		return 0;
	}
	while (digit && (*number != '\0')) {
		digit = isdigit(*number);
		number++;
	}
	return digit ? 1 : 0;
}

/* tries to convert the given string into an integer. it strips
 * white-spaces and exits if an error happens */
int str_to_int(const char *num) {
	char *end;

	const char *start = num;
	while (*start && isspace(*start))
		start++;

	errno = 0;

	const long sl = strtol(start, &end, 10);

	if (errno) {
		fprintf(stderr, "error: %s: %s\n", strerror(errno), start);
	} else if (end == start) {
		errno = EINVAL;
		fprintf(stderr, "error: not a decimal number: %s\n", start);
	} else if (*end != '\0' && *end != ' ') {
		errno = EINVAL;
		fprintf(stderr, "error: extra characters at end of input: %s\n", start);
	} else if (sl > INT_MAX || sl < INT_MIN) {
		errno = ERANGE;
		fprintf(stderr, "error: value out of range of integer: %s\n", start);
	} else {
		return (int)sl;
	}

#ifndef RUNNING_CHECK
	/* libcheck expects a return value not an exit code */
	exit_code(2, __PRETTY_FUNCTION__, NULL);
#endif
	return 0;
}

/* reads into the given buffer from standard input until the EOF
 * character, LF character or the given size of the buffer is exceeded */
int read_stdin(char *buf, int size, int ret) {
	int i, j;

	for(i = 0; i < size - 1; i++) {
		j = getchar();
		if (((ret == 0) && (j == EOF)) ||
			((ret == 1) && (j == '\n'))) {
			*(buf + i) = '\0';
			return i;
		}
		else {
			*(buf + i) = j;
		}
	}
	*(buf + i) = '\0';
	if (verbose)
		fprintf(stderr, "warning: readin buffer size exceeded\n");
	return i;
}

/* tries to allocate the given size of memory and sets it all to zero.
 * if the allocation fails it exits */
void *str_alloc(size_t size) {
	char *ptr;
#ifdef HAVE_CALLOC
	ptr = calloc(1, size);
#else
	ptr = malloc(size);
#endif
	if (ptr == NULL) {
		fprintf(stderr, "error: memory allocation failed\n");
		exit_code(255, __PRETTY_FUNCTION__, "memory allocation failure");
	}
#ifndef HAVE_CALLOC
	memset(ptr, 0, size);
#endif
	return ptr;
}

void dbg(char* format, ...) {
#ifdef DEBUG
	va_list ap;

	fprintf(stderr, "DEBUG: ");
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	fflush(stderr);
	va_end(ap);
#endif
}
