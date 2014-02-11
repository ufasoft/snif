/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#pragma once

#define MSC_VER _MSC_VER

#ifndef NTDDI_XPSP1
	#define NTDDI_XPSP1                      0x05010100
#endif

#define TRACE_ENTER(x)
#define TRACE_EXIT(x)
#define TRACE_PRINT(s)
#define TRACE_PRINT1(s, a)
#define TRACE_PRINT2(s, a, b)
#define TRACE_PRINT6(s, a, b, c, d, e, f)

#if defined(_WIN32) && !defined(WIN32) && !defined(NDIS_WDM) //!!!
	#define WIN32
#endif


#include <el/libext.h>
#ifdef __cplusplus
	using namespace Ext;
#endif


#ifdef WIN32

#	define SNIF_CONVERT_CODEPAGE 0

//!!!	#include <unistd.h>

#	define INET6 1

#	define TCPDUMP_DO_SMB

#	if defined(_KERNEL) && _KERNEL!=3
#		undef _KERNEL //!!!
#	endif

	#if !defined(DEBUG)
		#define DEBUG 0
	#endif


	#define lint

	#pragma comment(lib, "ws2_32.lib")

#ifdef _WIN32
#	include <crtdbg.h> // We need <*.h> here because interference between defines: EXT_DATA & extern
#	include <winsock2.h>
#	include <io.h>

	#ifndef __cplusplus
		#pragma warning(disable: 4057) // identifier1 ' indirection to slightly different base types from ' identifier2 ' 
		#pragma warning(disable: 4127) // conditional expression is constant
		#pragma warning(disable: 4132) // const object should be initialized
		#pragma warning(disable: 4242) // conversion from ' type ' to ' type ', possible loss of data
		#pragma warning(disable: 4245) // conversion from ' type1 ' to ' type2 ', signed/unsigned mismatch 
		#pragma warning(disable: 4267) // conversion from 'size_t' to 'int', possible loss of data
		#pragma warning(disable: 4311) // 'type cast' : pointer truncation from 'HANDLE' to 'DWORD'
		#pragma warning(disable: 4312) // 'type cast' : conversion from 'u_int32_t' to 'const u_char *' of greater size
		#pragma warning(disable: 4333) // right shift by too large amount, data loss
		#pragma warning(disable: 4389) // 'operator' : signed/unsigned mismatch
		#pragma warning(disable: 4701) // Potentially uninitialized local variable ' name ' used

		#pragma warning(disable : 4005 4013 4018 4047 4101 4133 4146 4715 4244)
	#endif


#endif
	#include <errno.h>
	#include <fcntl.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <time.h>
	#include <sys/stat.h>



	__BEGIN_DECLS
		#include <rpc/rpc.h>
		#ifdef _WIN32
		#	include <net/netdb.h>
		#endif
	__END_DECLS

	#if UCFG_EXTENDED
		#undef SLIST_ENTRY
		#include<net/if.h>
	#endif

	typedef unsigned int uint;

	#ifndef __cplusplus
		#define SUCCESS PROG_SUCCESS
	#endif

	//!!!#define _TIMEB_DEFINED

//!!!#	ifndef HAVE_STRUCT_TIMESPEC
//!!!#		define HAVE_STRUCT_TIMESPEC
//!!!#	endif

	#define HAVE_BPF_DUMP conflicts
	#define HAVE_PCAP_FINDALLDEVS
	#define HAVE_PCAP_BREAKLOOP
	#define HAVE_PCAP_VERSION
	#define HAVE_PCAP_DATALINK_NAME_TO_VAL
	#define HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION
	#define HAVE_PCAP_LIST_DATALINKS
	#define HAVE_PCAP_DUMP_FLUSH
	#define HAVE_REMOTE
	#define HAVE_PCAP_LIB_VERSION
	#define HAVE_PCAP_DUMP_FTELL

#	define HAVE_PF_NAT_THROUGH_PF_NORDR 0

	#define RETSIGTYPE void //!!!int

	#define HAVE_INET_NTOP
	#define HAVE_NETINET_IF_ETHER_H
	#define HAVE_NETINET_IP6_H
	#define HAVE_NET_PFVAR_H
	#define AIX_STRANGENESS
//	#define HAVE_NET_ETHERNET_H

//!!!R	#define HAVE_STDINT_H 0

	#ifdef _WIN32
	#	include "ip6_misc.h"
	#endif
//	#include <ip6.h>
	//!!!#include <icmp6.h>

//	#include <netinet/if_ether.h>

	#define MAXHOSTNAMELEN	64

	//!!!R #define IPPROTO_EGP 8		/* Exterior Gateway Protocol */

	#define yylval pcap_lval

	#define YY_NEVER_INTERACTIVE 1


	#define SIZEOF_CHAR 1
	#define SIZEOF_SHORT 2
	#define SIZEOF_INT 4

	#define inline __inline

/*!!!R
	#ifdef __cplusplus
		extern "C" 
	#endif
		__declspec(noreturn) void __cdecl ExitEx(int n);

	#define exit ExitEx
*/

	//!!!__inline void exit(int n) { ExitEx(0); }

	/*!!!
	#if !defined(PKTDUMP) && !defined(_PACKET32) && !defined(WPCAP) && !defined(TCPSLICE) 
		#define extern __declspec(dllimport)
		#include "interface.h"
	//	#undef extern
	#endif
	*/

	/*!!!
	#if !defined(_PACKET32) && !defined(WPCAP)
		#include "pktdump.h"
	#endif	
		*/

#	ifdef _MSC_VER
#		define	FSEEK	_fseeki64
#		define	FTELL	_ftelli64
#	endif

	#define HAVE_DECL_ETHER_NTOHOST 1

#endif

#ifdef _WIN32
#	include <ntddndis.h>
#	include <net/bpf.h>
#endif




