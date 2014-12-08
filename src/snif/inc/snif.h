/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#pragma once

#include "snifferstructs.h"

#ifdef _MSC_VER
#	define _REDEF_CALLING_CONV
#endif

#if UCFG_WIN32
#	include <winsock2.h>
#endif

#if !UCFG_SNIF_USE_PCAP

#	include <pcap.h>
#	if defined(_MSC_VER) && !defined(WPCAP) && !defined(_PACKET32)
#		pragma comment(lib, "wpcap")
#	endif

#else

#	ifndef WPCAP
#		ifdef UCFG_EXTENDED
#			pragma comment(lib, "/foreign/wpcap/lib/wpcap")
#		else
#			pragma comment(lib, "wpcap")
#		endif
#	endif

#	ifdef _REDEF_CALLING_CONV
#		define pcap_lookupdev		_cdecl pcap_lookupdev
#		define pcap_lookupnet		_cdecl pcap_lookupnet
#		define pcap_create			_cdecl pcap_create
#		define pcap_snaplen			_cdecl pcap_snaplen
#		define pcap_promisc			_cdecl pcap_promisc
#		define pcap_can_set_rfmon	_cdecl pcap_can_set_rfmon
#		define pcap_set_rfmon		_cdecl pcap_set_rfmon
#		define pcap_set_timeout		_cdecl pcap_set_timeout
#		define pcap_set_buffer_size	_cdecl pcap_set_buffer_size
#		define pcap_activate		_cdecl pcap_activate
#		define pcap_open_live		_cdecl pcap_open_live
#		define pcap_open_dead		_cdecl pcap_open_dead
#		define pcap_open_offline	_cdecl pcap_open_offline
//!!!#		define pcap_fopen_offline	_cdecl pcap_fopen_offline
#		define pcap_close			_cdecl pcap_close
#		define pcap_next			_cdecl pcap_next
#		define pcap_next_ex			_cdecl pcap_next_ex
#		define pcap_breakloop		_cdecl pcap_breakloop
#		define pcap_stats			_cdecl pcap_stats
#		define pcap_setfilter		_cdecl pcap_setfilter
#		define pcap_setdirection	_cdecl pcap_setdirection
#		define pcap_getnonblock		_cdecl pcap_getnonblock
#		define pcap_setnonblock		_cdecl pcap_setnonblock
#		define pcap_inject			_cdecl pcap_inject
#		define pcap_sendpacket		_cdecl pcap_sendpacket
#		define pcap_statustostr		_cdecl pcap_statustostr
#		define pcap_strerror		_cdecl pcap_strerror
#		define pcap_geterr			_cdecl pcap_geterr
#		define pcap_perror			_cdecl pcap_perror
#		define pcap_compile			_cdecl pcap_compile
#		define pcap_compile_nopcap	_cdecl pcap_compile_nopcap
#		define pcap_freecode		_cdecl pcap_freecode
#		define pcap_offline_filter	_cdecl pcap_offline_filter
#		define pcap_datalink		_cdecl pcap_datalink
#		define pcap_datalink_ext	_cdecl pcap_datalink_ext
#		define pcap_list_datalinks	_cdecl pcap_list_datalinks
#		define pcap_set_datalink	_cdecl pcap_set_datalink
#		define pcap_datalink_name_to_val		_cdecl pcap_datalink_name_to_val
#		define pcap_datalink_val_to_name		_cdecl pcap_datalink_val_to_name
#		define pcap_datalink_val_to_description	_cdecl pcap_datalink_val_to_description
#		define pcap_snapshot		_cdecl pcap_snapshot
#		define pcap_is_swapped		_cdecl pcap_is_swapped
#		define pcap_major_version	_cdecl pcap_major_version
#		define pcap_minor_version	_cdecl pcap_minor_version
#		define pcap_file			_cdecl pcap_file
#		define pcap_fileno			_cdecl pcap_fileno
#		define pcap_dump_open		_cdecl pcap_dump_open
#		define pcap_dump_fopen		_cdecl pcap_dump_fopen
#		define pcap_dump_file		_cdecl pcap_dump_file
#		define pcap_dump_ftell		_cdecl pcap_dump_ftell
#		define pcap_dump_flush		_cdecl pcap_dump_flush
#		define pcap_dump_close		_cdecl pcap_dump_close
#		define pcap_dump			_cdecl pcap_dump
#		define pcap_findalldevs		_cdecl pcap_findalldevs
#		define pcap_freealldevs		_cdecl pcap_freealldevs
#		define pcap_lib_version		_cdecl pcap_lib_version
#		define pcap_setbuff			_cdecl pcap_setbuff
#		define pcap_setmode			_cdecl pcap_setmode
#		define pcap_setmintocopy	_cdecl pcap_setmintocopy

#		define bpf_filter			__cdecl bpf_filter
#		define bpf_validate			_cdecl bpf_validate
#		define bpf_image			_cdecl bpf_image
#		define bpf_dump				_cdecl bpf_dump

		#define pcap_handler STDCALL_pcap_handler
		#define pcap_loop STDCALL_pcap_loop
		#define pcap_dispatch STDCALL_pcap_dispatch

#	endif

#	ifndef _MSC_VER
#		include <pcap.h>
#	endif
#	ifdef _MSC_VER
#		include <pcap/pcap.h>
#		include <pcap/pcap-int.h>
#	endif

#	ifdef _REDEF_CALLING_CONV
#		undef pcap_lookupdev
#		undef pcap_lookupnet
#		undef pcap_create
#		undef pcap_snaplen
#		undef pcap_promisc
#		undef pcap_can_set_rfmon
#		undef pcap_set_rfmon
#		undef pcap_set_timeout
#		undef pcap_set_buffer_size
#		undef pcap_activate
#		undef pcap_open_live		
#		undef pcap_open_dead		
#		undef pcap_open_offline	
//!!!#		undef pcap_fopen_offline	
#		undef pcap_close			
#		undef pcap_next			
#		undef pcap_next_ex			
#		undef pcap_breakloop		
#		undef pcap_stats			
#		undef pcap_setfilter		
#		undef pcap_setdirection	
#		undef pcap_getnonblock		
#		undef pcap_setnonblock		
#		undef pcap_inject			
#		undef pcap_sendpacket		
#		undef pcap_statustostr		
#		undef pcap_strerror		
#		undef pcap_geterr			
#		undef pcap_perror			
#		undef pcap_compile			
#		undef pcap_compile_nopcap	
#		undef pcap_freecode		
#		undef pcap_offline_filter	
#		undef pcap_datalink		
#		undef pcap_datalink_ext	
#		undef pcap_list_datalinks	
#		undef pcap_set_datalink	
#		undef pcap_datalink_name_to_val		
#		undef pcap_datalink_val_to_name		
#		undef pcap_datalink_val_to_description	
#		undef pcap_snapshot		
#		undef pcap_is_swapped		
#		undef pcap_major_version	
#		undef pcap_minor_version	
#		undef pcap_file			
#		undef pcap_fileno			
#		undef pcap_dump_open		
#		undef pcap_dump_fopen		
#		undef pcap_dump_file		
#		undef pcap_dump_ftell		
#		undef pcap_dump_flush		
#		undef pcap_dump_close		
#		undef pcap_dump			
#		undef pcap_findalldevs		
#		undef pcap_freealldevs		
#		undef pcap_lib_version		
#		undef pcap_setbuff			
#		undef pcap_setmode			
#		undef pcap_setmintocopy	

#		undef bpf_filter			
#		undef bpf_validate			
#		undef bpf_image			
#		undef bpf_dump				

#		undef pcap_handler
#		undef pcap_loop
#		undef pcap_dispatch

		typedef void (__cdecl * pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);
		extern "C" int	__cdecl pcap_loop(pcap_t *, int, pcap_handler, u_char *);
		extern "C" int	__cdecl pcap_dispatch(pcap_t *, int, pcap_handler, u_char *);
		
#	endif
#endif


#ifdef _MSC_VER
#	if UCFG_LIB_DECLS
#		ifdef UCFG_EXPORT_SNIF
			#define AFX_SNIF_CLASS       AFX_CLASS_EXPORT
#		else
			#if !defined(_PACKET32) && !defined(WPCAP)
				#define AFX_SNIF_CLASS       AFX_CLASS_IMPORT
				#pragma comment(lib, "snif")
			#else
				#define AFX_SNIF_CLASS
			#endif
		#endif
#	else
#		define AFX_SNIF_CLASS
#	endif
#else
#	define AFX_SNIF_CLASS
#endif

extern int g_Cflag;
extern pcap_t g_pd;
extern struct dump_info dumpinfo;

AFX_SNIF_CLASS DECLSPEC_NORETURN __inline void __stdcall PcapThrow(const char *errbuf) {
	TRC(0, errbuf);

	throw Exc(E_Sniffer_WPCap, errbuf);
}


void __cdecl Wpcap_dump_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);
void __cdecl Wpcap_dump_packet_and_trunc(u_char *user, const struct pcap_pkthdr *h, const u_char *sp);



extern "C" {
extern pcap_handler g_callback;
extern u_char *pcap_userdata;


#define INET
#undef SLIST_ENTRY

#ifndef __FreeBSD__
#	define _KERNEL 1
#endif

#include <net/if.h>
#include <net/if_arp.h>
#ifdef WIN32
#	include <net/ethertypes.h>
#	include <net/if_media.h>
#endif

#include <netinet/if_ether.h>

#include <netdb.h>

#ifndef ETHERTYPE_IPX
#	define	ETHERTYPE_IPX		0x8137	/* Novell (old) NetWare IPX (ECONFIG E option) */
#endif

#ifndef ETHERTYPE_PPP
#	define	ETHERTYPE_PPP		0x880B	/* PPP (obsolete by PPPOE) */
#endif

#ifndef ETHERTYPE_PPPOES
#	define ETHERTYPE_PPPOES	0x8864
#endif

#ifndef IPPROTO_IPV4
#	define IPPROTO_IPV4		4
#endif

#ifndef IPPROTO_ETHERIP
#	define IPPROTO_ETHERIP 97
#endif


#if UCFG_SNIF_WIFI
//!!!R #	include <ieee802_11_radio.h>
#	include <ieee802_11.h>
#	ifdef _WIN32
#		include <net80211/ieee80211_var.h>
#	endif
#endif

}

