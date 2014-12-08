/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#pragma once

// Van Jacobson compression scheme, based on RFC 1144

typedef unsigned char u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int u_int32_t;
typedef short int16_t;

#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/tcp.h>

#ifdef _WIN32
//#	include <net/slcompress.h>
#else
//#	include <../tcpdump/slcompress.h>
#endif


// from slcompress.h
#define TYPE_IP 0x40
#define TYPE_UNCOMPRESSED_TCP 0x70
#define TYPE_COMPRESSED_TCP 0x80
#define TYPE_ERROR 0x00

/* Bits in first octet of compressed packet */
#define NEW_C	0x40	/* flag bits for what changed in a packet */
#define NEW_I	0x20
#define NEW_S	0x08
#define NEW_A	0x04
#define NEW_W	0x02
#define NEW_U	0x01

/* reserved, special-case values of above */
#define SPECIAL_I (NEW_S|NEW_W|NEW_U)		/* echoed interactive traffic */
#define SPECIAL_D (NEW_S|NEW_A|NEW_W|NEW_U)	/* unidirectional data */
#define SPECIALS_MASK (NEW_S|NEW_A|NEW_W|NEW_U)

#define TCP_PUSH_BIT 0x10





#define MAX_STATES 255   /* must be >2 and <255 */ //!!!
#define MAX_HDR 128     /* max TCP+IP hdr length (by protocol def) */


struct CCompState {
  WORD m_hlen;
  BYTE m_id;
  BYTE m_filler;
  bool m_bBeginned;
  union
  {
    ip m_ipHeader;
    BYTE m_hdr[MAX_HDR];
  };

  CCompState()
  {
    ZeroStruct(_self);
  }
};

class CVJDecompressor {
public:
  vector<CCompState> m_arState;
  BYTE m_lastRecv;
  BYTE m_flags;
  bool m_bToss;
  BYTE m_buf[65536];

  CVJDecompressor();
  ConstBuf Uncompress(int type, const byte *p, ssize_t len);
};



