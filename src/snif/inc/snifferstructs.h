/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#pragma once

#include <manufacturer.h>

#ifdef WIN32
#	include <u-config.h>
#	include <winioctl.h>

#	define NDIS_STATUS_ADAPTER_NOT_FOUND 0xC0010006L //!!!
#	define NDIS_STATUS_ADAPTER_NOT_OPEN  0xC0010012L  //!!!

#elif defined(_WIN32)
#	include <devioctl.h>
#endif	

#ifdef _MSC_VER
#	pragma warning(disable : 4200)
#endif

#include "params.h"

#ifndef _SNIF_DRIVER_NAME
#	define _SNIF_DRIVER_NAME  "UfasoftSnifDriver4"  //!!!V Must be changed for every version
#endif	

#ifndef _SNIF_DRIVER_NAME6
#	define _SNIF_DRIVER_NAME6  "UfasoftSnifDriver6"  //!!!V Must be changed for every version
#endif	

#ifndef L_SNIF_DRIVER_NAME
#	define L_SNIF_DRIVER_NAME  L"UfasoftSnifDriver4"  //!!!V Must be changed for every version
#endif	

#ifndef L_SNIF_DRIVER_NAME6
#	define L_SNIF_DRIVER_NAME6  L"UfasoftSnifDriver6"  //!!!V Must be changed for every version
#endif	

#ifndef UCFG_SNIF_FILTER_INF
#	define UCFG_SNIF_FILTER_INF  "snif-filter.inf"
#endif	

#ifndef UCFG_SNIF_FILTER_NAME
#	define UCFG_SNIF_FILTER_NAME  "ufasoft_filter"
#endif	

#ifndef L_SNIF_DRIVER_USER_NAME
#	define L_SNIF_DRIVER_USER_NAME  L"Ufasoft Snif Driver v4"
#endif	

#ifndef L_SNIF_DRIVER_USER_NAME6
#	define L_SNIF_DRIVER_USER_NAME6  L"Ufasoft Snif Driver v6"
#endif	

#ifndef SNIF_DRIVERFILE_NAME
#	define SNIF_DRIVERFILE_NAME "usft_sn4"
#endif	

#ifndef SNIF_DRIVERFILE_NAME6
#	define SNIF_DRIVERFILE_NAME6 "usft_sn6"
#endif	

#ifndef UCFG_SNIF_USE_NDIS6
#	define UCFG_SNIF_USE_NDIS6 1
#endif

#ifndef UCFG_SNIF_USE_PCAP
#	define UCFG_SNIF_USE_PCAP UCFG_USE_POSIX
#endif

#ifndef UCFG_SNIF_PROTECT_WPCAP_CLOSEALL
#	define UCFG_SNIF_PROTECT_WPCAP_CLOSEALL 0
#endif

#ifndef UCFG_SNIF_FILTER
#	define UCFG_SNIF_FILTER 1
#endif

#ifndef UCFG_SNIF_HOSTDB
#	define UCFG_SNIF_HOSTDB (!UCFG_USE_POSIX)
#endif

#ifndef UCFG_SNIF_ARPSPOOF
#	define UCFG_SNIF_ARPSPOOF (!UCFG_USE_POSIX)
#endif

#ifndef UCFG_SNIF_ARPSPOOF_IPC
#	define UCFG_SNIF_ARPSPOOF_IPC 0
#endif

#ifndef UCFG_SNIF_LOG
#	define UCFG_SNIF_LOG (!UCFG_USE_POSIX)
#endif

#ifndef UCFG_SNIF_WIFI
#	define UCFG_SNIF_WIFI (!UCFG_SNIF_USE_PCAP)
#endif

#ifndef UCFG_SNIF_SUBSTITUTE_ENUM
#	define UCFG_SNIF_SUBSTITUTE_ENUM 1
#endif

#ifndef UCFG_SNIF_REMOTE
#	define UCFG_SNIF_REMOTE (!UCFG_SNIF_USE_PCAP)
#endif

#ifndef UCFG_SNIF_CUI
#	define UCFG_SNIF_CUI 1
#endif

#ifndef UCFG_SNIF_PACKET_CAPTURE
#	define UCFG_SNIF_PACKET_CAPTURE 1
#endif

#ifndef UCFG_SNIF_USE_DB
#	ifdef HAVE_SQLITE3
#		define UCFG_SNIF_USE_DB 1
#	else
#		define UCFG_SNIF_USE_DB 0
#	endif
#endif

#ifndef UCFG_SNIF_USE_OLEDB
#	define UCFG_SNIF_USE_OLEDB (UCFG_SNIF_USE_DB && !UCFG_USE_POSIX)
#endif

#ifndef UCFG_SNIF_USE_ODDB
#	define UCFG_SNIF_USE_ODDB (!UCFG_USE_POSIX)
#endif

#ifndef UCFG_SNIF_USE_WND
#	define UCFG_SNIF_USE_WND UCFG_WIN32
#endif

#ifndef UCFG_SNIF_IPV6
#	define UCFG_SNIF_IPV6 1
#endif

#ifndef UCFG_SNIF_HOST_RESOLVE
#	define UCFG_SNIF_HOST_RESOLVE UCFG_WIN32
#endif

#ifndef UCFG_SNIF_PROMISC_MODE
#	define UCFG_SNIF_PROMISC_MODE 1
#endif

#ifndef UCFG_SNIF_USE_TOR
#	define UCFG_SNIF_USE_TOR UCFG_WIN32
#endif

#ifndef UCFG_SNIF_FIX_OFFLOAD
#	define UCFG_SNIF_FIX_OFFLOAD 1
#endif


#pragma pack(push,1)

#include "sniffermsg.h"


struct CPacketOidData {
	ULONG Oid;
	ULONG Length;
	UCHAR Data[];
};

struct CQueueHeader {
	volatile UINT32  m_beg,
		m_end;
	UINT32 m_reserv;
	//!!!       m_maxLen;
	Int32 m_nOverflow;
	//!!!	int m_reserv[3];
};

const UCHAR BLOCK_FLAG_SKIP = 4,
					 BLOCK_FLAG_ERROR = 8,
					 BLOCK_FLAG_OUT = 0x10,
           BLOCK_FLAG_ORIGINAL = 0x20,
           BLOCK_FLAG_WAN  = 0x40,
           BLOCK_FLAG_NEXT = 0x80;

const size_t BLOCK_ALIGN_MASK = 0xFFFFFFF0;
//!!!const BLOCK_ALIGN_MASK = 0xFFFFFFFF;

struct CBlockHeader {
	Int64 m_timeStamp;
	//!!!  ULONG m_nOrder;
	byte m_medium,
		m_nDevice,
		m_nLink,
		m_flags;
	UInt32 m_len;
	byte m_data[];

	//!!!void *operator new(size_t size, size_t len);
};

#pragma pack(pop)

inline size_t CalculateAlignedSize(size_t len) {
	return (len+sizeof(CBlockHeader)+sizeof(CBlockHeader)-1) & BLOCK_ALIGN_MASK;
}

#ifdef _WIN32

#define FILE_DEVICE_PROTOCOL        0x8000 //!! low bits are important! must be zero

const int WRITE_BIT_DEFER = 0x4000;

#define SNIF_CODE(code,method) ULONG(CTL_CODE(FILE_DEVICE_PROTOCOL,code,method,FILE_ANY_ACCESS))

const ULONG IOCTL_PROTOCOL_QUERY_OID	= SNIF_CODE(0, METHOD_BUFFERED),
			IOCTL_PROTOCOL_SET_OID		= SNIF_CODE(1, METHOD_BUFFERED),
            IOCTL_PROTOCOL_STATISTICS = SNIF_CODE(2, METHOD_BUFFERED),
            IOCTL_PROTOCOL_RESET			= SNIF_CODE(3, METHOD_BUFFERED),
            IOCTL_PROTOCOL_READ       = SNIF_CODE(4, METHOD_OUT_DIRECT),
            IOCTL_PROTOCOL_WRITE      = SNIF_CODE(5, METHOD_BUFFERED),
            IOCTL_PROTOCOL_MACNAME    = SNIF_CODE(6, METHOD_BUFFERED),
            IOCTL_PROTOCOL_BIND       = SNIF_CODE(7, METHOD_BUFFERED),
            IOCTL_PROTOCOL_UNBIND     = SNIF_CODE(8, METHOD_BUFFERED),
            IOCTL_OPEN                = SNIF_CODE(7, METHOD_BUFFERED),
            IOCTL_CLOSE               = SNIF_CODE(8, METHOD_BUFFERED),
            IOCTL_ENUM_ADAPTERS       = SNIF_CODE(9, METHOD_BUFFERED),
            IOCTL_PROTOCOL_BIND_WAN   = SNIF_CODE(10, METHOD_BUFFERED),
            IOCTL_PROTOCOL_SET_BUFFER = SNIF_CODE(11, METHOD_OUT_DIRECT),
//!!!     IOCTL_PROTOCOL_SET_BUFFER_XP = SNIF_CODE(12,METHOD_OUT_DIRECT),
            IOCTL_PROTOCOL_WRITE_PACKETS = SNIF_CODE(13, METHOD_BUFFERED),
						IOCTL_SNIF_SET_NOTIFY_EVENT = SNIF_CODE(14, METHOD_BUFFERED),
						IOCTL_SNIF_SET_NOTIFY_IRP   = SNIF_CODE(15, METHOD_BUFFERED),
						IOCTL_SNIF_GET_VERSION		= SNIF_CODE(16, METHOD_BUFFERED), //!!! == IOCTL_DRV_GET_VERSION
						IOCTL_SNIF_SET_SEND_BUFFER= SNIF_CODE(17, METHOD_OUT_DIRECT),
						IOCTL_SNIF_PACKET_SENT		= SNIF_CODE(18, METHOD_BUFFERED),
						IOCTL_SNIF_WAIT_SEND		  = SNIF_CODE(19, METHOD_BUFFERED),
						IOCTL_SNIF_GET_STATS		  = SNIF_CODE(20, METHOD_BUFFERED),
						IOCTL_SNIF_SET_RECV_BUFFER	= SNIF_CODE(21, METHOD_OUT_DIRECT),

						IOCTL_SNIF_GET_ADAPTER_COUNT		= SNIF_CODE(60, METHOD_BUFFERED),	// must be > than numbers in IOCTL_COMMON_...
						IOCTL_SNIF_GET_ADAPTER_NAME			= SNIF_CODE(61, METHOD_BUFFERED),
						IOCTL_SNIF_GET_ADAPTER_PHY_TYPES	= SNIF_CODE(62, METHOD_BUFFERED),
						IOCTL_SNIF_GET_ADAPTER_MEDIUM		= SNIF_CODE(63, METHOD_BUFFERED);

#endif // WIN32

struct SSnifStats {
	UInt64 m_dropped;
};

const size_t ETHERNET_HEADER_LENGTH  = 14,
						 ETHERNET_DATA_LENGTH   = 1500,
						 ETHERNET_PACKET_LENGTH = ETHERNET_HEADER_LENGTH+ETHERNET_DATA_LENGTH;


const int SNIF_DRIVER_VERSION_LAST = 0x04040000,
			    SNIF_DRIVER_VERSION_WITH_NOTIFY_IRP = 0x04040000;

enum EImpqResult {
	IMPQ_PUSHED,
	IMPQ_FIRST,
	IMPQ_NEED_SPACE
};

class CInterModePacketQueue {
public:
	volatile UInt32 m_r, m_q, m_w;
	volatile Int32 m_count;

	static const size_t FLAG_FREE = 0x40000000;

	CInterModePacketQueue()
		:	m_r(sizeof(CInterModePacketQueue))
		,	m_q(m_r)
		,	m_w(m_r)
		,	m_count(0)
	{}

	UCHAR *GetP(size_t off) {
		return (UCHAR*)this+off;
	}

	size_t GetFreeLen(size_t size) {
		size_t w = m_w,
			     r = m_r;
		size_t toEnd = 0;
		if (w >= r) {
			if (w+sizeof(UInt32)+sizeof(UInt32) <= size)
				toEnd = size-m_w-sizeof(UInt32)-sizeof(UInt32);
			w = sizeof(CInterModePacketQueue);
		}
		size_t fromBegin = 0;
		if (r >= w+sizeof(UInt32)+1)
			fromBegin = r-w-sizeof(UInt32)-1;
		return std::max(toEnd,fromBegin);
	}

	bool HasSpace(size_t len, size_t size) {
		size_t asize = len+sizeof(UInt32);
		size_t w = m_w,
			     r = m_r; // because m_r is volatile
		if (w >= r) {
			if (w+asize+sizeof(UInt32) > size)
				w = sizeof(CInterModePacketQueue);
			else
				return true;
		}
		return w+asize < r;
	}

	void *BeginPush(size_t len, size_t size) {
		size_t asize = sizeof(UInt32)+len;
		size_t w = m_w,
					 r = m_r; // because m_r is volatile
		if (w >= r) {
			if (w+asize+sizeof(UInt32) > size) {
				*(UInt32*)GetP(w) = (UInt32)-1;
				w = sizeof(CInterModePacketQueue);
			} else
				goto LAB_FOUND;
		}
		if (w+asize >= r)
			return 0;
LAB_FOUND:
		UCHAR *pw = GetP(w);
		*(UInt32*)pw = len;
		return pw+sizeof(UInt32);
	}

	EImpqResult EndPush(void *pw) {
		size_t w = (UCHAR*)pw-(UCHAR*)this;
		m_w = w+*((UInt32*)pw-1);
		return Interlocked::Increment(m_count)==1 ? IMPQ_FIRST : IMPQ_PUSHED;
	}

	EImpqResult Push(const void *p, size_t len, size_t size) {
		void *d = BeginPush(len, size);
		if (!d)
			return IMPQ_NEED_SPACE;
		return EndPush(memcpy(d, p, len));
	}

	bool empty() {
		return m_q == m_w;
	}

	const void *GetNext(UInt32& len) {
		while (m_q != m_w) {
			UCHAR *pr = GetP(m_q);
			if ((len=*(UInt32*)pr) == (UInt32)-1)
				m_q = sizeof(CInterModePacketQueue);
			else {
				m_q += sizeof(UInt32)+len;
				return pr+sizeof(UInt32);
			}
		}
		return 0;
	}

	void Putback(UInt32 len) {
		m_q -= sizeof(UInt32)+len;
	}

	void FreeBlock(const void *block) {
		if (*(size_t*)GetP(m_r) == (size_t)-1)
			m_r = sizeof(CInterModePacketQueue);
		size_t off = (UCHAR*)block-(UCHAR*)this-sizeof(UInt32);
		*(UInt32*)GetP(off) |= FLAG_FREE;
		if (off == m_r) {
			while (m_r != m_q) {
				UInt32 len = *(UInt32*)GetP(m_r);
				if (len == (UInt32)-1)
					m_r = sizeof(CInterModePacketQueue);
				else if (len & FLAG_FREE)
					m_r += sizeof(UInt32)+(len & ~FLAG_FREE);
				else
					break;
			}
		}
		Interlocked::Decrement(m_count);
	}
};


#if UCFG_SNIF_WIFI
#	include <ieee802_11.h>

#	pragma push_macro("_KERNEL")
#	undef _KERNEL
#	include <net80211/ieee80211_radiotap.h>
#	pragma pop_macro("_KERNEL")

#	include <windot11.h>

class CRadioTapHeader : public ieee80211_radiotap_header {
	typedef ieee80211_radiotap_header base;

public:
	UInt64 m_tsft;
	byte m_flags, m_rate;
	UInt16 m_channel, m_chFlags;
	signed char m_dbmSignal, m_dbmNoise;
	byte m_antenna, m_dbSignal, m_dbNoise;

	CRadioTapHeader() {
		ZeroStruct(*this);
	}

	CRadioTapHeader(const ieee80211_radiotap_header& hdr) {
		ZeroStruct(*this);
		(base&)*this = hdr;
		CMemReadStream stm(ConstBuf(&hdr+1, hdr.it_len-sizeof(hdr)));
		BinaryReader rd(stm);
		if (it_present & (1<<IEEE80211_RADIOTAP_TSFT))
			rd >> m_tsft;
		if (it_present & (1<<IEEE80211_RADIOTAP_FLAGS))
			rd >> m_flags;
		if (it_present & (1<<IEEE80211_RADIOTAP_RATE))
			rd >> m_rate;
		if (it_present & (1<<IEEE80211_RADIOTAP_CHANNEL)) {
			if (stm.Position & 1)
				rd.ReadByte();
			rd >> m_channel >> m_chFlags;
		}
		if (it_present & (1<<IEEE80211_RADIOTAP_DBM_ANTSIGNAL))
			rd >> m_dbmSignal;
		if (it_present & (1<<IEEE80211_RADIOTAP_DBM_ANTNOISE))
			rd >> m_dbmNoise;
		if (it_present & (1 << IEEE80211_RADIOTAP_ANTENNA))
			rd >> m_antenna;
		if (it_present & (1<<IEEE80211_RADIOTAP_DB_ANTSIGNAL))
			rd >> m_dbSignal;
		if (it_present & (1<<IEEE80211_RADIOTAP_DB_ANTNOISE))
			rd >> m_dbNoise;
	}

	void SetTsft(UInt64 v) {
		m_tsft = v;
		it_present |= 1<<IEEE80211_RADIOTAP_TSFT;
	}

	void SetFlags(byte v) {
		m_flags = v;
		it_present |= 1<<IEEE80211_RADIOTAP_FLAGS;
	}

	void SetRate(byte v) {		// 500kb/s
		m_rate = v;
		it_present |= 1<<IEEE80211_RADIOTAP_RATE;
	}

	static UInt16 ToChannelFlags(DOT11_PHY_TYPE phyType) {
		switch (phyType)
		{
		case dot11_phy_type_fhss: 	return IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_GFSK;
		case dot11_phy_type_dsss: 	return IEEE80211_CHAN_2GHZ;
		case dot11_phy_type_ofdm: 	return IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM;
		case dot11_phy_type_hrdsss: return IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_CCK;
		case dot11_phy_type_erp: 	return IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM;

		default:
			return 0;
		}
	}

	void SetChannel(UInt16 v) {
		m_channel = v;
		it_present |= 1<<IEEE80211_RADIOTAP_CHANNEL;
	}

	void SetChannel(UInt16 freq, DOT11_PHY_TYPE phyType) {
		m_channel = freq;
		m_chFlags = ToChannelFlags(phyType);
		it_present |= 1<<IEEE80211_RADIOTAP_CHANNEL;
	}

	void SetRssi(signed char v) {
		m_dbmSignal = v;
		it_present |= 1<<IEEE80211_RADIOTAP_DBM_ANTSIGNAL;
	}

	void SetAntennta(byte v) {
		m_antenna = v;
		it_present |= 1<<IEEE80211_RADIOTAP_ANTENNA;
	}

	void SetAntNoise(byte v) {
		m_dbNoise = v;
		it_present |= 1<<IEEE80211_RADIOTAP_DB_ANTNOISE;
	}

	size_t CalcLen() {
		size_t r = sizeof(ieee80211_radiotap_header);
		if (it_present & (1<<IEEE80211_RADIOTAP_TSFT))
			r += sizeof(UInt64);
		if (it_present & (1<<IEEE80211_RADIOTAP_FLAGS))
			r += 1;
		if (it_present & (1<<IEEE80211_RADIOTAP_RATE))
			r += 1;
		if (it_present & (1<<IEEE80211_RADIOTAP_CHANNEL)) {
			if (r & 1)
				r += 1;
			r += 2*sizeof(UInt16);
		}
		if (it_present & (1<<IEEE80211_RADIOTAP_DBM_ANTSIGNAL))
			r += 1;
		if (it_present & (1<<IEEE80211_RADIOTAP_DBM_ANTNOISE))
			r += 1;
		if (it_present & (1<<IEEE80211_RADIOTAP_ANTENNA))
			r += 1;
		if (it_present & (1<<IEEE80211_RADIOTAP_DB_ANTSIGNAL))
			r += 1;
		if (it_present & (1<<IEEE80211_RADIOTAP_DB_ANTNOISE))
			r += 1;
		it_len = (UInt16)r;
		return r;
	}

	void WriteTo(byte *p) {
		if (!it_len)
			CalcLen();
		*(ieee80211_radiotap_header*)p = *this;
		int i = sizeof(ieee80211_radiotap_header);
		if (it_present & (1<<IEEE80211_RADIOTAP_TSFT)) {
			*(UInt64*)(p+i) = m_tsft;
			i += sizeof(UInt64);
		}
		if (it_present & (1<<IEEE80211_RADIOTAP_FLAGS))
			*(p + i++) = m_flags;
		if (it_present & (1<<IEEE80211_RADIOTAP_RATE))
			*(p + i++) = m_rate;
		if (it_present & (1<<IEEE80211_RADIOTAP_CHANNEL)) {
			if (i & 1)
				*(p+ i++) =  0;
			*(UInt16*)(p + i) = m_channel;
			i += 2;
			*(UInt16*)(p + i) = m_chFlags;
			i += 2;
		}
		if (it_present & (1<<IEEE80211_RADIOTAP_DBM_ANTSIGNAL))
			*(p + i++) = m_dbmSignal;
		if (it_present & (1<<IEEE80211_RADIOTAP_DBM_ANTNOISE))
			*(p + i++) = m_dbmNoise;
		if (it_present & (1<<IEEE80211_RADIOTAP_ANTENNA))
			*(p + i++) = m_antenna;
		if (it_present & (1<<IEEE80211_RADIOTAP_DB_ANTSIGNAL))
			*(p + i++) = m_dbSignal;
		if (it_present & (1<<IEEE80211_RADIOTAP_DB_ANTNOISE))
			*(p + i++) = m_dbNoise;
	}
};


inline size_t CalcWifiHeaderLen(UInt16 fc) {
	size_t r = MGMT_HDRLEN;
	switch (FC_TYPE(fc))
	{
	case T_CTRL:
		switch (FC_SUBTYPE(fc))
		{
		case CTRL_PS_POLL:
			return CTRL_PS_POLL_HDRLEN;
		case CTRL_RTS:
			return CTRL_RTS_HDRLEN;
		case CTRL_CTS:
			return CTRL_CTS_HDRLEN;
		case CTRL_ACK:
			return CTRL_ACK_HDRLEN;
		case CTRL_CF_END:
			return CTRL_END_HDRLEN;
		case CTRL_END_ACK:
			return CTRL_END_ACK_HDRLEN;
		}
		break;
	case T_DATA:
		if (FC_TO_DS(fc) && FC_FROM_DS(fc))
			r += 6;
		if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
			r += sizeof(UInt16);
		break;
	}
	return r;
}



#endif // UCFG_SNIF_WIFI


