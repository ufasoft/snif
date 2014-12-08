/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#pragma once

#if UCFG_WIN32
#	include <inaddr.h>
#endif

#if UCFG_COM
#	include <oleauto.h>
#endif
// MPPC Protocol  RFC 2118

#include <net/ppp_defs.h>

#ifndef PPP_VJC_COMP
#	define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#endif

#ifndef PPP_VJC_UNCOMP
#	define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#endif

#ifndef PPP_MP
#	define PPP_MP		0x3d
#endif



//!!!#include "packet.h"

#include "snifferstructs.h"
#if UCFG_SNIF_USE_ODDB
#	include <el/db/odutils.h>
#endif	

#include "vjc.h"
#include "sniffermsg.h"

namespace Snif {

const size_t MAX_PPP_PACKETSIZE = 8192;

//!!! must be generater from .mc

class SnifferPacket;
class Adapter; //!!!
class CWifiPacket;

#if !UCFG_LIB_DECLS
#	define AFX_PACKET_CLASS
#elif UCFG_SNIF_USE_PCAP
#	if defined(UCFG_EXPORT_SNIF) || defined(_PACKET32)
#		define AFX_PACKET_CLASS       AFX_CLASS_EXPORT
#	else
#		define AFX_PACKET_CLASS       AFX_CLASS_IMPORT
#	endif
#else
#	ifdef _PACKET32
#		define AFX_PACKET_CLASS       AFX_CLASS_EXPORT
#	else
#		pragma comment(lib, "packet.lib")
#		define AFX_PACKET_CLASS       AFX_CLASS_IMPORT
#	endif
#endif


typedef ptr<SnifferPacket, Interlocked> ILP_SnifferPacket; //!!!

#if UCFG_ADDITIONAL_HEAPS
extern AFX_PACKET_CLASS CHeap g_heapPacket;
#endif

class SnifferPacketBase : public Object {
public:
	virtual ~SnifferPacketBase() {}
	virtual Buf GetData() =0;
	virtual long GetProto() =0;
	virtual bool IsSnifferPacket() { return false; }
	virtual ILP_SnifferPacket GetRootPacket() { Throw(E_FAIL); }
	virtual String GetFrom() { return "From"; }
	virtual String GetTo() { return "To"; }


#if UCFG_ADDITIONAL_HEAPS
	void *operator new(size_t size) { return g_heapPacket.Alloc(size); }
	void operator delete(void *p) { return g_heapPacket.Free(p); }
#endif
};

/*!!!
struct CSnifPacket
{
DateTime TimeStamp;
DWORDLONG Order;
CPointer<Adapter> Adapter;
BYTE Medium;
BYTE Flags;
bool BadCrc;
size_t Size;
BYTE *Data;

CSnifPacket()
:	Flags(0),
Size(0),
BadCrc(false)
{}
};*/

#pragma pack(push,4)


class AFX_PACKET_CLASS SnifferPacket : public SnifferPacketBase {
	typedef SnifferPacket class_type;
public:
#if UCFG_SNIF_USE_ODDB
	COdObject m_ob;
#endif

	DateTime TimeStamp;
	UInt64 Order;
	CPointer<class Adapter> Adapter;
	byte Medium;
	byte Flags;
	const byte *Data;
	size_t Size;

	/*
	DateTime m_timestamp;
	DWORDLONG m_nOrder;
	BYTE m_medium;
	bool m_bBadCrc;
	BYTE m_flags;
	size_t m_len;
	*/
	//!!!	BYTE m_data[];

	void * __stdcall operator new(size_t size, int len);		// int instead of size_t to avoid error in GCC
	void __stdcall operator delete(void *p, int len) {
#if UCFG_ADDITIONAL_HEAPS
		 SnifferPacketBase::operator delete(p);
#else
		 ::operator delete(p);
#endif
	}

	void __stdcall operator delete(void *p) {
#if UCFG_ADDITIONAL_HEAPS
		 SnifferPacketBase::operator delete(p);
#else
		 ::operator delete(p);
#endif
	}

	SnifferPacket()
		:	Order(0)
		,	Medium(0)
		,	Flags(0)
		,	Data((BYTE*)(this+1))
	{}

#if !UCFG_SNIF_USE_PCAP
	SnifferPacket(CBlockHeader *bh, UInt64 order = 0); //!!!, bool bOwner = false);
	//!!!  SnifferPacket(size_t size);
	//!!!  ~SnifferPacket();

	void FillHeader(CBlockHeader *bh);
#endif

	static ILP_SnifferPacket __stdcall FromSnifPacket(SnifferPacket& snifPacket);	
	Buf GetData() { return Buf((byte*)Data, Size); }

	//!!!  void TakeOwnership();

#if UCFG_COM
	static ptr<SnifferPacket, NonInterlocked> __stdcall Load(IDispatch *disp);
	void Save(IDispatch *disp);
#endif
#if UCFG_SNIF_USE_ODDB
	COdObject GetODObject() { return m_ob; }
#endif
	long GetProto() override;
	bool IsSnifferPacket() { return true; }

	bool get_BadCrc() { return Flags & BLOCK_FLAG_ERROR; }
	void put_BadCrc(bool b) { Flags = (Flags & ~BLOCK_FLAG_ERROR) | (b ? BLOCK_FLAG_ERROR : 0); }
	DEFPROP(bool, BadCrc);
};

#pragma pack(pop)

class CReadBitStream {
public:
	const BYTE *m_p;
	size_t m_len;
	ssize_t m_bits;
	BYTE m_byte;

	CReadBitStream(const BYTE *p, size_t len)
		:	m_bits(0)
		,	m_p(p)
		,	m_len(len)
	{}

	bool Eof();
	BYTE ReadBit();
	DWORD ReadBits(int count);

	void AdjustToOctet() {
		m_bits = 0;
	}
};

const size_t MPPC_BUF_SIZE = 8192;

class AFX_PACKET_CLASS CMPPC {
public:
	byte *m_p;
	DWORD m_count;
	byte m_buf[MPPC_BUF_SIZE];

	CMPPC()
		:	m_p(0)
		,	m_count(0)
	{}

	const BYTE *Unpack(const BYTE *p, ssize_t len, ssize_t& rlen);
private:
	void Put(byte v) {
		if (m_p >= m_buf+sizeof(m_buf))
			Throw(E_Sniffer_InvalidPPPFormat);
		*m_p++ = v;
	}

	void ReadTuple(CReadBitStream& stm, int bits, int add);
	void CopyTuple(int len, int offset);
};

class CMultiLink {
public:
	BYTE m_buf[MAX_PPP_PACKETSIZE];
	ssize_t m_nNext;
	DWORD m_seq;
	bool m_bShort;

	CMultiLink()
		:	m_seq(0)
		,	m_nNext(0)
		,	m_bShort(false)
	{}

	const BYTE *Process(const BYTE *p, size_t len, ssize_t& rlen);
};

class CPPPDecompressor : public Object {
public:
	byte m_buf[8192];
	CMPPC m_mppcSend,
		m_mppcRecv;
	byte m_destbuf[65536+PPP_HDRLEN];
	CVJDecompressor m_tcpSend,
		m_tcpRecv;
	CMultiLink m_multiLinkSend,
		m_multiLinkRecv;

#if !UCFG_SNIF_USE_PCAP
	ILP_SnifferPacket Unpack(CBlockHeader *bh, bool bOut);
private:
	ILP_SnifferPacket AddPppHeader(CBlockHeader *bh, WORD proto, ConstBuf mb);
#endif
};

class AFX_PACKET_CLASS CPppManager {
public:
	typedef map<DWORD, ptr<CPPPDecompressor> > CLinkMap;
	CLinkMap m_mapLink;

#if !UCFG_SNIF_USE_PCAP
	ILP_SnifferPacket	Process(CBlockHeader *bh, UInt64 nOrder);	
#endif
};

} // Snif::
