/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>


#include "pppex.h"

namespace Snif {

bool CReadBitStream::Eof() {
	return !m_len;
}

BYTE CReadBitStream::ReadBit() {
	if (!m_bits) {
		if (!m_len)
			Throw(E_Sniffer_InvalidPPPFormat);
		else {
			m_byte = *m_p++;
			m_len--;
			m_bits = 8;
		}
	}
	m_bits--;
	BYTE r = (m_byte & 0x80) >> 7;
	m_byte <<= 1;
	return r;
}

DWORD CReadBitStream::ReadBits(int count) {
	DWORD r = 0;
	for (int i=0; i<count; i++)
		r = (r << 1) | ReadBit();
	return r;
}

void CMPPC::CopyTuple(int len, int offset) {
	int pos = DWORD((m_p-m_buf)+sizeof(m_buf)-offset) % sizeof(m_buf);

	if (pos+len > sizeof(m_buf) || m_p+len > m_buf+sizeof(m_buf))
		Throw(E_Sniffer_BadPacketFormat);
	memcpy(m_p, m_buf+pos, len);
	m_p += len;
}

void CMPPC::ReadTuple(CReadBitStream& stm, int bits, int add) {
	if (stm.Eof())
		return;
	int offset = add+stm.ReadBits(bits);
	for (int i=1; i<13; i++) {
		if (!stm.ReadBit()) {
			CopyTuple(i==1 ? 3 : (1 << i)+stm.ReadBits(i), offset);
			return;
		}
	}
	Throw(E_Sniffer_InvalidPPPFormat);
}

const BYTE *CMPPC::Unpack(const BYTE *p, ssize_t len, ssize_t& rlen) {
	CReadBitStream stm(p, len);
	BYTE flags = (BYTE)stm.ReadBits(4);
	DWORD count = stm.ReadBits(12);
	if (flags & 8) {
		ZeroStruct(m_buf);
		m_p = m_buf;
	} else {
		if (!m_p)
			return 0;
		if ((m_count+1)%4096 != count) {
			m_p = 0;
			return 0;
		}
	}
	m_count = count;
	if (flags & 4)
		m_p = m_buf;
	if (!m_p)
		return 0;
	BYTE *r = m_p;
	if (flags & 2) {
		while (!stm.Eof())
			if (stm.ReadBit())
				if (stm.ReadBit())
					if (stm.ReadBit())
						if (stm.ReadBit())
							ReadTuple(stm, 6, 0);
						else
							ReadTuple(stm, 8, 64);
					else
						ReadTuple(stm, 13, 320);
				else
					Put((BYTE)stm.ReadBits(7) | 0x80);
			else {
				if (!stm.m_len && stm.m_bits < 7)
					break;
				Put((BYTE)stm.ReadBits(7));
			}
	} else {
		if (m_p+len-2 > m_buf+MPPC_BUF_SIZE)
			Throw(E_Sniffer_BadPacketFormat);
		memcpy(m_p, p+2, len-2);
		m_p += len-2;
	}
	rlen = m_p-r;
	return r;
}

const BYTE *CMultiLink::Process(const BYTE *p, size_t len, ssize_t& rlen) {
	const BYTE *q;
	int seq = 0;
	if (m_bShort) {
		seq = ((p[0] & 0xF)<<8) | p[1];
		len -= 2;
		q = p+2;
	} else {
		seq = (p[1]<<16) | (p[2]<<8) | p[3];
		len -= 4;
		q = p+4;
	}
	m_seq = seq;
	if (*p & 0x80)
		m_nNext = 0;
	if (m_nNext+len > MAX_PPP_PACKETSIZE)
		Throw(E_Sniffer_InvalidPPPFormat);
	memcpy(m_buf+m_nNext, q, len);  
	rlen = m_nNext += len;
	return (*p & 0x40) ? m_buf : 0;
}


//!!!ofstream g_ofs1("c:\\3\\ppp1.bin", ios::binary);//!!!

#if !UCFG_SNIF_USE_PCAP

ILP_SnifferPacket CPPPDecompressor::AddPppHeader(CBlockHeader *bh, WORD proto, ConstBuf mb) {
	if (!mb.P)
		return nullptr;
	ILP_SnifferPacket sp = new(mb.Size+PPP_HDRLEN) SnifferPacket;
	sp->FillHeader(bh);
	sp->Flags &= ~BLOCK_FLAG_ORIGINAL;
	byte *data = (byte*)sp->Data;
	data[0] = 0xFF; // BSD's PPP_ADDRESS;
	data[1] = 3; // BSD's PPP_CONTROL;
	*(WORD*)(data+2) = htobe16(proto);
	memcpy(data+PPP_HDRLEN, mb.P, mb.Size);
	return sp;

	/*!!!
	CBlockHeader *nbh = new(mb.m_len+PPP_HDRLEN) CBlockHeader;
	*nbh = *bh;
	nbh->m_len = mb.m_len+PPP_HDRLEN;
	nbh->m_flags &= ~BLOCK_FLAG_ORIGINAL;
	nbh->m_data[0] = PPP_ADDRESS;
	nbh->m_data[1] = PPP_CONTROL;
	*(WORD*)(nbh->m_data+2) = htons(proto);
	memcpy(nbh->m_data+PPP_HDRLEN, mb.m_p, mb.m_len);
	return nbh;*/
}

ILP_SnifferPacket CPPPDecompressor::Unpack(CBlockHeader *bh, bool bOut) {
	/*!!!g_ofs1.write((char*)&len, 4);//!!!
	g_ofs1.write(p, len);*/
	BYTE *p = bh->m_data;
	ssize_t len = bh->m_len;
	if (len<1 || len >= 8192)
		Throw(E_Sniffer_InvalidPPPFormat);
	if (p[0] == 0x7E) {
		BYTE *q = m_buf;
		bool bEscape = false;
		for (int i=1; i<len; i++) {
			BYTE b = p[i];
			if (b == 0x7E)
				break;
			else if (b == 0x7D) {
				bEscape = true;
				continue;
			} else if (bEscape) {
				b ^= 0x20;
				bEscape = false;
			}
			*q++ = b;
		}
		p = m_buf;
		len = q-m_buf-2;
		bOut = true;
	}
	CMPPC *pMppc = bOut ? &m_mppcSend : &m_mppcRecv;
	CVJDecompressor *vj = bOut ? &m_tcpSend : &m_tcpRecv;
	ConstBuf mb(p, len);
	while (true)  {
		const byte *p = mb.P;
		len = mb.Size;
		if (!p || len < 2)
			return nullptr;
		WORD proto = *p++;
		len--;
		if (!(proto & 1)) {
			proto = (proto<<8)|*p++;
			len--;
		}
		switch (proto) {
		case PPP_COMP:
			try {
				p = pMppc->Unpack(p, len, len); //!!! FCS
			} catch (RCExc) {
				return nullptr; //!!!E_Sniffer_InvalidPPPFormat
			}
			mb = ConstBuf(p, len);
			break;
		case PPP_VJC_COMP:
			return AddPppHeader(bh, PPP_IP, vj->Uncompress(TYPE_COMPRESSED_TCP, p, len));
		case PPP_VJC_UNCOMP:
			return AddPppHeader(bh, PPP_IP, vj->Uncompress(TYPE_UNCOMPRESSED_TCP, p, len));
		case PPP_MP:
			//!!!case 0x3D: //!!! must be 0xC03D
			p = (bOut ? &m_multiLinkSend : &m_multiLinkRecv)->Process(p+1, len-1, len);
			mb = ConstBuf(p, len);
			break;
		case 0xff:  //!!! HDLC RFC-1549  BSD's PPP_ADDRESS
			mb = ConstBuf(p+1, len-1);
			break;
		default:
			return AddPppHeader(bh, proto, ConstBuf(p, len));
		}
	}
	Throw(E_Sniffer_InvalidPPPFormat);
}

ILP_SnifferPacket CPppManager::Process(CBlockHeader *bh, UInt64 nOrder) {
	if (bh->m_data[0] == 0x7E) {		//!!!
		bh->m_flags |= BLOCK_FLAG_OUT;
		BYTE *q = bh->m_data;
		bool bEscape = false;
		for (int i=1; i<bh->m_len; i++) {
			BYTE b = bh->m_data[i];  
			if (b == 0x7E)
				break;
			else if (b == 0x7D) {
				bEscape = true;
				continue;
			} else if (bEscape) {
				b ^= 0x20;
				bEscape = false;
			}
			*q++ = b;
		}
		bh->m_len = q - bh->m_data-2; //!!! FCS
	}

	int devLink = (bh->m_nDevice<<8)|bh->m_nLink;
	CLinkMap::iterator i = m_mapLink.find(devLink);
	CPPPDecompressor *dc;
	if (i != m_mapLink.end())
		dc = i->second.get();
	else
		m_mapLink[devLink] = dc = new CPPPDecompressor();  
	ILP_SnifferPacket sp = dc->Unpack(bh, bh->m_flags & BLOCK_FLAG_OUT);
	if (sp)
		sp->Order = nOrder;
	return sp;
}

#endif // !UCFG_SNIF_USE_PCAP

} // Snif::
