/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#if UCFG_WIN32
#	include <winsock2.h>
#	include <inaddr.h>
#endif

#include "vjc.h"

#define SLF_TOSS 1       /* tossing rcvd frames because of input err */

void Decode(const BYTE *&p, u_int32_t& dw) {
	if (BYTE b = *p++)
		dw = htonl(ntohl(dw)+b);
	else {
		dw = htonl(ntohl(dw)+ntohs(*(WORD*)p));
		p += 2;
	}
}

void Decode(const BYTE *&p, WORD& w) {
	if (BYTE b = *p++)
		w = htons(ntohs(w)+b);
	else {
		w = htons(ntohs(w)+ntohs(*(WORD*)p));
		p += 2;
	}
}

void DecodeU(const BYTE *&p, WORD& w) {
	if (BYTE b = *p++)
		w = htons(b);
	else {
		w = *(WORD*)p;
		p += 2;
	}
}

CVJDecompressor::CVJDecompressor()
	:	m_bToss(true)
	,	m_lastRecv(MAX_STATES)
	,	m_arState(MAX_STATES)
{  
	for (size_t i=m_arState.size(); i--;)
		m_arState[i].m_id = (BYTE)i;
}

ConstBuf CVJDecompressor::Uncompress(int type, const byte *p, ssize_t len) {
	ConstBuf rb;
	switch (type) {
	case TYPE_UNCOMPRESSED_TCP:
		{
			ip *iph = (ip*)p;
			if (iph->ip_p >= MAX_STATES)
				break;
			CCompState& cs = m_arState[m_lastRecv = iph->ip_p];
			m_bToss = false;
			iph->ip_p = IPPROTO_TCP;  
			int hlen = iph->ip_hl;
			hlen = (hlen+((tcphdr*)((BYTE*)iph+hlen*4)))->th_off << 2;
			memcpy(cs.m_hdr,iph,hlen);
			cs.m_ipHeader.ip_sum = 0;
			cs.m_hlen = (WORD)hlen;
			cs.m_bBeginned = true;
		}
	case TYPE_IP:
		return ConstBuf(p,len);
	case TYPE_COMPRESSED_TCP:
		const BYTE *cp = p;
		BYTE changes = *cp++;
		if (changes & NEW_C) {
			if (*cp >= MAX_STATES || !m_arState[*cp].m_bBeginned)
				break;
			m_bToss = false;
			m_lastRecv = *cp++;
		} else if (m_bToss)
			break;
		CCompState& st = m_arState[m_lastRecv];
		int hlen = st.m_ipHeader.ip_hl << 2;
		tcphdr *th = (tcphdr*)(st.m_hdr+hlen);
		th->th_sum = htons((*cp << 8) | cp[1]);
		cp += 2;
		if (changes & TCP_PUSH_BIT)
			th->th_flags |= TH_PUSH;
		else
			th->th_flags &= ~TH_PUSH;
		switch (changes & SPECIALS_MASK)
		{
		case SPECIAL_I:
			{
				DWORD i = ntohs(st.m_ipHeader.ip_len)-st.m_hlen;
				th->th_ack = htonl(ntohl(th->th_ack)+i);
				th->th_seq = htonl(ntohl(th->th_seq)+i);
			}
			break;
		case SPECIAL_D:
			th->th_seq = htonl(ntohl(th->th_seq)+ntohs(st.m_ipHeader.ip_len)-st.m_hlen);
			break;
		default:
			if (changes & NEW_U) {
				th->th_flags |= TH_URG;
				DecodeU(cp,th->th_urp);
			}
			else
				th->th_flags &= ~TH_URG;
			if (changes & NEW_W)
				Decode(cp,th->th_win);
			if (changes & NEW_A)
				Decode(cp,th->th_ack);
			if (changes & NEW_S)
				Decode(cp,th->th_seq);
		}
		if (changes & NEW_I) {
			WORD ipId = st.m_ipHeader.ip_id;
			Decode(cp, ipId);
			st.m_ipHeader.ip_id = ipId;
		} else
			st.m_ipHeader.ip_id = htons(ntohs(st.m_ipHeader.ip_id)+1);
		if ((len-=cp-p) < 0)
			break;
		memcpy(m_buf+st.m_hlen,cp,len);
		st.m_ipHeader.ip_len = htons(WORD(len+st.m_hlen)); //!!!
		BYTE *wp = m_buf; 
		memcpy(wp,st.m_hdr,st.m_hlen);
		DWORD sum = 0;
		for (WORD *bp = (WORD*)wp; hlen > 0; hlen -= 2)
			sum += *bp++;
		sum = LOWORD(sum)+HIWORD(sum);
		((ip*)wp)->ip_sum = ~WORD(LOWORD(sum)+HIWORD(sum));
		return ConstBuf(wp, len+st.m_hlen);
	}
	m_bToss = true;
	return rb;
}


