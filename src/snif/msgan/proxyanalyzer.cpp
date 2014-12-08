/*######     Copyright (c) 1997-2012 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #####
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published #
# by the Free Software Foundation; either version 3, or (at your option) any later version. This program is distributed in the hope that #
# it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. #
# See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with this #
# program; If not, see <http://www.gnu.org/licenses/>                                                                                    #
########################################################################################################################################*/

#include <el/ext.h>

#include "msgan.h"

namespace Snif {

class ProxyAnalyzerOutStream : public AnalyzerStream {
public:
	ProxyAnalyzerOutStream()
	{
		m_state = ASTATE_NEED_MORE;
		m_wanted = 9; // enough for SOCKS4
	}

	bool Socks4(const ConstBuf& mb);
	bool Socks5(const ConstBuf& mb);
	void Process(const ConstBuf& mb) override;
};

class ProxyAnalyzerInStream : public AnalyzerStream {
public:
	ProxyAnalyzerInStream()
	{
		m_state = ASTATE_NEED_MORE;
		m_wanted = 8; //!!!
	}

	void Process(const ConstBuf& mb) override;
};

class ProxyAnalyzer : public Analyzer {
public:
	int m_socksVer;
	int m_stage;
	IPEndPoint m_hp;

	ProxyAnalyzerOutStream m_outStm;
	ProxyAnalyzerInStream m_inStm;

	ProxyAnalyzer()
		:	m_socksVer(0)
		,	m_stage(0)
	{
		SetOutStm(&m_outStm);
		SetInStm(&m_inStm);
	}

	void IncrementStage() {
		if (++m_stage == 2) {
			for (CAnalyzerList::iterator i=m_ci->PotentialAnalyzers.begin(), e=m_ci->PotentialAnalyzers.end(); i!=e; ++i) {
				((Analyzer&)(*i)).m_arStm[0]->m_offset = m_arStm[0]->m_wanted;
				((Analyzer&)(*i)).m_arStm[1]->m_offset = m_arStm[1]->m_wanted;
			}
			m_ci->DstEndPoint = m_hp;
			Delete();
		}
	}

	bool TryRecognize() { return true; }
};

bool ProxyAnalyzerOutStream::Socks4(const ConstBuf& mb) {
	ProxyAnalyzer& pa = *(ProxyAnalyzer*)m_analyzer;
	if (mb.P[1] != 1)
		return false;
	String username,
			    domainname;
	int i;
	for (i=8;; i++) {
		if (i >= mb.Size) {
			m_wanted = i+1;
			return true;
		}
		if (char c = mb.P[i])
			username += String(c);
		else {
			i++;
			break;
		}
	}
	if (!mb.P[4] && !mb.P[5] && !mb.P[6] && mb.P[7]) { // SOCKS4A domain name 
		for (i++;; i++) {
			if (i >= mb.Size) {
				m_wanted = i+1;
				return true;
			}
			if (char c = mb.P[i])
				domainname += String(c);
			else
				break;
		}
		pa.m_hp = IPEndPoint(domainname);
	}
	else
		pa.m_hp = IPEndPoint(*(long*)(mb.P+4));
	m_wanted = m_processed = i;
	m_state = ASTATE_NO_NEED;
	pa.m_hp.Port = ntohs(*(WORD*)(mb.P+2));
	pa.IncrementStage();	
	return true;
}

bool ProxyAnalyzerOutStream::Socks5(const ConstBuf& mb) {
	ProxyAnalyzer& pa = *(ProxyAnalyzer*)m_analyzer;
	byte n = mb.P[1];
	m_wanted =  2+n+10;
	if (mb.Size < m_wanted)
		return true;
	const byte *q = mb.P+2+n;
	if (q[0] != 5)
		return false;
	switch (q[3])
	{
	case 1:
		pa.m_hp = IPEndPoint(*(long*)(q+4));
		break;
	case 3:
		m_wanted += q[4]-3;
		if (mb.Size < m_wanted)
			return true;
		pa.m_hp = IPEndPoint(String((const char*)q+5, q[4]));
		break;
	default:
		return false; //!!! IPv6
	}
	m_processed = m_wanted;
	m_state = ASTATE_NO_NEED;
	pa.m_hp.Port = ntohs(*(WORD*)(mb.P+m_wanted-2));
	pa.IncrementStage();
	return true;
}

void ProxyAnalyzerOutStream::Process(const ConstBuf& mb) {
	ProxyAnalyzer& pa = *(ProxyAnalyzer*)m_analyzer;
	switch (mb.P[0])
	{
	case 4: 
		pa.m_socksVer = mb.P[0];
		if (Socks4(mb))
			return;
		break;
	case 5:
		pa.m_socksVer = mb.P[0];
		if (Socks5(mb))
			return;
	}
	m_analyzer->Delete();
}

void ProxyAnalyzerInStream::Process(const ConstBuf& mb) {
	ProxyAnalyzer& pa = *(ProxyAnalyzer*)m_analyzer;
	switch (pa.m_socksVer)
	{
	case 4:
		if (mb.P[0] != 0)
			break;
		if (mb.P[1] != 90)
			break;
		m_processed = m_wanted;
		pa.IncrementStage();
		return;
	case 5:
		m_wanted = 12;
		if (mb.Size < m_wanted)
			return;
		if (mb.P[0]!=5 || mb.P[2]!=5 || mb.P[3]!=0)
			break;
		switch (mb.P[5])
		{
		case 1:
			break;
		case 3:
			m_wanted = 12+mb.P[6]; //!!!
			if (mb.Size < m_wanted)
				return;
			break;
		default:
			goto del;
		}
		m_processed = m_wanted;
		pa.IncrementStage();
		return;
	}
del:
	m_analyzer->Delete();
}

/*!!!

	void Socks5(TcpConnection *c)
	{
		try
		{
			Blob blob(c->GetOutStream()->GetData());
			CBlobReadStream bsOut(blob);
			BYTE b, n;
			bsOut >> b >> n;
			bsOut.ReadBuffer(0, n);
			BYTE buf[256];
			bsOut.ReadBuffer(buf, 4);
			if (buf[0]!=5 || buf[1]!=1)
				Throw(1);
			switch (buf[3])
			{
			case 1: bsOut.ReadBuffer(0, 4); break;
			case 3:
				bsOut >> buf[0];
				bsOut.ReadBuffer(0, buf[0]);
				break;
			default: Throw(1);
			}
			WORD port;
			bsOut >> port;

			blob = c->GetInStream()->GetData();
			CBlobReadStream bsIn(blob);
			bsIn.ReadBuffer(buf, 6);
			if (buf[0]!=5 || buf[2]!=5 || buf[3]!=0)
				Throw(1);
			switch (buf[5])
			{
			case 1: bsIn.ReadBuffer(0, 4); break;
			case 3:
				bsIn >> buf[0];
				bsIn.ReadBuffer(0, buf[0]);
				break;
			default: Throw(1);
			}
			bsIn >> port;
			c->m_iConn->DiscardOut((DWORD)bsOut.Position);
			c->m_iConn->DiscardIn((DWORD)bsIn.Position);
		}
		catch (RCExc e)
		{
			switch (e.HResult)
			{
			case 1: c->Delete();
			case E_EXT_EndOfStream: return;
			default: throw;
			}
		}
	}


class CProxyAnalyzer : public CTcpAnalyzer
{
	void Socks4(TcpConnection *c)
	{
		try
		{
			Blob blob(c->GetOutStream()->GetData());
			CBlobReadStream bsOut(blob);
			BYTE buf[256];
			bsOut.ReadBuffer(buf, 8);
			if (buf[0]!=4 || buf[1]!=1)
				Throw(1);
			for (BYTE b; (bsOut>>b), b;)
				;
			if (!buf[4] && !buf[5] && !buf[6] && buf[7])
				for (BYTE b; (bsOut>>b), b;) // SOCKS 4a
					;
			blob = c->GetInStream()->GetData();
			CBlobReadStream bsIn(blob);
			bsIn.ReadBuffer(buf, 8);
			c->m_iConn->DiscardOut((DWORD)bsOut.Position);
			c->m_iConn->DiscardIn((DWORD)bsIn.Position);
		}
		catch (RCExc e)
		{
			switch (e.HResult)
			{
			case 1: c->Delete();
			case E_EXT_EndOfStream: return;
			default: throw;
			}
		}
	}


	void UpdatedConnection(TcpConnection *c)
	{
		if (!c->GetWasSYN())
			c->Delete();
		else
		{
      ConstBuf mb = c->GetOutStream()->GetData();
			if (mb.m_len)
			{
				BYTE b = mb.m_p[0];
				switch (b)
				{
				case 4: Socks4(c); break;
				case 5: Socks5(c); break;
				default: c->Delete();
				}
			}
			else
				c->Delete();	//!!!
		}
	}
};
*/

class ProxyAnalyzerClass : public AnalyzerClass<ProxyAnalyzer> {
public:
	ProxyAnalyzerClass() {
		Priority = 0;
		Create("Proxy");
	}
};

extern "C" {
	class CProxyMessageAnalyzerClass : public CMessageAnalyzerClass
	{
	public:
		CProxyMessageAnalyzerClass()
			: CMessageAnalyzerClass("PROXY")
		{
			Type = ATYPE_MANDATORY;
		}

		CMessageAnalyzer *CreateObject()
		{
			return new CMessageAnalyzer(new ProxyAnalyzerClass);
		}

	} g_proxyMessageAnalyzerClass;
}

} // Snif::

