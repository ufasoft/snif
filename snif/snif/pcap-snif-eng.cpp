/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "pcap-snif-eng.h"
#include "tcpapi.h"

//!!!R#if UCFG_COPY_PROT
//#	include "upgrade.cpp"
//#endif

namespace Snif {

class PcapAdapter : public Adapter, protected CPacketProvider {
	typedef Adapter base;
public:
	PcapAdapter(PcapSnifEng& eng, CPacketProvider::PacketInterface& itf)
		:	base(&eng.m_tr)
		,	m_eng(eng)
	{
		m_bAutoDelete = false;
		m_desc.Name = itf.Name;
		m_desc.Description = itf.Description;
		CPacketProvider::OpenLive(itf.Name);
		m_ipParams = itf.Params;
#if defined(_DEBUG)
//!!!		ThreadBase::CreationHelper();
#endif
		base::Start();
	}

	void SignalStop() {
		BreakLoop();
		Thread::SignalStop();
	}

	vector<CIpParams> GetIpParams() {
		return m_ipParams;
	}

	void SendEx(const Buf& mb, bool bDefer) {
		CPacketProvider::Send(mb);
	}
	
	int ReadOp(int cnt, CSnifCallback& cb) {
		CPointerKeeper<CSnifCallback> pk(p_cb, &cb);
		return CPacketProvider::Loop(cnt);
	}

	void Execute() {
		CBoolKeeper bk(m_bEnqueueToEng.Ref(), true);
		CPacketProvider::Loop();
	}

	void *operator new(size_t size) {
		return ::operator new(size);
	}
private:
	PcapSnifEng& m_eng;
	CPointer<CSnifCallback> p_cb;
	vector<CIpParams> m_ipParams;
	CBool m_bEnqueueToEng;

	void OnPacket(const pcap_pkthdr& hdr, const ConstBuf& mb) {
		SnifferPacket snifPacket;
		SnifferPacket *p = &snifPacket;

		const u_char *data = (const u_char*)mb.P;
		int len = mb.Size;
		byte medium = CPacketProvider::m_medium;
		AdjustPacketMedium(data, len, medium);


		ILP_SnifferPacket sp;
		if (m_bEnqueueToEng)
			 p = sp = new(len) SnifferPacket;
		p->TimeStamp = hdr.ts;
		p->Adapter = this;
		p->Medium = medium;

		if (p_cb) {
			snifPacket.Data = (byte*)data;
			snifPacket.Size = len;
			p_cb->ProcessPacket(snifPacket);
		} else if (m_bEnqueueToEng) {
			memcpy((byte*)sp->Data, data, len);
			m_eng.Process(sp, this);
//			m_filter->Process(sp);
//!!!			m_eng.m_queue.push_back(sp);
		}
	}
};


void PcapSnifEng::OpenAdapters() {
	m_bAdaptersOpened = true;
	vector<CPacketProvider::PacketInterface> ar = CPacketProvider::GetAllInterfaces();
	for (int i=0; i<ar.size(); ++i) {
		CPacketProvider::PacketInterface& itf = ar[i];
		ptr<Adapter> a = new PcapAdapter(_self, itf);
//!!!		a->m_filter = new CAdapterFilter(a);
//!!!		a->m_filter->m_bLooped = true;
		//!!!g_packetFB.Add(a->m_filter);
//!!!R		a->m_filter->hFile = (HANDLE)a;
		EXT_LOCK (m_cs) {
			m_adapters.push_back(a);
		}
	}
}

void PcapSnifEng::Create(bool bEnabled) {
	OpenAdapters();
	m_bEnabled = bEnabled;
}

void PcapSnifEng::BreakLoop() {
//!!!	m_tr.SignalStop();
}


} // Snif::

