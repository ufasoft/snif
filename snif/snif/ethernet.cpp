/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "standard-plugin.h"

namespace Snif {

class CPacketDataSet;

class EthernetPacket : public MACPacket {
	DECLARE_DYNCREATE(EthernetPacket)
public:
	EthernetPacket() {
		m_dataOffset = 14;
	}

	EthernetPacket *Clone() const {
		return new EthernetPacket(_self);
	}

	void PreAnalyze() override {
		WORD w = GetType();
		if (w <= 1500) {
			ConstBuf mb = GetRawData();
			if (mb.Size < 16)
				Throw(E_FAIL);
			if (*(WORD*)(mb.P+14) == 0xFFFF) {
				m_dataOffset += 2;
				m_ethertype = ETHERTYPE_IPX;
			} else {
				m_bLLC = true;
				MACPacket::PreAnalyze();
			}
		}
	}
protected:
	MacAddress GetSource() { return MacAddress(ConstBuf(GetChunk(6, 6), 6)); }
	MacAddress GetDestination() { return MacAddress(ConstBuf(GetChunk(0, 6), 6)); }
	WORD GetType() { return ntohs(GetWord(12)); }

	void SetType(WORD typ) {
		return SetWord(12,htons(typ));
	}

	void SetSource(MacAddress mac) {
		SetChunk(6, ConstBuf(&mac.m_n64, 6));
	}

	void SetDestination(MacAddress mac) {
		SetChunk(0, ConstBuf(&mac.m_n64, 6));
	}

	String GetFrom() {
		ostringstream os;
		os << GetSource();
		return os.str();
	}

	String GetTo() {
		ostringstream os;
		os << GetDestination();
		return os.str();
	}
};

class EthernetObj : public MACExObj {
	typedef MACExObj base;
public:
	EthernetObj()
		:	MACExObj(PROTO_ETHERNET)
	{
		m_name = "Ethernet";
		m_layer = PROTO_ETHERNET;
		m_pPacketClass = RUNTIME_CLASS(EthernetPacket);
	}

	ptr<MACPacket> ComposePacket(PluginPacket *pp) {
		ptr<EthernetPacket> r = new EthernetPacket;
		ptr<SnifferPacket> sp = new(14+pp->m_iBase->GetData().Size) SnifferPacket;
		r->m_iBase = (SnifferPacket*)sp;
		pp->m_iBase = (EthernetPacket*)r; //!!!
		return StaticCast<MACPacket>(r);
	}

	vector<long> GetProvided() override {
		vector<long> r = base::GetProvided();
		r.push_back(PROTO_PPPOES);  // PPPoE
		return r;
	}

	void Analyze(SnifferPacketBase *iPacket) override {
		EthernetPacket packet;
		AnalyzeCreated(packet, iPacket);
	}

	void Bind() override {
		m_binder->m_mapIp[IPPROTO_ETHERIP].insert(this);
	}

	void UnbindPlugin() override {
		m_binder->m_mapIp[IPPROTO_ETHERIP].erase(this);
	}
};

IMPLEMENT_DYNCREATE(EthernetPacket, PluginPacket)

//!!!CStandardPluginClass g_classEthernet(CLSID_Ethernet,CEthernetObj::_CreateInstance,IDS_ETHERNET);

ptr<MACObj> CreateEthernet() {
	return new EthernetObj;
}

extern "C" { PluginClass<EthernetObj,PROTO_ETHERNET> g_ethernetClass; }

} // Snif::
