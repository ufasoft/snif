/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

//!!!#include "slip.h"
#define SLIP_HDRLEN 16

#include "standard-plugin.h"
#include "tcpapi.h"
#include "pppex.h"
#include "sniffermsg.h"

#include "gre.h"

namespace Snif {

class PPPObj;
class SLIPObj;

class PPPPacket : public PluginPacket {
	DECLARE_DYNCREATE(PPPPacket)
public:
#if UCFG_OLE
	void Info(CBag& bag) override {
		CBag row;
		ostringstream os;
		os << "Protocol 0x" << hex << GetProto();
		AddFieldInfo(row,os.str(), 0, 1);
		bag.Add((CBag("PPP"), row));
	}
#endif

	UInt16 GetProtoEx() {
		UInt16 w;
		byte b1 = GetByte(2);
		if (b1 & 1)
			w = b1;
		else {
			byte b2 = GetByte(3);
			w = (b1 << 8)|b2;
		}
		return w;
	}

	bool IsMPPE() {
		return GetProtoEx() == PPP_COMP && (GetByte(3) & 0x10);
	}

	long GetProto() override {
		switch (GetProtoEx()) {
		case PPP_IP: return ETHERTYPE_IP;
		case PPP_IPX: return ETHERTYPE_IPX;
		default: return PROTO_UNKNOWN;
		}
	}
protected:
	int GetOffset() override {
		return 0;
	}

	int GetLocalDataOffset() override {
		BYTE b1 = GetByte(2);
		return b1 & 1 ? 3 : 4;
	}
};

IMPLEMENT_DYNCREATE(PPPPacket, PluginPacket)

class PppoePacket : public PluginPacket {
	DECLARE_DYNCREATE(PppoePacket)
protected:
	long GetProto() override {
		return ETHERTYPE_PPP;
	}

	int GetLocalDataOffset() override {
		return 4;
	}
};

IMPLEMENT_DYNCREATE(PppoePacket, PluginPacket)


#if UCFG_GUI
class PPPDataSet : public PacketDataSet {
	PPPObj& m_plugin;
	//!!!CUnkPtr m_iOwner;
protected:
	ptr<Object> GetItem(int idx);
	size_t GetCount();
public:
	PPPDataSet(PPPObj& plugin);
};
#endif

class PppStream {
public:
	CMPPC m_ppc;
};

class PPPObj : public MACObj {        //!!!SnifferPlugin
	typedef MACObj base;

	CBool m_bWarned;

	void Decompress(ILP_SnifferPacket iSP, bool bNotify, bool bReanalyze = false);
protected:
	vector<long> GetProvided() override {
		vector<long> ar;
		ar.push_back(PROTO_IP);
		ar.push_back(PROTO_IPX);
		return ar;
	}

	void Bind() override {
		base::Bind();
		m_binder->m_mapEthernet[ETHERTYPE_PPP].insert(this);
	}

	void UnbindPlugin() override {
		m_binder->m_mapEthernet[ETHERTYPE_PPP].erase(this);
		base::UnbindPlugin();
	}

	void Disconnect() override {
#if UCFG_GUI
		m_collRaw.Release();
#endif
		SnifferPlugin::Disconnect();
	}
	/*!!!
	ptr<PluginPacket> CreatePluginPacket(SnifferPacketBase *iSP) {
	return CreatePacket(iSP);
	}*/

	/*!!!
	void Analyze(SnifferPacketBase *iPacket) {
	ptr<SnifferPacket> iOSP = StaticCast<SnifferPacket>(ptr<SnifferPacketBase>(iPacket));
	if (m_obCond && AsBoolean(m_obCond.GetProperty("Save")))
	{
	iOSP->Save(m_clPacket);
	m_collRaw.Add(iOSP->GetODObject());
	}
	Decompress(iOSP,false);
	}

	void Reanalyze(SnifferPacketBase *iPacket) {
	ptr<SnifferPacket> iOSP = StaticCast<SnifferPacket>(ptr<SnifferPacketBase>(iPacket));
	if (AsBoolean(m_obCond.GetProperty("Save")))
	m_collRaw.Add(iOSP->GetODObject());

	Decompress(iOSP,false,true);
	}*/

	void Clear() override {
		SnifferPlugin::Clear();
#if UCFG_GUI
		m_collRaw.DeleteAll();
#endif
	}

public:
#if UCFG_GUI
	ptr<DataSet> m_iPPPDataSet;
	COdCollObjects m_collRaw;

	void Connect(SnifferSite *pSite) override {
		SnifferPlugin::Connect(pSite);
		if (m_obj)
			m_collRaw = m_obj.GetProperty("RawPackets");
	}

	vector<String> GetDataSets() override {
		vector<String> vec;    
		vec.push_back("Packets");
		vec.push_back("OriginalPackets");
		return vec;
	}

	ptr<DataSet> GetDataSet(RCString name) override {
		if (name == "OriginalPackets") {
			if (!m_iPPPDataSet)
				m_iPPPDataSet = new PPPDataSet(_self);
			return m_iPPPDataSet;
		} else
			return SnifferPlugin::GetDataSet(name);
	}

	void DefinePluginClasses(COdClass& clCond) override {
		COdDatabase db = clCond.Database;
		COdClass cl = db.Classes[m_name];
		cl.CreateField("RawPackets","Packet *[]");
	}
#endif

	/*!!!static CComObjectRootBase *_CreateInstance() {
	return new PPPObj;
	}*/

	typedef pair<IPAddress, IPAddress> PppId;
	typedef LruMap<PppId, PppStream> PppStreams;
	PppStreams m_pppStreams;

	PPPObj()
		:	MACObj(PROTO_WAN)
	{
		m_name = "PPP";
		m_layer = PROTO_WAN;
		m_pPacketClass = RUNTIME_CLASS(PPPPacket);
	}


	void ProcessSubAnalyzers(PluginPacket *iPacket) override {
		PPPPacket *ppp = static_cast<PPPPacket*>(iPacket);
		switch (ppp->GetProtoEx()) {
		case PPP_COMP:
			if (ppp->IsMPPE())
				break;
			if (ppp->m_iBase) {
				if (GrePacket *gre = dynamic_cast<GrePacket*>(ppp->m_iBase.get())) {
					if (gre->m_iBase) {
						if (IpPacket *ip = dynamic_cast<IpPacket*>(gre->m_iBase.get())) {
							PppId pppId(IPAddress(ip->GetSrcAddr()), IPAddress(ip->GetDstAddr()));
							PppStream& pppStream = m_pppStreams[pppId];
							ConstBuf data = gre->GetData();
							data.P += 3;
							data.Size -= 3;
							/*!!!TODO
							ssize_t size;
							const byte *p = pppStream.m_ppc.Unpack(data.P, data.Size, size);
							ptr<SnifferPacket> sp = new(size) SnifferPacket;
							memcpy((byte*)sp->Data, p, size);	//!!!?
							sp->Size = size;
							PPPPacket pppNew;
							AnalyzeCreated(pppNew, sp);*/
						}
					}
				}
			}
			break;
		default:
			base::ProcessSubAnalyzers(iPacket);
		}
	}
};


class PppoeObj : public PPPObj {
public:
	PppoeObj() {
		m_name = "PPPoE";
		m_layer = PROTO_PPPOES;
		m_pPacketClass = RUNTIME_CLASS(PppoePacket);
	}

	vector<long> GetProvided() override {
		vector<long> r;
		r.push_back(PROTO_WAN);
		return r;
	}

	void Bind() override {
		m_binder->m_mapEthernet[ETHERTYPE_PPPOES].insert(this);
	}

	void UnbindPlugin() override {
		m_binder->m_mapEthernet[ETHERTYPE_PPPOES].erase(this);
	}
};


/*!!!void PPPObj::Decompress(ptr<SnifferPacket> iSP, bool bNotify, bool bReanalyze)
{
}*/

#if UCFG_GUI

PPPDataSet::PPPDataSet(PPPObj& plugin)
	:	PacketDataSet(&plugin)
	,	m_plugin(plugin)
{
	//!!!m_iOwner = &plugin;
}

ptr<Object> PPPDataSet::GetItem(int idx) {
	return m_plugin.m_iSite->ProcessPacket(SnifferPacket::Load(m_plugin.m_collRaw.GetItem(idx)));
}

size_t PPPDataSet::GetCount() {
	return m_plugin.m_collRaw.Count;
}
#endif

ptr<MACObj> CreatePPP() {
	return new PPPObj;
}

class SLIPPacket : public PluginPacket {
	DECLARE_DYNCREATE(SLIPPacket)
public:
#if UCFG_OLE
	void Info(CBag& bag) override {
		CBag row;
		bag.Add((CBag("SLIP"),row));
	}
#endif

	long GetProto() override {
		return PROTO_IP;
	}
protected:
	int GetOffset() override {
		return 0;
	}

	int GetLocalDataOffset() override {
		return SLIP_HDRLEN;
	}

};

IMPLEMENT_DYNCREATE(SLIPPacket, PluginPacket)

class SLIPObj : public MACObj {       //!!!SnifferPlugin
public:
	SLIPObj()
		:	MACObj(PROTO_SLIP)
	{
		m_name = "SLIP";
		m_layer = PROTO_SLIP;
		m_pPacketClass = RUNTIME_CLASS(SLIPPacket);
	}
protected:
	vector<long> GetProvided() override {
		vector<long> ar;
		ar.push_back(PROTO_IP);
		return ar;
	}

	void Disconnect() override {
		SnifferPlugin::Disconnect();
	}

#if UCFG_GUI
	ptr<DataSet> m_iSLIPDataSet;

	void Connect(SnifferSite *pSite) override {
		SnifferPlugin::Connect(pSite);
	}

	vector<String> GetDataSets() override {
		vector<String> vec;    
		vec.push_back("Packets");
		return vec;
	}
#endif // UCFG_GUI
private:
	CBool m_bWarned;
};

ptr<MACObj> CreateSLIP() {
	return new SLIPObj;
}

extern "C" { PluginClass<PPPObj, PROTO_WAN> g_pppClass; }
extern "C" { PluginClass<PppoeObj, PROTO_PPPOES> g_pppoeClass; }
extern "C" { PluginClass<SLIPObj, PROTO_SLIP> g_slipClass; }

} // Snif::

