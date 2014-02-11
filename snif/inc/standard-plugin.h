/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#pragma once

#if UCFG_WIN32
#	include <winsock2.h>
#	include <inaddr.h>
#	include <regstr.h>
#endif

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#if UCFG_GUI
#	include <el/gui/tabcontrol.h>
#	include <el/gui/treeview.h>
#	include <el/comp/plot.h>

namespace Ext {
#	include <el/libext/win32/ext-afxdd_.h>
}
//!!!R #include <el/comp/upgrade.h>
#endif


#if UCFG_OLE
#	include <el/comp/bag.h>
#endif


#include "snif-config.h"
#include <snif.h>
#include <sniffeng.h>
#include "pppex.h"


#include "res.h"
#include "../snif/resource.h"

//!!!#include "ether.h"
//!!!#include "ethertype.h"


#if UCFG_USE_POSIX
#	include <netinet/in.h>
#else
#	include "ipproto.h"
#endif


//!!!#include "PktDump.h"

namespace Snif {

class SnifferPlugin;
class PluginPacket;
class PacketDataSet;
class CDialogControlPanel;
class CDialogSelectAdapter;
class IpPacket;
class CConditionsView;

const WORD ETHERTYPE_MY_NETBEUI = 0x8191; //!!!

} namespace Ext {
template <> struct ptr_traits<Snif::SnifferPlugin> {
	typedef NonInterlocked interlocked_policy;
};

template <> struct ptr_traits<Snif::PluginPacket> {
	typedef NonInterlocked interlocked_policy;
};
} // Ext::
namespace Snif {

class AnalyzerBinder {
public:
	typedef set<ptr<SnifferPlugin> > Subscribers;
	typedef unordered_map<long, Subscribers> Map;

	Map m_map;
	Map m_mapEthernet;
	Map m_mapIp;
};

#if UCFG_GUI
class SnifferSite : public Object {
public:
	virtual COdDatabase GetDatabase() { return COdDatabase(); }
	virtual ptr<PluginPacket> ProcessPacket(SnifferPacket *iSP) { return nullptr; } 
	//!!!  virtual ptr<SnifferPacket> CreatePacket(CBlockHeader *bh) =0;
};

class DataSetNotify : public Object {
public:
	virtual void OnChanged() =0;
};

class DataSet : public Object {
public:
	virtual ptr<Object> GetItem(int idx) =0;
	virtual size_t GetCount() =0;
	virtual vector<String> GetFields() =0;
	virtual void SetNotify(DataSetNotify *iNotify) =0;
};

class PacketDataSet : public DataSet {
	ptr<SnifferPlugin> m_plugin;
protected:
	ptr<DataSetNotify> m_iNotify;

	ptr<Object> GetItem(int idx);
	size_t GetCount();
	vector<String> GetFields();
	void SetNotify(DataSetNotify *iNotify) { m_iNotify = iNotify; }
public:
	PacketDataSet(ptr<SnifferPlugin> plugin)
		:	m_plugin(plugin)
	{}
};


#endif // UCFG_GUI

class SnifferPlugin : public Object {
	DECLARE_DYNCREATE(SnifferPlugin)
protected:

#if UCFG_GUI
	CPointer<CConditionsView> m_pView;
#endif

	struct CSubscription {
		ptr<SnifferPlugin> m_iSubscription;
		long m_proto;
	};
	//!!!  vector<CSubscription> m_arSubscribers;

	virtual bool CheckConditions(PluginPacket *iPacket);
	virtual void ProcessSubAnalyzers(PluginPacket *iPacket);
	virtual void ProcessPacket(PluginPacket *iPacket);
#if UCFG_SNIF_USE_ODDB
	virtual void DefinePluginClasses(COdClass& clCond);
	virtual void SetDefaultConditions();
	virtual void UpgradePluginClasses(COdClass& clCond);
#endif
	virtual vector<long> GetProvided() { return vector<long>(); }
	virtual AnalyzerBinder::Map *GetProtocolMap() { return 0; }
public:
	CPointer<AnalyzerBinder> m_binder;
	String m_name;
	long m_layer;
	bool m_bMacPlugin;
#if UCFG_SNIF_USE_ODDB
	COdObject m_obj,
		m_obCond;
	COdCollObjects m_collPackets;
	COdClass m_clPacket;
#endif

	ptr<SnifferPlugin> m_iBase;
	CPointer<CRuntimeClass> m_pPacketClass;

#if UCFG_GUI
	ptr<SnifferSite> m_iSite;
	ptr<PacketDataSet> m_pDataSet;
	CPointer<CRuntimeClass> m_pViewClass;

	virtual void CreateConditionsView();
	virtual void Connect(SnifferSite * aSnifferObj);
	virtual ptr<DataSet> GetDataSet(RCString name);
	virtual HWND ShowFilter(HWND hwnd);
	virtual void HideFilter();
	virtual vector<String> GetDataSets();
#endif
	
	SnifferPlugin();

	String GetName() { return m_name; }
	long GetLayer() { return m_layer; }
	virtual void Bind();
	virtual void UnbindPlugin();
	void AnalyzeCreated(PluginPacket *iPP);
	void AnalyzeCreated(PluginPacket& pp, SnifferPacketBase *iPacket);
	virtual void Analyze(SnifferPacketBase *iPacket);
	virtual void Reanalyze(SnifferPacketBase *iPacket);
	virtual void Disconnect();
	//!!!  virtual void Subscribe(SnifferPlugin *anObj, long prot);
	//!!!  virtual void Unsubscribe(SnifferPlugin *anObj);
	virtual void Clear();
	virtual ptr<PluginPacket> CreateSubPluginPacket(ptr<PluginPacket> iNew);
	virtual ptr<PluginPacket> CreatePluginPacket(SnifferPacketBase *iSP);
#if UCFG_OLE
	virtual void GetProps(CBag& bag);
#endif
	virtual ptr<PluginPacket> CreatePacket(SnifferPacketBase *iSPB);
};

class AFX_SNIF_CLASS PluginClassBase {
public:
	typedef map<long, PluginClassBase*> PluginMap;

	static PluginMap& __stdcall InstanceMap() {
		static PluginMap m;
		return m;
	}

	static ptr<SnifferPlugin> __stdcall CreatePlugin(long layer, AnalyzerBinder *binder);

	virtual ptr<SnifferPlugin> CreateObject() =0;
};

template <class T, long proto> class PluginClass : public PluginClassBase {
public:
	PluginClass() {
		InstanceMap()[proto] = this;
	}

	ptr<SnifferPlugin> CreateObject() {
		return new T;
	}
};

class AFX_SNIF_CLASS ITcpdumpHook {
public:
	static ITcpdumpHook *I;

	virtual String Process(SnifferPacket *iSP) =0;
};

class AFX_SNIF_CLASS PluginPacket : public SnifferPacketBase {
	typedef SnifferPacketBase base;
	DECLARE_DYNAMIC(PluginPacket)
public:
	ptr<SnifferPacketBase, Interlocked> m_iBase;
	//!!!  CPointer<CBlockHeader> m_pBlock;
	CPointer<SnifferPlugin> m_pPlugin;

	PluginPacket() {
	}

	void InitInStack(SnifferPlugin *plugin, SnifferPacketBase *iSPB) {
		m_pPlugin = plugin;
		m_iBase = iSPB;
		base::InitInStack();
	}

	virtual PluginPacket *Clone() const {
		return new PluginPacket(_self);
	}

	String GetFrom() { return m_iBase ? m_iBase->GetFrom() : SnifferPacketBase::GetFrom(); }
	String GetTo() { return m_iBase ? m_iBase->GetTo() : SnifferPacketBase::GetTo(); }

	long GetProto() override { return PROTO_UNKNOWN; } //!!!
	ILP_SnifferPacket GetRootPacket();
	ptr<PluginPacket> MakePacketHeaped();
	virtual void PreAnalyze() {}
	virtual long GetDataOffset() { return GetOffset()+GetLocalDataOffset(); }
	virtual String GetField(RCString fieldID);
	//!!!D  ptr<SnifferPacketBase> GetBase() { return m_iBase; }
#if UCFG_OLE
	virtual void Info(CBag& bag);
#endif
	Buf GetData();
	virtual Blob GetDataBlob() { return GetData(); }
protected:
	virtual int GetOffset();
	virtual int GetLocalDataOffset();
#if UCFG_OLE
	void AddFieldInfo(CBag& bag, RCString s, ssize_t beg, ssize_t len);
#endif

	const byte *GetChunk(int pos, int size);
	void SetChunk(int pos, const ConstBuf& chunk);
	BYTE GetByte(int pos) { return *GetChunk(pos, 1); }	
	WORD GetWord(int pos) { return *(WORD*)GetChunk(pos, 2); }
	void SetWord(int pos, WORD w) { SetChunk(pos, ConstBuf(&w, 2)); }
	WORD GetHWord(int pos) { return ntohs(GetWord(pos)); }
	void SetHWord(int pos, WORD w) { SetWord(pos, htons(w)); }
	DWORD GetDWord(int pos) { return *(DWORD*)GetChunk(pos, 4); }
	void SetDWord(int pos, DWORD dw) { SetChunk(pos, ConstBuf(&dw, 4)); }
	DWORD GetHDWord(int pos) { return ntohl(GetDWord(pos)); }
	void SetHDWord(int pos, DWORD dw) { SetDWord(pos, htonl(dw)); }
};

/*!!!R
class IpWrap {
public:
	typedef IpWrap class_type;

	ip *m_ip;

	IpWrap(ip *ip)
		:	m_ip(ip)
	{}

	inline IpWrap(IpPacket *iIPP);

	BYTE get_IHL() { return m_ip->ip_hl; }
	DEFPROP_GET(BYTE, IHL);

	DWORD get_Src() { return Fast_ntohl(m_ip->ip_src.s_addr); }
	DEFPROP_GET(DWORD, Src);

	DWORD get_Dst() { return Fast_ntohl(m_ip->ip_dst.s_addr); }
	DEFPROP_GET(DWORD, Dst);

	BYTE get_Flags() { return ((BYTE*)m_ip)[6] >> 5; }
	DEFPROP_GET(BYTE, Flags);

	bool get_MF() { return Flags & 1; }
	DEFPROP_GET(bool, MF);

	WORD get_FragmentOffset() { return Fast_ntohs(m_ip->ip_off) << 3; }
	DEFPROP_GET(WORD, FragmentOffset);
};

inline IpWrap::IpWrap(IpPacket *iIPP)
:	m_ip((ip*)iIPP->m_iBase->GetData().m_p)
{
}
*/

class IpPacket : public PluginPacket {
	typedef PluginPacket base;
	typedef IpPacket class_type;
public:
	virtual ConstBuf GetSrcAddr() =0;
	virtual ConstBuf GetDstAddr() =0;
	virtual byte GetHopLimit() =0;
};


const int FID_ETHERNET_SourceMAC = 1,
FID_ETHERNET_DestinationMAC = 2,
FID_ETHERNET_Protocol = 3,
FID_ETHERNET_Data = 4;

const int FID_Source = 10,
FID_Destination = 11,
FID_Order = 12,
FID_Time = 13,
FID_Summary = 14;

const int FID_IP_SourceIP = 100,
FID_IP_DestinationIP = 101,
FID_IP_Protocol = 102,
FID_IP_TTL = 103,
FID_IP_Data = 104,
FID_IP_IHL = 105,
FID_IP_Version = 106,
FID_IP_TypeOfService = 107,
FID_IP_TotalLength = 108,
FID_IP_Identification = 109,
FID_IP_HeaderChecksum = 110,
FID_IP_FragmentOffset = 111,
FID_IP_HeaderFlags = 112;

const int FID_ARP_OpCode = 200,
FID_ARP_SenderMAC = 201,
FID_ARP_SenderPA = 202,
FID_ARP_TargetMAC = 203,
FID_ARP_TargetPA = 204;

const int FID_UDP_SourcePort = 400,
FID_UDP_DestinationPort = 401,
FID_UDP_Length = 402,
FID_UDP_Checksum = 403,
FID_UDP_Data = 404;

const int FID_TCP_SourcePort = 500,
FID_TCP_DestinationPort = 501,
FID_TCP_Data = 502,
FID_TCP_Sequence = 503,
FID_TCP_Acknowledgment = 504,
FID_TCP_URG = 505,
FID_TCP_ACK = 506,
FID_TCP_PSH = 507,
FID_TCP_RST = 508,
FID_TCP_SYN = 509,
FID_TCP_FIN = 510,
FID_TCP_Window = 511,
FID_TCP_DataOffset = 512;


extern int
forceIP,
forceIP6,
forceTCP;

class MACPacket : public PluginPacket {
public:
	MACPacket()
		:	m_ethertype(0)
		,	m_dataOffset(0)
	{}

	long GetProto() override;
	String GetField(RCString fieldID);
#if UCFG_OLE
	void Info(CBag& bag) override;
#endif
	void PreAnalyze() override;
	virtual MacAddress GetSource() =0;
	virtual void SetSource(MacAddress mac) { Throw(E_FAIL); }
	virtual MacAddress GetDestination() =0;
	virtual void SetDestination(MacAddress mac) { Throw(E_FAIL); }
	virtual WORD GetType() =0;
	virtual void SetType(WORD typ) { Throw(E_FAIL); }
	virtual ConstBuf GetRawData() { return m_iBase->GetData(); }
protected:
	CBool m_bLLC;
	WORD m_ethertype;
	int m_dataOffset;

	int GetOffset() override {
		return 0;
	}

	int GetLocalDataOffset() override { return m_dataOffset; }
};

class IMacHook {
public:
	virtual void OnReceivedMac(MACPacket *mac) =0;
};

class MACObj : public SnifferPlugin, public CAdapterFilter {
protected:
	vector<long> GetProvided() override {
		vector<long> ar;
		ar.push_back(PROTO_IP);
#if UCFG_SNIF_IPV6
		ar.push_back(PROTO_IP6);
#endif
		ar.push_back(PROTO_ARP);
		ar.push_back(PROTO_IPX);
		ar.push_back(PROTO_NETBEUI);
		return ar;
	}

	AnalyzerBinder::Map *GetProtocolMap() override {
		return &m_binder->m_mapEthernet;
	}
public:
	vector<IMacHook*> m_subscribers;

	void SubscribeHook(IMacHook *hook) { m_subscribers.push_back(hook); }
	void UnsubscribeHook(IMacHook *hook) { Ext::Remove(m_subscribers, hook); }

	MACObj(BYTE medium)
		:	CAdapterFilter(medium)
	{
		m_bMacPlugin = true;
	}

	void ProcessPacket(PluginPacket *iPacket) override {
		MACPacket *iMP = static_cast<MACPacket*>(iPacket);
		for (size_t i=m_subscribers.size(); i--;)
			m_subscribers[i]->OnReceivedMac(iMP);
		SnifferPlugin::ProcessPacket(iPacket);
	}

	virtual ptr<MACPacket> ComposePacket(PluginPacket *pp) { return nullptr; }

	void OnReceived(SnifferPacket *sp);
};

class MACExObj : public MACObj {
public:
	MACExObj(BYTE medium);

	bool CheckConditions(PluginPacket *iPacket) override {
		if (SnifferPlugin::CheckConditions(iPacket))
			return true;
#if UCFG_SNIF_USE_ODDB
		MACPacket *iMP = static_cast<MACPacket*>(iPacket);
		MacAddress macSrc = iMP->GetSource(),
			macDst =  iMP->GetDestination();
		CVariantIterator vi(m_obCond.GetProperty("MACs"));
		for (COleVariant v; vi.Next(v);) {
			MacAddress mac(AsOptionalBlob(v));
			if (macSrc == mac || macDst == mac)
				return true;
		}
#endif
		return false;
	}

#if UCFG_SNIF_USE_ODDB
	void DefinePluginClasses(COdClass& clCond) override {
		clCond.CreateField("MACs", "binary []");
	}
#endif
};

class IcmpPacket : public PluginPacket {
	DECLARE_DYNCREATE(IcmpPacket)

	String IcmpTypeToStr();
	String IcmpCodeToStr();
protected:
	int GetLocalDataOffset() override { return 4; }
public:
	typedef IcmpPacket class_type;

	BYTE get_Type() { return GetByte(0); }
	DEFPROP_GET(BYTE,Type);

	BYTE get_Code() { return GetByte(1); }
	DEFPROP_GET(BYTE,Code);

	WORD get_Checksum() { return GetHWord(2); }
	DEFPROP_GET(WORD,Checksum);

#if UCFG_OLE
	void Info(CBag& bag) override;
#endif
};

class IIcmpHook {
public:
	virtual void OnReceivedIcmp(IcmpPacket *icmp) =0;
};

class IcmpObj : public SnifferPlugin {
public:
	CSubscriber<IIcmpHook> m_subscriber;

	IcmpObj();
	void ProcessPacket(PluginPacket *iPacket) override;

	void Bind() override {
		m_binder->m_mapIp[IPPROTO_ICMP].insert(this);
	}

	void UnbindPlugin() override {
		m_binder->m_mapIp[IPPROTO_ICMP].erase(this);
	}
};

class NetBEUIPacket : public PluginPacket {
public:
	typedef NetBEUIPacket class_type;

	NetBEUIPacket *Clone() const {
		return new NetBEUIPacket(_self);
	}

	WORD get_HeaderLength();
	DEFPROP_GET(WORD,HeaderLength);

	BYTE get_Command() { return GetByte(4); }
	DEFPROP_GET(BYTE,Command);

	int GetLocalDataOffset() override { return HeaderLength; }

	DECLARE_DYNCREATE(NetBEUIPacket)
};

class INetbeuiHook {
public:
	virtual void OnReceivedNetbeui(NetBEUIPacket *netbeui) =0;
};

class NetBEUIObj : public SnifferPlugin {
public:
	CSubscriber<INetbeuiHook> m_subscriber;

	NetBEUIObj();
protected:
	void ProcessPacket(PluginPacket *iPacket) override;

	void Bind() override {
		m_binder->m_mapEthernet[ETHERTYPE_MY_NETBEUI].insert(this);
	}

	void UnbindPlugin() override {
		m_binder->m_mapEthernet[ETHERTYPE_MY_NETBEUI].erase(this);
	}

	void Analyze(SnifferPacketBase *iPacket) override {
		NetBEUIPacket packet;
		AnalyzeCreated(packet, iPacket);
	}
};


class COsRouting {
public:
	static bool GetEnable() {
#ifdef WIN32
		return (DWORD)RegistryKey(HKEY_LOCAL_MACHINE,GetRegistryKey()).TryQueryValue(GetRegistryValue(),(DWORD)0);
#else
		return false; //!!!TODO
#endif
	}

	static void SetEnable(bool b) {
#ifdef WIN32
		RegistryKey(HKEY_LOCAL_MACHINE,GetRegistryKey()).SetValue(GetRegistryValue(),(DWORD)b);
#endif
	}
private:
#ifdef WIN32
	static String GetRegistryKey() {
		return String(REGSTR_PATH_SERVICES) + (Environment.OSVersion.Platform == PlatformID::Win32NT ? "\\Tcpip\\Parameters" : "\\VxD\\MSTCP");
	}

	static String GetRegistryValue() {
		return Environment.OSVersion.Platform == PlatformID::Win32NT ? "IPEnableRouter" : "EnableRouting";
	}
#endif
};


ptr<MACObj> CreateEthernet();
ptr<MACObj> CreateTokenRing();
ptr<MACObj> CreatePPP();
ptr<MACObj> CreateSLIP();
ptr<MACObj> Create802_11();

ptr<SnifferPlugin> CreateARP();
ptr<SnifferPlugin> CreateIP();
ptr<SnifferPlugin> CreateICMP();
ptr<SnifferPlugin> CreateUDP();
ptr<SnifferPlugin> CreateIPX();
ptr<SnifferPlugin> CreateNetBEUI();


long GetEtherType(WORD w);

} // Snif::
