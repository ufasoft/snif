/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#pragma once

#if UCFG_XML
#	include <el/xml.h>
#endif

#include "standard-plugin.h"
#include "sniffeng.h"

#include "tcp-itf.h"

#include "params.h"

namespace Snif {

const DWORD TCPDUMP_MAGIC = 0xa1b2c3d4;

class CTcpAnalyzer;
class TcpFlowPlugin;
class ArpPacket;
class CTcpMan;
class TcpObj;
class TcpPacket;
typedef UInt64 tcppos_t;

class ITcpConnection
#if UCFG_SNIF_PACKET_CAPTURE
	:	public PluginPacket
#else
	:	public Object
#endif
{
public:
	virtual tcppos_t GetInPos() =0;
	virtual tcppos_t GetOutPos() =0;
	virtual ConstBuf GetInData() =0;
	virtual ConstBuf GetOutData() =0;
	virtual IPEndPoint GetSrcEndPoint() =0;
	virtual IPEndPoint GetDstEndPoint() =0;
	virtual void DiscardIn(DWORD size) =0;
	virtual void DiscardOut(DWORD size) =0;
	virtual bool GetWasSYN() =0;
	virtual void Delete() =0;
};

struct CSeqData {
	UInt32 m_seq;
	Blob m_data;

	CSeqData(UInt32 seq, const Blob& data)
		:	m_seq(seq)
		,	m_data(data)
	{}
};

class CTcpStream {
public:
	int m_packetsAfterHole;
	UInt32 m_seq;
	UInt32 m_finSeq;
	tcppos_t m_pos;
	Blob m_blob;

	typedef vector<CSeqData> CFrames;
	CFrames m_frames;

	CBool m_bFIN,
		m_bClosed;		    
	CBool m_bSeqInited;
	CBool IsOut;

	CTcpStream()
		:	m_pos(0)
		,	m_packetsAfterHole(0)
	{}

	void Delete() {
		m_blob.Size = 0;
		m_frames.clear();
	}

	void CheckFragments();
	bool CheckHoles(bool bAllHoles = false);
};

class CConnID {
public:
	IPEndPoint m_ippMin,
		m_ippMax;

	CConnID(const IPEndPoint& ipp0, const IPEndPoint& ipp1)
		:	m_ippMin(ipp0)
		,	m_ippMax(ipp1)
	{
		if (ipp1 < ipp0)
			swap(m_ippMin,m_ippMax);
	}

	bool operator==(const CConnID& id) const {
		//!!!R return !memcmp(this,&id, sizeof(CConnID));
		return m_ippMin==id.m_ippMin && m_ippMax==id.m_ippMax;
	}

	bool operator<(const CConnID& id) const {
		//!!!R return memcmp(this, &id, sizeof(CConnID)) < 0;
		 return m_ippMin<id.m_ippMin || (m_ippMin==id.m_ippMin && m_ippMax<id.m_ippMax);
	}
};

//!!!R #pragma pack(pop)

} namespace EXT_HASH_VALUE_NS {
inline size_t hash_value(const Snif::CConnID& id) {
	return hash_value(id.m_ippMin)+hash_value(id.m_ippMax);
}
}

EXT_DEF_HASH(Snif::CConnID)

namespace Snif {

#ifdef _DEBUG

inline ostream& operator<<(ostream& os, const CConnID& connID) {
	return os << connID.m_ippMin << " - " << connID.m_ippMax;
}

#endif

class CTcpConnection : public ITcpConnection, public ISimpleTcpConnection {
	DECLARE_DYNCREATE(CTcpConnection)
public:
	typedef Interlocked interlocked_policy;


	CTcpStream m_out, m_in;
	CTcpStream *m_arStm;

	IPEndPoint m_source,
		m_dest;
	Snif::Direction Direction;
	/*!!!R	vector<DATE> m_inTimes,
	m_outTimes;
	*/
#if UCFG_SNIF_USE_ODDB
	COdObject m_ob;
#endif
	DateTime m_dt;
	//!!!  int m_nOrder;
	CPointer<TcpObj> m_pPlugin;
	CPointer<IDisconnectable> m_implConn;
	CBool m_bCorrectlyClosed;
	CBool m_bWasSYN,
		m_bDeleted;

	CTcpConnection(TcpObj *pPlugin = 0)
		:	m_pPlugin(pPlugin)
		,	m_arStm(&m_out)
		,	Direction(Snif::Direction::Unknown)
	{
		m_out.IsOut = true;
	}

	~CTcpConnection() {
	}

	CConnID GetConnID() { return CConnID(m_source,m_dest); }

	struct SProcessResult {
		bool m_bUpdated;

		SProcessResult()
			:	m_bUpdated(false)
		{}
	};

	SProcessResult ProcessStream(CTcpStream& stream, TcpPacket *iTP);
	void ProcessPacket(TcpPacket *iTP);

	void CloseEx();

	String GetField(RCString name) {
		if (name == "Timestamp")
			return m_dt.ToLocalTime().ToString(Microseconds());
		else if (name == "SourceIP")
			return m_source.Address.ToString();
		else if (name == "SourcePort")
			return Convert::ToString(m_source.Port);
		else if (name == "DestIP")
			return m_dest.Address.ToString();
		else if (name == "DestPort")
			return Convert::ToString(m_dest.Port);
		else
			Throw(E_EXT_ItemNotFound);
	}

	void Load() {
#if UCFG_SNIF_USE_ODDB
		m_dt = (FILETIME&)AsCurrency(m_ob.GetProperty("Timestamp"));
		m_source = IPEndPoint(htonl(Convert::ToInt32(m_ob.GetProperty("SourceIP"))), (WORD)Convert::ToInt32(m_ob.GetProperty("SourcePort")));
		m_dest = IPEndPoint(htonl(Convert::ToInt32(m_ob.GetProperty("DestIP"))), (WORD)Convert::ToInt32(m_ob.GetProperty("DestPort")));
		m_in.m_blob = m_ob.GetProperty("In");
		m_out.m_blob = m_ob.GetProperty("Out");
#endif
	}

	tcppos_t GetInPos() override { return m_in.m_pos; }
	tcppos_t GetOutPos() override { return m_out.m_pos; }

	ConstBuf GetInData() override { return m_in.m_blob; }
	ConstBuf GetOutData() override { return m_out.m_blob; }

	void Save();

	IPEndPoint GetSrcEndPoint() override { return m_source; }
	IPEndPoint GetDstEndPoint() override { return m_dest; }

	DWORD GetSrcIP() { return m_source.Address.GetIP(); }
	DWORD GetDstIP() { return m_dest.Address.GetIP(); }
	WORD GetSrcPort() { return m_source.Port; }
	WORD GetDstPort() { return m_dest.Port; }

	void DiscardIn(DWORD size) override {
		int span = min((size_t)size, (size_t)m_in.m_blob.Size);
		m_in.m_pos += span;
		m_in.m_blob.Replace(0, span, ConstBuf(0, 0));
	}

	void DiscardOut(DWORD size) override {
		int span = min((size_t)size, (size_t)m_out.m_blob.Size);
		m_out.m_pos += span;
		m_out.m_blob.Replace(0, span, ConstBuf(0,0));
	}

	bool GetWasSYN() override { return m_bWasSYN; }

	void Delete() override;
	void Disconnect();

	Snif::Direction GetDirection() {
		return Direction;
	}

#if UCFG_OLE
	Blob GetDataBlob() {
		Blob blob = m_in.m_blob;
		blob.Replace(blob.Size,0,m_out.m_blob);
		return blob;
	}

	void AddFieldInfo(CBag& bag, RCString s) {
		bag.Add(s);
	}

#if UCFG_SNIF_PACKET_CAPTURE
	void Info(CBag& bag) override {
		CBag row;
		AddFieldInfo(row,"Source Port " + Convert::ToString(GetSrcPort()));
		AddFieldInfo(row,"Destination Port " + Convert::ToString(GetDstPort()));
		row.Add((CBag("Incoming traffic"), COleVariant(),COleVariant(m_in.m_blob)));
		row.Add((CBag("Outgoing traffic"), COleVariant(),COleVariant(m_out.m_blob)));
		bag.Add((CBag("TCP"), row));
	}
#endif
#endif
private:
	void UpdatedConnection();
	void FoundHole();
};

} namespace Ext {
template <> struct ptr_traits<Snif::CTcpConnection> {
	typedef Interlocked interlocked_policy;
};
} // Ext::
namespace Snif {

class TcpConnection;

class AFX_SNIF_CLASS TcpStream {
public:
	TcpConnection& m_conn;

	TcpStream(TcpConnection& conn, bool bOut)
		:	m_conn(conn)
		,	m_bOut(bOut)
		,	m_pos(0)
	{}

	tcppos_t GetPos() { return m_pos; }
	ConstBuf GetData();
	void Skip(size_t bytes);
private:
	tcppos_t m_pos;
	bool m_bOut;
};

class AFX_SNIF_CLASS TcpConnection : public Object {
public:
	ptr<ITcpConnection> m_iConn;
	CTcpMan *m_tcpMan;
	
	TcpStream InStream,
		OutStream;

	TcpConnection()
		:	InStream(_self, false)
		,	OutStream(_self, true)
	{}

	void Init(CTcpMan& tcpMan, CTcpAnalyzer& an, ITcpConnection *conn) {
		m_tcpMan = &tcpMan;
		m_an = &an;
		m_iConn = conn;
	}

	IPEndPoint GetSrcEndPoint();
	IPEndPoint GetDstEndPoint();

	bool GetWasSYN() { return m_iConn->GetWasSYN(); }
	void Delete();
private:
	CTcpAnalyzer *m_an;
};

class AFX_SNIF_CLASS CTcpAnalyzer {
public:
	typedef std::unordered_map<ptr<ITcpConnection>, ptr<TcpConnection> > CMapConn;
	CMapConn m_mapConn;

	bool m_bJustCreated;
	static vector<CTcpAnalyzer*> m_all;

	CTcpAnalyzer();
	virtual ~CTcpAnalyzer();
	void Unbind();
	
	TcpConnection *Find(ITcpConnection *conn) {
		CMapConn::iterator it = m_mapConn.find(conn);
		return it!=m_mapConn.end() ? it->second.get() : 0;
	}
protected:
	virtual ptr<TcpConnection> CreateTcpConnectionObject(CTcpMan& tcpMan, ITcpConnection *conn) {
		ptr<TcpConnection> r = new TcpConnection;
		r->Init(tcpMan, _self, conn);
		return r;
	}
	virtual void CreatedConnection(TcpConnection *conn) {}   
	virtual void ClosedConnection(TcpConnection *conn) {} 
	virtual void UpdatedConnection(TcpConnection *conn) {}
	virtual void FoundHole(TcpConnection *conn) {}

	friend class TcpFlowPlugin;
};


AFX_SNIF_CLASS int __stdcall PcapCheck(int r);

class AFX_SNIF_CLASS CPacketProvider {
public:
	CBool m_bEOF;
	CPointer<pcap_t> m_pd;
	UInt64 Order;
	BYTE m_medium;

	CPacketProvider(pcap_t *pd = 0)
		:	m_pd(pd)
		,	Order(1)
		,	m_medium(0)
	{
#if UCFG_UPGRADE
		EnsureUpgrade();
#endif
	}

	virtual ~CPacketProvider() 	{
		if (m_pd)
			pcap_close(m_pd); //!!!
	}

	struct PacketInterface {
		String Name, Description;
		vector<CIpParams> Params;
	};

	static vector<PacketInterface> GetAllInterfaces();

	void OpenLive(RCString name);
	virtual ILP_SnifferPacket GetNext(bool bAsync = false);
	virtual int Loop(IProcessPacket *iProcessPacket, int cnt = -1);
	int Loop(int cnt = -1);
	virtual void BreakLoop();
	virtual void SetUserFilter(RCString s);
	bpf_program Compile(RCString exp);
	void SetFilter(bpf_program& fcode);

	void Send(const ConstBuf& mb) {
		PcapCheck(::pcap_sendpacket(m_pd, mb.P, mb.Size));
	}
protected:
	static void AdjustPacketMedium(const u_char *&data, int& len, byte& medium);
	virtual void OnPacket(const pcap_pkthdr& hdr, const ConstBuf& mb) {}
private:
	static void __cdecl PcapHandlerProcessPacket(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt_data);
	static void __cdecl PcapHandler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt_data);	
};

class AFX_SNIF_CLASS CFilePacketProvider : public CPacketProvider {
public:
	FileStream m_stm;
	size_t m_i;

	CFilePacketProvider(pcap_t *p);
	CFilePacketProvider()
		:	m_i(0)
	{}

	CFilePacketProvider(RCString filename)
		:	m_stm(filename, FileMode::Open, FileAccess::Read)
	{}

	static CFilePacketProvider* __stdcall FromFilename(RCString filename);
};

class AFX_SNIF_CLASS CFilesPacketProvider : public CPacketProvider {
	String m_sUserFilter;
public:
	CBool m_bBreak;
	deque<String> m_filenames;
	
	mutex m_csProv;
	unique_ptr<CPacketProvider> m_prov;

	void BreakLoop();
	ILP_SnifferPacket GetNext(bool bAsync = false);
	int Loop(IProcessPacket *iProcessPacket, int cnt = -1);
	void SetUserFilter(RCString s);
};

AFX_SNIF_CLASS CFilePacketProvider* __stdcall CreateNetMonPacketProvider(RCString filename);
AFX_SNIF_CLASS CFilePacketProvider* __stdcall CreateNetxrayPacketProvider(RCString filename);
AFX_SNIF_CLASS CFilePacketProvider* __stdcall CreateCommViewPacketProvider(RCString filename);

#if UCFG_XML && UCFG_WIN32
class AFX_SNIF_CLASS CXmlPacketProvider : public CFilePacketProvider {
	XmlDocument m_dom;
	XmlNodeList m_nodes;
public:
	CXmlPacketProvider(RCString filename);
	ILP_SnifferPacket GetNext(bool bAsync);
};
#endif

class AFX_SNIF_CLASS CCapturePacketProvider : public CPacketProvider
{
public:
	CCapturePacketProvider(const char *devName = 0);
	//!!!  CPacket GetNext(bool bAsync = false);
};

class AFX_SNIF_CLASS CCapturePacketProviderEx : public CPacketProvider {
	//  CSniffEng m_eng;
public:
	CCapturePacketProviderEx();
	ILP_SnifferPacket GetNext(bool bAsync = false);
};


class CConnCompare {
public:
	bool operator()(ITcpConnection *c1, ITcpConnection *c2) const {
		return c1 < c2;
	}
};

class ITcpFlowPlugin : public Object {
public:
	virtual void CreatedConnection(ITcpConnection *conn) =0;
	virtual void ClosedConnection(ITcpConnection *conn, int timeOut) =0;
	virtual void UpdatedConnection(ITcpConnection *conn) =0;
	virtual void FoundHole(ITcpConnection *conn) =0;
};

class ITcpPlugin : public SnifferPlugin {
public:
	ptr<IcmpObj> m_icmpObj;

	virtual void SubscribeFlow(ITcpFlowPlugin *p) =0;
};

ptr<ITcpPlugin> CreateTCP();


//!!!typedef vector<ptr<TcpConnection> > CConnVector;

class IArpHook {
public:
	virtual void OnReceivedArp(ArpPacket *arp) =0;
};

class IIpHook {
public:
	virtual bool OnReceivedIp(IpPacket *ip) =0;
};

class ArpPacket : public PluginPacket {
	DECLARE_DYNCREATE(ArpPacket)

#if UCFG_OLE
	void Info(CBag& bag) override;
#endif
public:
	typedef ArpPacket class_type;

	WORD get_OpCode() { return GetHWord(6); }
	void put_OpCode(WORD w) { return SetHWord(6,w); }
	DEFPROP(WORD,OpCode);

	MacAddress get_SenderMAC() { return MacAddress(ConstBuf(GetChunk(8, 6), 6)); }
	void put_SenderMAC(MacAddress mac) { SetChunk(8, ConstBuf(&mac.m_n64, 6)); }
	DEFPROP(MacAddress, SenderMAC);

	IPAddress get_SenderPA() { return IPAddress(GetDWord(14)); }
	void put_SenderPA(const IPAddress& ip) { SetHDWord(14, ip.GetIP()); }
	DEFPROP(IPAddress, SenderPA);

	MacAddress get_TargetMAC() { return MacAddress(ConstBuf(GetChunk(18, 6), 6)); }
	void put_TargetMAC(MacAddress mac) { SetChunk(18, ConstBuf(&mac.m_n64, 6)); }
	DEFPROP(MacAddress,TargetMAC);

	IPAddress get_TargetPA() { return IPAddress(GetDWord(24)); }
	void put_TargetPA(const IPAddress& ip) { SetHDWord(24, ip.GetIP()); }
	DEFPROP(IPAddress, TargetPA);
};

class ArpObj : public SnifferPlugin {
public:
	ArpObj() {
		m_name = "ARP";
		m_layer = PROTO_ARP;
		m_pPacketClass = RUNTIME_CLASS(ArpPacket);
	}

	vector<IArpHook*> m_subscribers;

	void ProcessPacket(PluginPacket *iPacket) override;
	void SubscribeArp(IArpHook *hook) { m_subscribers.push_back(hook); }
	void UnsubscribeArp(IArpHook *hook) { Ext::Remove(m_subscribers, hook); }
	ptr<ArpPacket> ComposePacket();

	void Bind() override {
		m_binder->m_mapEthernet[ETHERTYPE_ARP].insert(this);
	}

	void UnbindPlugin() override {
		m_binder->m_mapEthernet[ETHERTYPE_ARP].erase(this);
	}
};

struct CIpSnap {
	UInt64 tcpPart;
	in_addr ip_src,ip_dst;	/* source and dest address */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
	u_int8_t	ip_tos;		/* type of service */
	u_int8_t	ip_p;		/* protocol */
};

inline bool operator==(const CIpSnap& x, const CIpSnap& y) {
	return !memcmp(&x, &y, sizeof(CIpSnap));
}

} namespace EXT_HASH_VALUE_NS {
inline size_t hash_value(const Snif::CIpSnap& ipSnap) {
	return hash_value(&ipSnap, sizeof(Snif::CIpSnap));
}
}

EXT_DEF_HASH(Snif::CIpSnap)
namespace Snif {


class IpObjBase : public MACExObj {
	typedef MACExObj base;
public:
	vector<IIpHook*> m_subscribers;
	CBool m_bSkipDuplicates;

	IpObjBase(byte medium)
		:	base(medium)
	{}
protected:
	vector<long> GetProvided() override {
		vector<long> ar;
		ar.push_back(PROTO_TCP);
		ar.push_back(PROTO_UDP);
		ar.push_back(PROTO_ICMP);
		ar.push_back(PROTO_GRE);
		return ar;
	}

	AnalyzerBinder::Map *GetProtocolMap() override {
		return &m_binder->m_mapIp;
	}

	void SubscribeHook(IIpHook *hook) { m_subscribers.push_back(hook); }
	void UnsubscribeHook(IIpHook *hook) { Ext::Remove(m_subscribers, hook); }
};


extern AFX_SNIF_CLASS int g_opt_LogLevel;
extern AFX_SNIF_CLASS bool g_opt_PrintAsDateTime;

class AFX_SNIF_CLASS CProtoEngBase : public CFilterBind {
	void SetCombinedFilter();
public:
	static CProtoEngBase *s_pMain;

	static CBool s_bEnableLog;
	String m_sLogDir;
	unique_ptr<CPacketProvider> m_prov;
	ptr<SnifferPlugin> m_netbeui;
	String m_sIPFilter,
		m_sUserFilter;

	CProtoEngBase(bool bEnabled)
		:	CFilterBind(bEnabled)
	{
		TRC(0, "");
	}

	~CProtoEngBase() {
		if (s_pMain == this)
			s_pMain = nullptr;
	}

	void MakeMain();
	void LoadFilter();
	void SetUserFilter(RCString s);
	void SetIPFilter(RCString s);
};

class AFX_SNIF_CLASS CProtoEng : public CProtoEngBase, public AnalyzerBinder, public IProcessPacket {
	//!!!ptr<SnifferSite> m_iSink;
	ptr<MACObj> m_eth,
		m_ppp,
		m_slip,
#if UCFG_SNIF_WIFI
		m_802_11,
#endif
		m_tokenRing;
	ptr<MACObj> m_pppoe;
	
	ptr<IpObjBase> m_ip;
#if UCFG_SNIF_IPV6
	ptr<IpObjBase> m_ip6;
#endif

	ptr<ITcpPlugin> m_tcp;
	ptr<ArpObj> m_arp;
protected:
	virtual bool ProcessOption(char opt, const char *optarg) { return false; }
public:
	String m_options;
	int m_nAdapter;
	CBool m_bAllowOtherOptons;

	enum EOnlyEthernet //!!! and TokenRing
	{};

	CProtoEng(EOnlyEthernet);
	CProtoEng(bool bEnabled);
	virtual void PrintUsage();
	void ParseCommandLine(int argc, char *argv[], bool bCreateArpSpoofer = true);
	void ParseCommandLine(bool bCreateArpSpoofer = true) { ParseCommandLine(AfxGetCApp()->Argc, AfxGetCApp()->Argv, bCreateArpSpoofer); }
	bool ProcessPacket(SnifferPacket& sp);
	int Loop(const TimeSpan& timespan);
	void BreakLoop() {
		if (m_prov.get())
			m_prov->BreakLoop();
#if UCFG_SNIF_USE_PCAP
		if (SnifEngBase::s_I)
			SnifEngBase::s_I->BreakLoop();
#endif

	}
	//!!!ptr<Adapter> GetAdapterOf(PluginPacket *pp) { return m_adapters[pp->GetRootPacket()->GetAdapter()]; }
	ptr<ArpObj> GetArpObj();
	ptr<IpObjBase> GetIpObj();
#if UCFG_SNIF_IPV6
	ptr<IpObjBase> GetIp6Obj();
#endif
	ptr<MACObj> GetMACObj(BYTE medium);
	ptr<ITcpPlugin> GetTcpObj();
};

extern bool g_bArpSpoofingEnabled;

class AFX_SNIF_CLASS CTcpMan
#if UCFG_SNIF_PACKET_CAPTURE
	:	public CProtoEng
#endif
{

	/*!!!  CComPtr<ISnifferPlugin> CreatePlugin(const CLSID& clsid)
	{
	CComPtr<IClassFactory> cf;
	AfxDllGetClassObject(clsid,IID_IClassFactory,(void**)&cf);
	CComPtr<ISnifferPlugin> r;
	OleCheck(cf->CreateInstance(0,IID_ISnifferPlugin,(void**)&r));
	return r;
	}*/
public:
	ptr<ITcpFlowPlugin> m_tcpFlowPlugin;

#if !UCFG_SNIF_PACKET_CAPTURE
	DateTime m_dtLastPacket;
	static bool s_bEnableLog;
#endif

	//!!!	CPointer<CTcpAnalyzer> m_proxyAnalyzer;

	//!!!typedef map<CComPtr<ITcpConnection>,CConnVector,CConnCompare > CMapConn;
	//!!!CMapConn m_mapConn;

	CTcpMan();
	void UpdatePos(ITcpConnection *conn);
};

class IArpNotify {
public:
	virtual void OnIP(DWORD ip) =0;
};

struct CHostState {
	CBool m_bSpoof,
		m_bActive;
};

typedef map<IPAddress, CHostState> CMapHostState;

#if UCFG_GUI
#endif

#ifdef WIN32
extern AFX_SNIF_CLASS CThreadRef g_trWpcap;
extern AFX_SNIF_CLASS CAppBase *g_wpcapApp;
AFX_SNIF_CLASS CAppBase * __stdcall GetWpcapApp();
AFX_SNIF_CLASS void __cdecl WpcapCloseAll();
#endif

class AFX_SNIF_CLASS CHostResolver : public CThreadRef {
	CUsingSockets m_usingSockets;
public:
	struct AFX_SNIF_CLASS HostInfo {
		IPAddress m_ip;
		String m_name;

		HostInfo(RCString n = "")
			:	m_name(n)
		{}

		String ToString();
	};

	static CHostResolver *I;
	static unique_ptr<CHostResolver> IOwner;

	typedef map<IPAddress, HostInfo> HostMap;
	HostMap m_hosts;
	set<IPAddress> m_setInResolving;

	CHostResolver();
	~CHostResolver();
	static CHostResolver& __stdcall Get();
	HostInfo Resolve(const IPAddress& ip);
	static String __stdcall Resolve(const IPEndPoint& hp);
	void SaveDB();
	void LoadDB();
};

class CImporter {
public:
	virtual bool ImportPacket(SnifferPacket *sp) =0;
};

AFX_SNIF_CLASS void __stdcall ImportSnifferFile(RCString filename, CImporter& importer);
AFX_SNIF_CLASS void __stdcall WpcapFileImport(CImporter& importer);

AFX_SNIF_CLASS extern int g_verbose;
AFX_SNIF_CLASS extern mutex g_mtxSnif;

#pragma pack(push, 1)

	struct CTcpPseudoHeader {
		UInt32 m_src,
			m_dst;
		byte m_zero;
		byte m_proto;
		UInt16 m_len;

		CTcpPseudoHeader(UInt32 src, UInt32 dst, byte proto, UInt16 len)
			:	m_src(src)
			,	m_dst(dst)
			,	m_zero(0)
			,	m_proto(proto)
			,	m_len(len)
		{}
	};

#pragma pack(pop)



} // Snif::

