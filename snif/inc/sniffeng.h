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
#endif

#ifdef _WIN32
#	define NWF_EXTAP_SUPPORTED

#	include <ntddndis.h>
#	include <net/bpf.h>

#	include <el/libext/win32/ext-win.h>
#endif

#include "snifferstructs.h"

#if !UCFG_SNIF_USE_PCAP
#	include "packet.h"
#endif

#include <el/libext/ext-net.h>


#if UCFG_UPGRADE
#	include <el/comp/upgrade.h>
#endif

#ifdef _WIN32
#	include <el/comp/e-iphlpapi.h>
#endif

#include "params.h"

//!!! #include "packet.h"

#include "pppex.h"

#if UCFG_SNIF_WIFI
#	include <windot11.h>

#	include <el/comp/ext-wlan.h>
#	include "wificard.h"
#endif	


#ifndef WIN32

enum NDIS_MEDIUM {
    NdisMedium802_3,
    NdisMedium802_5,
    NdisMediumFddi,
    NdisMediumWan,
    NdisMediumLocalTalk,
    NdisMediumDix,     
    NdisMediumArcnetRaw,
    NdisMediumArcnet878_2,
    NdisMediumAtm,
    NdisMediumWirelessWan,
    NdisMediumIrda,
    NdisMediumBpc,
    NdisMediumCoWan,
    NdisMedium1394,
    NdisMediumInfiniBand,
    NdisMediumTunnel,
    NdisMediumNative802_11,
    NdisMediumLoopback,
    NdisMediumWiMAX,
    NdisMediumIP,
    NdisMediumMax  
};

#endif // WIN32



const long  PROTO_ETHERNET  = 0,  // Must be compatible with NdisMeduim
PROTO_TOKENRING = 1,
PROTO_WAN       = 3,

PROTO_IEEE802_11_RADIO = 0x10, //!!!

PROTO_ATM = 8,

PROTO_IP        = 32,
PROTO_IPX       = 33,
PROTO_NETBEUI   = 34,
PROTO_TCP       = 35,
PROTO_UDP       = 36,
PROTO_ICMP      = 37,
PROTO_ARP       = 38,
PROTO_X25L3     = 39,
PROTO_TRAIN     = 40,
PROTO_CGMP      = 41,
PROTO_3C_NBP_DGRAM = 42,
PROTO_DEC       = 43,
PROTO_DNA_DL    = 44,
PROTO_DNA_RC    = 45,
PROTO_DNA_RT    = 46,
PROTO_LAT       = 47,
PROTO_DEC_DIAG  = 48,
PROTO_DEC_CUST  = 49,
PROTO_DEC_SCA   = 50,
PROTO_ETHBRIDGE = 51,
PROTO_REVARP    = 52,
PROTO_DEC_LB    = 53,
PROTO_ATALK     = 54,
PROTO_SNA       = 55,
PROTO_AARP      = 56,
PROTO_VLAN      = 57,
PROTO_SNMP      = 58,
PROTO_WCP       = 59,
PROTO_IPv6      = 60,
PROTO_PPP       = 61,
PROTO_MPLS      = 62,
PROTO_MPLS_MULTI = 63,
PROTO_PPPOED    = 64,
PROTO_PPPOES    = 65,
PROTO_EAPOL     = 66,
PROTO_LOOP      = 67,
PROTO_GRE        = 68,
PROTO_IP6        = 69,

PROTO_RAW       = 101,
PROTO_NULL      = 102,
PROTO_SLIP      = 103,


PROTO_IEEE802_11 = DLT_IEEE802_11, //!!! 105


PROTO_UNKNOWN   = -1;

namespace Snif {

class CFilterBind;
//!!!class CLocalSnifEng;

class CSnifEng;


class Adapter;

/*!!!R
enum EAdapterType
{
	ADTYPE_LOCAL,
	ADTYPE_WIFI,
	ADTYPE_REMOTE
};*/

class CAdapterDesc {
public:
	String Name,
		Description,
		GuidName;
	//	String DeviceInstanceId;
	CBool m_bWan;
	CBool m_bBinded;
	BYTE m_originalMedium;
	byte m_medium;
	BYTE m_nDevice;
	//!!!	BYTE m_nBindedAdapter;
//!!!R	EAdapterType Type;
	String InstanceID;
	//	vector<String> HardwareIDs,
	//		              CompatibleIDs;

#if UCFG_SNIF_WIFI
	CBool m_bWlan;
	class WlanInterface WlanInterface;
	ptr<CWifiCard> WifiCard;
#endif

	CAdapterDesc()
		:	m_originalMedium(255)
		,	m_medium(NDIS_MEDIUM(255))
		,	m_nDevice(BYTE(-1))
//!!!		,	Type(ADTYPE_LOCAL)
	{}
};

class CIpParams {
public:
	IPAddress m_addr,
		m_netmask,
		m_broadaddr,
		m_dstaddr;
};

class AFX_PACKET_CLASS CBpfProgram : public Object, public bpf_program
#if UCFG_SNIF_REMOTE
	, public CPersistent
#endif
{
public:
	typedef Interlocked interlocked_policy;

	CBpfProgram() {
		bf_len = 0;
		bf_insns = 0;
	}

	CBpfProgram(const CBpfProgram& p) {
		bf_insns = 0;
		operator=(p);
	}

	~CBpfProgram() {
		Destroy();
	}

	void Destroy() {
		delete exchange(bf_insns,(bpf_insn*)0);
	}

	CBpfProgram& operator=(const bpf_program& fp);
	CBpfProgram& operator=(const CBpfProgram& fp) { return operator=((bpf_program&)fp); }

	static CBpfProgram __stdcall All();

#if UCFG_SNIF_REMOTE
	void Write(BinaryWriter& wr) const override;
	void Read(const BinaryReader& rd) override;
#endif
};

interface IProcessPacket {
	virtual bool ProcessPacket(SnifferPacket& sp) =0;
};

class CSnifCallback : public IProcessPacket {
public:
	virtual bool OnCheckBreak() { return false; }
	virtual void OnDropped(DWORD dropped) {}
	virtual bool ProcessPacket(SnifferPacket& snifPacket) { return false; }
};

class AFX_PACKET_CLASS CAdapterFilter
#if !UCFG_SNIF_USE_PCAP
	:	public ADAPTER
#endif
{
	void CommonInit();
public:
	//!!!D	mutex m_cs;
	//!!!D	size_t m_maxQueueSize;
	bool m_bOverflow;

	typedef CMTQueue<ILP_SnifferPacket> CPacketQueue;
	CPacketQueue m_queue;
	int m_nAccepted;
	CPointer<ThreadBase> LoopingThread;
	CPointer<CSnifCallback> Callback;

	CEvent m_evRead;
	ptr<CBpfProgram> m_bpfProgram;
	vector<Adapter*> m_arAdapter;
	bool m_bLooped;
	const BYTE m_medium;
	CPointer<CFilterBind> m_bind;

	CAdapterFilter(BYTE medium);
	CAdapterFilter(Adapter *ad);
	virtual ~CAdapterFilter();
	//!!!  void Bind();
	void Unbind();
	void FilterPacket(SnifferPacket *sp);
	void SetFilter(bpf_program& bpf);
	virtual void OnReceived(SnifferPacket *sp);
	int ReadOp(int cnt, CSnifCallback& cb);
	void CheckOverflow();
protected:
	bool	m_bResetted;

};


class AFX_PACKET_CLASS CFilterBind {
public:
	typedef vector<CFilterBind*> CAllBinds;
	static CAllBinds s_all;

	DateTime m_dtLastPacket;
	DateTime m_onTimerPrev;
	TimeSpan m_timerPeriod;

	CBool m_bEnabled,
		m_bLocal,
		m_bDirectThread;

	typedef vector<CAdapterFilter*> CFilters;
	CFilters m_filters;

	vector<CFilters> m_medium2filters;

	CFilterBind(bool bEnabled, bool bSync = true);
	virtual ~CFilterBind();
	void Unbind();
	virtual void OnFilterTimer() {}
	void Add(CAdapterFilter *f);
	void Remove(CAdapterFilter *f);
	void ProcessFilters(byte medium, SnifferPacket *sp, Adapter *ad);
private:
	bool m_bSync;
};

extern AFX_PACKET_CLASS mutex g_mtxSnifEng;
extern CFilterBind g_packetFB;

ENUM_CLASS(EAdapterType) {
	Local,
	Remote,
	Wifi,
	LegacyWifi
} END_ENUM_CLASS(EAdapterType);

class AFX_PACKET_CLASS Adapter : public Thread {		// Thread can be used only in some descendats, but we common base as Object
	typedef Thread base;

	static int s_id;
protected:
	CBool m_bEnabled;
public:
	typedef Adapter class_type;

	//!!!	int m_id;
	size_t Index;
	DWORD m_oidCurrentAddress;
	CAdapterDesc m_desc;
	bool m_bLoopback;
	EAdapterType Type;
	CBpfProgram m_bpf;

	static bool s_bEnableByDefault;

	Adapter(CThreadRef *tr = 0);
	virtual ~Adapter() {}
	virtual void OnCreated(CSnifEng& eng) {}
	virtual int ReadOp(int cnt, CSnifCallback& cb) = 0;

	virtual bool get_MonitorModeP() { return false; }
	virtual void put_MonitorModeP(bool v) { Throw(E_NOTIMPL); }
	DEFPROP_VIRTUAL(bool, MonitorModeP);	

	virtual NDIS_MEDIUM GetMedium() { return get_MonitorModeP() ? NdisMediumNative802_11 : (NDIS_MEDIUM)m_desc.m_medium; }
	virtual vector<CIpParams> GetIpParams() { Throw(E_NOTIMPL); }
	virtual void SendEx(const Buf& mb, bool bDefer) { Throw(E_NOTIMPL); }
	
	void Send(const ConstBuf& mb, bool bDefer = false);
	void Send(const vector<Blob>& ar);

	virtual class MacAddress get_MacAddress() { Throw(E_NOTIMPL); }
	DEFPROP_VIRTUAL_GET(class MacAddress, MacAddress);

	bool get_Enabled() { return m_bEnabled; }
	virtual void put_Enabled(bool v) { m_bEnabled = v; }
	DEFPROP_VIRTUAL(bool, Enabled);

	virtual UInt64 get_LinkSpeed() { return 10000000; }
	DEFPROP_VIRTUAL_GET(UInt64, LinkSpeed);

	virtual UInt64 get_RcvNoBuffer() { return 0; }
	DEFPROP_VIRTUAL_GET(UInt64, RcvNoBuffer);
};

class AFX_PACKET_CLASS CSnifEng : public Thread {
public:
	static volatile Int32 s_nDriverLost;
	static volatile Int32 s_nUserLost;
	static volatile Int32 s_nUserLostSum;

	static vector<ptr<CSnifEng> > s_all;
	static CPointer<ThreadBase> s_LoopingThread;

	CBool m_bLocal;
	bool m_bEnabled;
	CInt<DWORD> m_nLost,
		m_nError;
	CInt<UInt64> m_nOrder;
	CBool m_bUpdated;
	exception_ptr m_exc;

	~CSnifEng();
	void Dispose();		// base::Delete()  hase other semantics
	virtual String GetHostName() { return "localhost"; }

	typedef vector<ptr<Adapter> > CAdapters;
	
	CAdapters GetAdapters() const {
		EXT_LOCK (m_cs) {
			return m_adapters;
		}
	}

	static int __stdcall Loop(const TimeSpan& timespan);
	static void __stdcall AllLoadSettings();
	static void __stdcall AllSaveSettings();
	void Process(SnifferPacket *sp, Adapter *ad);
#ifdef WIN32
	virtual void LoadSettings(RegistryKey& key);
	virtual void SaveSettings(RegistryKey& key);
#endif
protected:
	mutable mutex m_cs;
	CAdapters m_adapters;

	CSnifEng();
};

class SnifEngBase : public CSnifEng {
public:
	static mutex s_mtx;
	static SnifEngBase *s_I;
	CBool m_bAdaptersOpened;
	bool m_bBindWifi;

	CInt<UInt64> PacketCount;

	SnifEngBase()
		:	m_bBindWifi(true)
	{
	}

	virtual void Create(bool bEnabled = true) {}
	virtual void OpenAdapters() =0;
	virtual void BreakLoop() {}
};



//!!!extern CPointer<CLocalSnifEng> g_pSniffEng;

AFX_PACKET_CLASS SnifEngBase& __stdcall SnifEng(bool bBindWifi = true);
//!!!R AFX_PACKET_CLASS void __stdcall SetSniffEng(CLocalSnifEng *eng);

class INotifyHook {
public:
	virtual ~INotifyHook() {}
	virtual void OnNotifyHook() =0;
};



#if UCFG_EXTENDED
extern unique_ptr<CUpgrade> g_pUpgrade; 
#endif

void AFXAPI EnsureUpgrade();


AFX_PACKET_CLASS BYTE __stdcall DltToMedium(int linktype);
AFX_PACKET_CLASS int __stdcall MediumToDlt(BYTE medium);


AFX_PACKET_CLASS void AFXAPI InitPacketDll();

class Adapter;


#if !UCFG_SNIF_USE_PCAP

class AFX_PACKET_CLASS CRemoteSnifEng : public CSnifEng {
	CUsingSockets m_usingSockets;

	mutex m_csNotifyHook;
	CPointer<INotifyHook> m_iNotifyHook;
public:
	Socket m_sock;
	IPEndPoint m_hp;
	String m_login,
		m_password;

	CBool m_bAdaptersListed;

	String m_regSubkey;

	CThreadRef m_tr;

	CRemoteSnifEng();
	CRemoteSnifEng(RCString uri);
	~CRemoteSnifEng();

	String GetHostName() { return m_hp.Address.ToString(); }

	void Stop() override {
		m_tr.StopChilds();
		m_sock.Close();
		CSnifEng::Stop();
	}

	void SetNotifyHook(INotifyHook *i) {
		EXT_LOCK (m_csNotifyHook) {
			m_iNotifyHook = i;
		}
	}

	void Notify() {
		EXT_LOCK (m_csNotifyHook) {
			if (m_iNotifyHook)
				m_iNotifyHook->OnNotifyHook();
		}
	}

	void Connect(const IPEndPoint& hp, RCString login, RCString password);
	void Execute() override;
	void LoadSettings(RegistryKey& key);
	void SaveSettings(RegistryKey& key);

	friend class RemoteAdapter;
};

class CLocalSnifEng;

class CAdapterManager {
#if UCFG_SNIF_WIFI
	ptr<CWifiCard> CreateCardByIDs(DiDeviceInfo di, const vector<String>& ar);
#endif

protected:
	DWORD m_dwRes;

	CAdapterManager(CLocalSnifEng& eng)
		:	m_eng(eng)
	{}

	bool AllowedNDIS4or5(RCString upper);
	virtual bool AllowedUpper(RCString upper, CAdapterDesc& ad);
	virtual vector<CAdapterDesc> GetAdapters();
public:
	vector<CAdapterDesc> AdapterDescs;

	CLocalSnifEng& m_eng;

	virtual ~CAdapterManager();
	void Load();
	static unique_ptr<CAdapterManager> CreateObject(CLocalSnifEng& eng);
	virtual vector<CIpParams> GetIpParams(RCString iname);
	//!!!  virtual CAdapter *CreateAdapter();
};

class CCreateSendBufferWorkItem {
public:
	CEvent m_ev;
	byte m_nDevice;
};

class AFX_PACKET_CLASS CLocalSnifEng : public SnifEngBase {
public:
	static bool s_StartInSeparateThread;
	static bool s_LoopInSeparateThread;
	static volatile Int32 s_CaptureSemaphore;

	DWORD DriverVersion;
	CBool UseNdis6;		// can be inited oonly as paramener to SnifEng()
#if UCFG_SNIF_WIFI
	unique_ptr<WlanClient> WlanClient;
#endif

#ifdef _DEBUG
	CBool m_bDisableSend;
#endif

	CEvent m_evCreated;

	mutex m_csDriver;
	queue<CCreateSendBufferWorkItem*> m_workItems;
	CVirtualMemory m_vqh;
	size_t m_size;
	vector<CPointer<CInterModePacketQueue> > m_arSendQueues;
	size_t m_cbIMPQ;
	COvlEvent m_ovl,
		m_ovlReceive;
	vector<ptr<COvlEvent>> m_arOVL;
	File m_dev;
	//!!!  vector<CAdapterDesc> m_arDesc;

	CQueueHeader& get_Qh() { return *(CQueueHeader*)m_vqh.m_address; }
	DEFPROP_GET(CQueueHeader&, Qh);

	unique_ptr<CAdapterManager> m_pManager;
	bool m_bBreak;
	bool m_bWithoutDriver;
	CBool m_bWaiting;
	
	CEvent m_ev;

	CLocalSnifEng();
	~CLocalSnifEng();

	void Stop() {
		CSnifEng::Stop();
		m_ev.Set();
	}

	void CreateSendBuffer(int nDevice);
	void ProcessWorkItems();
	bool VerifyBinded(CAdapterDesc& ad);
	void RebindAdapters();
	int LoopPackets(int cnt, CSnifCallback& cb);
	bool WaitPackets();
	int ReadOp(int cnt, CSnifCallback& cb);
	void Create(bool bEnabled = true);
	void CreateAdapterObject(CAdapterDesc& ad);
	void OpenAdapters();
	void Loop(CSnifCallback& cb);
	void Execute() override;
	void ReadLoop(DWORD timeOut);
	CBlockHeader *GetNextBlock();
	void FreeLastBlock();
	void SendPacket(DWORD nAdapter, const Buf& mb, bool bDefer);
	void SendPackets(const ConstBuf& mb);
	size_t GetSize();
	size_t GetUsed();
	String QueryAdapterName(int nDevice);
	void TryBindToWlanInterface(CAdapterDesc& ad);
	Adapter *GetAdapter(byte nDevice);
protected:
	virtual void OnPacketCaptured(CBlockHeader *pBlock);
private:
	Adapter *m_tblDevice2Adapter[256];

	size_t m_nLastLen;
	CPppManager m_pppManager;
};

AFX_PACKET_CLASS CLocalSnifEng& AFXAPI LocalSnifEng();

class AFX_PACKET_CLASS LocalAdapter : public Adapter {
public:
	CLocalSnifEng& m_eng;

	LocalAdapter(CLocalSnifEng& eng)
		:	m_eng(eng)
	{
		Type = EAdapterType::Local;
	}

	int ReadOp(int cnt, CSnifCallback& cb);
	vector<CIpParams> GetIpParams();
	void SendEx(const Buf& mb, bool bDefer);
	void Send(const vector<Blob>& ar);
	class MacAddress get_MacAddress();
	void OnCreated(CSnifEng& eng);

	Blob QueryOID(DWORD oid, size_t size);
	DWORD QueryDWORD(DWORD oid);
	UINT64 QueryCounter(DWORD oid);

	template <typename T> void QueryStruct(DWORD oid, T& st) {
		memcpy(&st, QueryOID(oid, sizeof st).constData(), sizeof st);
	}

	void SetOID(DWORD oid, const ConstBuf& mb);

	template <typename T> void SetStruct(DWORD oid, T& st) {
		SetOID(oid, ConstBuf(&st, sizeof st));
	}

	UInt64 get_LinkSpeed();
	UInt64 get_RcvNoBuffer() { return QueryCounter(OID_GEN_RCV_NO_BUFFER); }

	UInt32 get_Filter() { return QueryDWORD(OID_GEN_CURRENT_PACKET_FILTER); }	
	void put_Filter(UInt32 v) { SetStruct(OID_GEN_CURRENT_PACKET_FILTER, v); }
	DEFPROP(UInt32, Filter);
protected:
	virtual void SetPromiscModeFilter();
	virtual void SetPacketFilter();
};

class AFX_PACKET_CLASS RemoteAdapter : public Adapter {
	CPointer<SocketThread> m_t;
public:
	CRemoteSnifEng& m_eng;

	RemoteAdapter(CRemoteSnifEng& eng, RCString uri = nullptr);
	~RemoteAdapter();

	void Execute() override;
	void Start();
	void Stop() override;

	bool get_Enabled() {
		return m_bEnabled;
	}

	void put_Enabled(bool v) {
		bool prev = exchange(m_bEnabled, v);
		if (!prev && v)
			Start();
		if (prev && !v)
			Stop();
	}

	int ReadOp(int cnt, CSnifCallback& cb) {
		Throw(E_NOTIMPL); //!!!
	}
};

#	if UCFG_SNIF_WIFI

ENUM_CLASS(EAdapterMode) {
	Normal,
		Disabled,
		Monitor
} END_ENUM_CLASS(EAdapterMode);

class EModulation {
public:
	static const int FHSS = dot11_phy_type_fhss,
	DSSS = dot11_phy_type_dsss,
	OFDM = dot11_phy_type_ofdm,
	HR_DSSS = dot11_phy_type_hrdsss,
	ERP = dot11_phy_type_erp,
	HT = dot11_phy_type_ht;

	EModulation(int v)
		:	m_val(v)
	{}

	EModulation(RCString s) {
		if (s=="FH" || s=="FHSS")
			m_val = FHSS;
		else if (s=="DSSS")
			m_val = DSSS;
		else if (s=="OFDM" || s=="11a")
			m_val = OFDM;
		else if (s=="11b")
			m_val = HR_DSSS;
		else if (s=="ERP" || s=="11g")
			m_val = ERP;
		else if (s=="HT" || s=="11n")
			m_val = HT;
		else
			Throw(HRESULT_FROM_WIN32(ERROR_INVALID_DATA));
	}

	operator DOT11_PHY_TYPE() const {
		return (DOT11_PHY_TYPE)m_val;
	}

	String ToString() const {
		switch ((DOT11_PHY_TYPE)m_val)
		{
		case dot11_phy_type_fhss: return "FHSS";
		case dot11_phy_type_dsss: return "DSSS";
		case dot11_phy_type_ofdm: return "11a";
		case dot11_phy_type_hrdsss: return "11b";
		case dot11_phy_type_erp: return "11g";
		case dot11_phy_type_ht: return "11n";
		default:
			return "Unknown";
		}
	}
private:
	int m_val;
};



class WifiAdapter : public LocalAdapter {
	typedef LocalAdapter base;
public:
	vector<DOT11_PHY_ATTRIBUTES> m_phyTypes;

	WifiAdapter(CLocalSnifEng& eng)
		:	base(eng)
	{
		Type = EAdapterType::Wifi;
	}

	void OnCreated(CSnifEng& eng) {
		DOT11_PHY_ATTRIBUTES buf[32];
		DWORD size = static_cast<CLocalSnifEng&>(eng).m_dev.DeviceIoControlAndWait(IOCTL_SNIF_GET_ADAPTER_PHY_TYPES|(m_desc.m_nDevice<<16), 0, 0, buf, sizeof(buf));
		m_phyTypes.assign(buf, buf+size/sizeof(DOT11_PHY_ATTRIBUTES));

		base::OnCreated(eng);
	}

	bool get_MonitorModeP() {
		return m_desc.WlanInterface.OperationMode == DOT11_OPERATION_MODE_NETWORK_MONITOR;
	}

	void put_MonitorModeP(bool v);

	virtual EAdapterMode get_Mode() {
		if (MonitorModeP)
			return EAdapterMode::Monitor;
		return EAdapterMode::Normal;
	}

	virtual void put_Mode(EAdapterMode mode) {
		MonitorModeP = mode == EAdapterMode::Monitor;
	}
	DEFPROP_VIRTUAL(EAdapterMode, Mode);

	virtual EModulation get_Modulation();
	virtual void put_Modulation(EModulation v);
	DEFPROP_VIRTUAL(EModulation, Modulation);
	
	virtual vector<EModulation> get_SupportedModulations();
	DEFPROP_VIRTUAL_GET(vector<EModulation>, SupportedModulations);

	virtual bool get_PowerState();
	virtual void put_PowerState(bool v);
	DEFPROP_VIRTUAL(bool, PowerState);

//!!!?	NDIS_MEDIUM GetMedium() override { return NdisMediumNative802_11; }

	static const int CHANNEL_OFDM = 0x8000;

	virtual vector<int> get_ChannelList();
	DEFPROP_VIRTUAL_GET(vector<int>, ChannelList);

	virtual int get_ChannelNum();
	virtual void put_ChannelNum(int v);
	DEFPROP_VIRTUAL(int, ChannelNum);
protected:
	void SetPromiscModeFilter();
	void SetPacketFilter();
};

class LegacyWifiAdapter : public WifiAdapter {
	typedef WifiAdapter base;

	int ReadOp(int cnt, CSnifCallback& cb);
public:
	LegacyWifiAdapter(CLocalSnifEng& eng)
		:	base(eng)
	{
		Type = EAdapterType::LegacyWifi;
	}

	~LegacyWifiAdapter() {
		m_desc.WifiCard->SetHandler(0);
	}

	void OnCreated(CSnifEng& eng) {
	}

	bool get_MonitorModeP() { return m_desc.WifiCard && m_desc.WifiCard->Mode == WIFIMODE_MONITOR; }

	void put_MonitorModeP(bool v) {
		if (m_desc.WifiCard)
			m_desc.WifiCard->Mode = v ? WIFIMODE_MONITOR : WIFIMODE_NORMAL;
	}

	EAdapterMode get_Mode() {
		switch (m_desc.WifiCard->Mode) {
		case WIFIMODE_MONITOR: return EAdapterMode::Monitor;
		case WIFIMODE_DISABLED: return EAdapterMode::Disabled;
		default: return EAdapterMode::Normal;
		}	
	}

	void put_Mode(EAdapterMode mode) {
		switch (mode)
		{
		case EAdapterMode::Monitor: m_desc.WifiCard->Mode = WIFIMODE_MONITOR; break;
		case EAdapterMode::Disabled: m_desc.WifiCard->Mode = WIFIMODE_DISABLED; break;
		case EAdapterMode::Normal: m_desc.WifiCard->Mode = WIFIMODE_NORMAL; break;
		}
	}

	EModulation get_Modulation() {
		return EModulation::HR_DSSS;
	}

	void put_Modulation(EModulation v) {
	}

	bool get_PowerState() { return true; }
	void put_PowerState(bool v) {}

	vector<EModulation> get_SupportedModulations() {
		vector<EModulation> r;
		r.push_back(EModulation::HR_DSSS);
		return r;
	}

	vector<int> get_ChannelList();

	int get_ChannelNum();
	void put_ChannelNum(int v);
};


class AFX_PACKET_CLASS CWifiManager {
	bool CreateCardByIDs(DiDeviceInfo di, const vector<String>& ar);

	static unique_ptr<CWifiManager> s_I;
public:
	static vector<CWifiCardClass*> s_classes;

	vector<ptr<WifiAdapter> > get_Adapters();
	DEFPROP_GET(vector<ptr<WifiAdapter> >, Adapters);
//!!!	vector<ptr<CWifiCard> > Cards;

	CWifiManager();

	static CWifiManager& AFXAPI I() {
		if (!s_I.get())
			s_I.reset(new CWifiManager);
		return *s_I;
	}
};



#	endif // UCFG_SNIF_WIFI



#endif // !UCFG_SNIF_USE_PCAP

} // Snif::
