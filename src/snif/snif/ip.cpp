/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "standard-plugin.h"
#include "tcpapi.h"

#if UCFG_GUI
#	include "plugin-gui.h"
#endif

namespace Snif {


class Ip4Obj;
class Ip4Packet;

#if UCFG_GUI
class OriginalIPDataSet : public PacketDataSet {
	Ip4Obj& m_plugin;
	//!!!CUnkPtr m_iOwner;
public:
	OriginalIPDataSet(Ip4Obj& plugin);

	ptr<Object> GetItem(int idx);
	size_t GetCount();
};
#endif

class Ip4Packet : public IpPacket {
	typedef IpPacket base;
	typedef Ip4Packet class_type;

	DECLARE_DYNCREATE(Ip4Packet)
public:
	Buf m_mb;

	Ip4Packet *Clone() const {
		return new Ip4Packet(_self);
	}

	void PreAnalyze() override {
		base::PreAnalyze();
		m_ip = (ip*)GetChunk(0, sizeof(ip));
	}

	ConstBuf GetSrcAddr() {
		return ConstBuf(&m_ip->ip_src, 4);
	}

	ConstBuf GetDstAddr() {
		return ConstBuf(&m_ip->ip_dst, 4);
	}

	byte get_IHL() { return m_ip->ip_hl; }
	DEFPROP_GET(byte, IHL);

	UInt16 get_FragmentOffset() { return Fast_ntohs(m_ip->ip_off) << 3; }
	DEFPROP_GET(UInt16, FragmentOffset);

	byte get_Flags() { return ((byte*)m_ip.get())[6] >> 5; }
	DEFPROP_GET(byte, Flags);

	DWORD get_Src() { return GetHDWord(12); }
	DEFPROP_GET(DWORD, Src);

	DWORD get_Dst() { return GetHDWord(16); }
	DEFPROP_GET(DWORD, Dst);

	byte get_Protocol() { return GetByte(9); }
	DEFPROP_GET(byte, Protocol);

	byte GetHopLimit() { return GetByte(8); }

	BYTE get_Version() { return (GetByte(0) >> 4) & 15; }
	DEFPROP_GET(BYTE, Version);

	BYTE get_ToS() { return GetByte(1); }
	DEFPROP_GET(BYTE, ToS);

	bool get_MF() { return Flags & 1; }
	DEFPROP_GET(bool, MF);

	WORD get_TotalLength() { return GetHWord(2); }
	DEFPROP_GET(WORD, TotalLength);

	Buf GetData() {
		if (!m_mb.P) {
			Buf mb = PluginPacket::GetData();
			(m_mb=mb).Size = TotalLength-GetLocalDataOffset(); //!!!
			if (m_mb.Size > mb.Size)
				Throw(E_Sniffer_BadPacketFormat);
		}
		return m_mb;
	}

	WORD get_Identification() { return GetHWord(4); }
	DEFPROP_GET(WORD,Identification);

	WORD get_HeaderChecksum() { return GetHWord(10); }
	DEFPROP_GET(WORD,HeaderChecksum);

	long GetProto() {
		return Protocol;
		/*!!!
		switch (Protocol)
		{
		case IPPROTO_ICMP: return PROTO_ICMP;
		case IPPROTO_TCP: return PROTO_TCP;
		case IPPROTO_UDP: return PROTO_UDP;
		default: return PROTO_UNKNOWN;
		}*/
	}

	String GetFrom() { return HostToStr(Src); }
	String GetTo() { return HostToStr(Dst); }

#if UCFG_OLE
	void Info(CBag& bag) override;
#endif
protected:
	CPointer<ip> m_ip;

	int GetLocalDataOffset() override { return IHL*4; }
};

typedef vector<ptr<Ip4Packet> > FragmentParts;

struct CIPFragmentKey {
	UInt32 m_src,
		m_dst;
	byte m_protocol;
	UInt16 m_id;

	bool operator==(const CIPFragmentKey& key) const {
		return !memcmp(this, &key, sizeof(CIPFragmentKey));
	}

	CIPFragmentKey()
	{}

	CIPFragmentKey(const CIPFragmentKey& fk) {
		memcpy(this, &fk, sizeof(CIPFragmentKey));
	}

	CIPFragmentKey(Ip4Packet *iIP)
		:	m_src(iIP->Src)
		,	m_dst(iIP->Dst)
		,	m_protocol(iIP->Protocol)
		,	m_id(iIP->Identification)
	{
	}
};

} namespace EXT_HASH_VALUE_NS {
inline size_t hash_value(const Snif::CIPFragmentKey& fk) {
	return fk.m_src + fk.m_dst + fk.m_id;
}
}
EXT_DEF_HASH(Snif::CIPFragmentKey)
namespace Snif {

class Ip4Obj : public IpObjBase {
	typedef IpObjBase base;
protected:
	typedef LruMap<CIPFragmentKey, FragmentParts> FragmentsCache;
	FragmentsCache LastFragments;

	bool CheckConditions(PluginPacket *iPacket) override {
		if (SnifferPlugin::CheckConditions(iPacket))
			return true;
#if UCFG_SNIF_USE_ODDB
		ptr<Ip4Packet> iIPP = static_cast<Ip4Packet*>(iPacket);
		UInt32 src = iIPP->Src,
			dst = iIPP->Dst;
		CVariantIterator vi(m_obCond.GetProperty("IPs"));
		for (COleVariant v; vi.Next(v);) {
			UInt32 ip = UInt32(Convert::ToInt32(v));
			if (src == ip || dst == ip)
				return true;
		}
#endif
		return false;
	}

#if UCFG_SNIF_USE_ODDB
	void DefinePluginClasses(COdClass& clCond) override {
		clCond.CreateField("IPs", "dword []");
		UpgradePluginClasses(clCond);
	}

	void UpgradePluginClasses(COdClass& clCond) override {
		COdClass cl = clCond.Database.Classes[m_name];
		try {
			DBG_LOCAL_IGNORE(E_OD_InvalidFieldName);

			COdFields fields = cl.Fields;
			COdField field = fields["RawPackets"];
		} catch (RCExc) {
			cl.CreateField("RawPackets", "Packet *[]");
		}
	}
#endif

	LruCache<CIpSnap> m_lastIpSnaps;

	//!!!R	void ProcessSubAnalyzers(PluginPacket *iPacket);
	void ProcessPacket(PluginPacket *iPacket) override;
	void Analyze(SnifferPacketBase *iPacket) override;

	//!!!R	ptr<PluginPacket> CreateSubPluginPacket(ptr<PluginPacket> iNew);
public:
#if UCFG_SNIF_USE_ODDB
	COdCollObjects m_collRaw;
#endif


	/*!!!  static CComObjectRootBase *_CreateInstance()
	{
	return new CIp4Obj;
	}*/

	Ip4Obj();
	~Ip4Obj();
	void FragmentedPacket(Ip4Packet *iIP);

	void Bind() override {
		m_binder->m_mapEthernet[ETHERTYPE_IP].insert(this);
		m_binder->m_mapIp[IPPROTO_IPV4].insert(this);
	}

	void UnbindPlugin() override	{
		m_binder->m_mapEthernet[ETHERTYPE_IP].erase(this);
		m_binder->m_mapIp[IPPROTO_IPV4].erase(this);
	}

#if UCFG_GUI
	CPointer<OriginalIPDataSet> m_pOriginalDataSet;
	ptr<DataSet> m_iOriginalDataSet;

	void Connect(SnifferSite *pSite) {
		SnifferPlugin::Connect(pSite);
		m_collRaw = m_obj.GetProperty("RawPackets");
	}

	ptr<DataSet> GetDataSet(RCString name) override {
		if (name == "OriginalPackets")  {
			if (!m_pOriginalDataSet) {
				m_pOriginalDataSet = new OriginalIPDataSet(_self);
				m_iOriginalDataSet = m_pOriginalDataSet.get();
			}
			return m_pOriginalDataSet;
		} else
			return SnifferPlugin::GetDataSet(name);
	}
#endif

	void Disconnect() override {
#if UCFG_SNIF_USE_ODDB
		m_collRaw.Release();
#endif
		LastFragments.clear();
		SnifferPlugin::Disconnect();
	}

	void Clear() override {
		SnifferPlugin::Clear();
#if UCFG_SNIF_USE_ODDB
		m_collRaw.DeleteAll();
#endif
	}

#if UCFG_GUI
	vector<String> GetDataSets() override {
		vector<String> vec;
		vec.push_back("Packets");
		vec.push_back("OriginalPackets");
		return vec;
	}
#endif

};




#if UCFG_GUI

class CFormIP : public CConditionsView {
	DECLARE_DYNCREATE(CFormIP)

	void SaveIPs();
public:
	//{{AFX_DATA(CFormIP)
	enum { IDD = IDD_IP };
	CListBox	m_lbxIPs;
	//}}AFX_DATA

	CFormIP();

	//{{AFX_VIRTUAL(CFormIP)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

protected:
	~CFormIP();

	//{{AFX_MSG(CFormIP)
	afx_msg void OnAdd();
	afx_msg void OnEdit();
	afx_msg void OnDelete();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
#endif

IMPLEMENT_DYNCREATE(Ip4Packet, PluginPacket)

#if UCFG_OLE
void Ip4Packet::Info(CBag& bag) {
	PluginPacket::Info(bag);
	CBag row;
	AddFieldInfo(row, "Source "+HostToStr(Src), 12, 4);
	AddFieldInfo(row, "Destination "+HostToStr(Dst), 16, 4);
	AddFieldInfo(row, "Protocol "+Convert::ToString(Protocol), 9, 1);
	AddFieldInfo(row, "Length "+Convert::ToString(TotalLength), 2, 2);
	AddFieldInfo(row, "Identification "+Convert::ToString(Identification), 4, 2);
	AddFieldInfo(row, "Flags "+Convert::ToString(Flags),6,1);
	AddFieldInfo(row, "Fragmet Offset "+Convert::ToString(FragmentOffset), 6, 2);
	ConstBuf mb = GetData();
	//!!!OleCheck(m_iBase->GetData(&p, &len));
	long off = GetLocalDataOffset();
	//!!!AddFieldInfo(row,"Data", off, len-off);
	AddFieldInfo(row,"Data", off, mb.Size);
	bag.Add((CBag("IP"), row));
}
#endif



#if UCFG_GUI

OriginalIPDataSet::OriginalIPDataSet(Ip4Obj& plugin)
	:	PacketDataSet(&plugin)
	,	m_plugin(plugin)
{
	//!!!  m_iOwner = &plugin;
}

ptr<Object> OriginalIPDataSet::GetItem(int idx) {
	return m_plugin.m_iSite->ProcessPacket(SnifferPacket::Load(m_plugin.m_collRaw.GetItem(idx)));
}

size_t OriginalIPDataSet::GetCount() {
	return m_plugin.m_collRaw.Count;
}

IMPLEMENT_DYNCREATE(CFormIP,CConditionsView)

BEGIN_MESSAGE_MAP(CFormIP, CConditionsView)
	ON_BN_CLICKED(ID_ADD, &CFormIP::OnAdd)
	ON_BN_CLICKED(ID_EDIT, &CFormIP::OnEdit)
	ON_BN_CLICKED(ID_DELETE, &CFormIP::OnDelete)
END_MESSAGE_MAP()

CFormIP::CFormIP()
	:	CConditionsView(IDD)
{
}

CFormIP::~CFormIP() {
}

void CFormIP::DoDataExchange(CDataExchange* pDX) {
	CConditionsView::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CFormIP)
	DDX_Control(pDX, LBX_IPS, m_lbxIPs);
	//}}AFX_DATA_MAP
	if (!pDX->m_bSaveAndValidate) {
		CVariantIterator vi(COdObject(AsUnknown(m_pPlugin->m_obj.GetProperty("Conditions"))).GetProperty("IPs"));
		for (COleVariant v; vi.Next(v);)
			m_lbxIPs.AddString(HostToStr(Convert::ToInt32(v)));
	}
}

class CDialogIP : public CDialog {
public:
	IPAddress m_host;

	CDialogIP(CWnd* pParent = NULL);   // standard constructor

	//{{AFX_DATA(CDialogIP)
	enum { IDD = IDD_IPADDR };
	CIPAddressCtrl	m_ip;
	//}}AFX_DATA

	//{{AFX_VIRTUAL(CDialogIP)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL
protected:
	//{{AFX_MSG(CDialogIP)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CDialogIP::CDialogIP(CWnd* pParent /*=NULL*/)
	:	CDialog(CDialogIP::IDD, pParent)
	,	m_host(0)
{
	//{{AFX_DATA_INIT(CDialogIP)
	//}}AFX_DATA_INIT
}

void CDialogIP::DoDataExchange(CDataExchange* pDX) {
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDialogIP)
	DDX_Control(pDX, IDC_IP, m_ip);
	//}}AFX_DATA_MAP
	if (pDX->m_bSaveAndValidate) {
		m_ip.GetAddress(m_host);
	}
	else {
		if (m_host.GetIP())
			m_ip.SetAddress(m_host);
	}
}

BEGIN_MESSAGE_MAP(CDialogIP, CDialog)
	//{{AFX_MSG_MAP(CDialogIP)
	// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

void CFormIP::OnAdd() {
	CDialogIP d;
	if (d.DoModal() == IDOK) {
		IPAddress ip;
		d.m_ip.GetAddress(ip);
		m_lbxIPs.AddString(ip.ToString());
		SaveIPs();
	}
}

void CFormIP::OnEdit()  {
	CDialogIP d;
	int i = m_lbxIPs.CurSel;
	d.m_host = IPAddress::Parse(m_lbxIPs.GetText(i));
	if (d.DoModal() == IDOK) {
		m_lbxIPs.DeleteString(i);
		m_lbxIPs.InsertString(i, d.m_host.ToString());
		SaveIPs();
	}
}

void CFormIP::OnDelete() {
	int idx = m_lbxIPs.CurSel;
	if (idx != -1) {
		m_lbxIPs.DeleteString(m_lbxIPs.CurSel);
		SaveIPs();
	}
}

void CFormIP::SaveIPs() {
	COdCollection coll = m_pPlugin->m_obCond.GetProperty("IPs");
	coll.DeleteAll();
	for (int i=0; i<m_lbxIPs.Count; i++) {
		DWORD host = IPAddress::Parse(m_lbxIPs.GetText(i)).GetIP();
		coll.Add(COleVariant(long(host)));
	}
}
#endif

//!!!CIpPluginClass g_classIP;

int forceIP;

ptr<SnifferPlugin> CreateIP() {
	return new Ip4Obj;
}

Ip4Obj::Ip4Obj()
	:	base(PROTO_IP)
	,	LastFragments(IP_MAX_FRAGMENTED_NUMBER)
//!!!	,	m_lastIpSnaps(12) //!!!D
{
	m_name = "IP";
	m_layer = PROTO_IP;
#if UCFG_GUI
	m_pViewClass = RUNTIME_CLASS(CFormIP);
#endif
	m_pPacketClass = RUNTIME_CLASS(Ip4Packet);
}

Ip4Obj::~Ip4Obj() {
}

void Ip4Obj::FragmentedPacket(Ip4Packet *iIP) {
	FragmentsCache::iterator iter = LastFragments.insert(FragmentsCache::value_type(CIPFragmentKey(iIP), FragmentParts())).first;
	FragmentParts& item = iter->second.first;
	UInt16 offset = iIP->FragmentOffset;
	FragmentParts::iterator j = item.begin();
	for (; j<item.end(); ++j) {
		UInt16 off = (*j)->FragmentOffset;
		if (offset < off)
			break;
		if (offset == off) {
			j = item.erase(j);
			break;
		}
	}
	item.insert(j, iIP);

	ssize_t pos = 0;
	for (int i=0; i<item.size(); i++) {
		ptr<Ip4Packet> ip = item[i];
		UInt16 off = ip->FragmentOffset;
		if (off < pos)
			Throw(E_FAIL);
		if (off > pos || (i == item.size()-1) && ip->MF)
			return;
		pos += ip->GetData().Size;
	}

	ILP_SnifferPacket iSP = iIP->GetRootPacket();
	//!!!  iSP->TakeOwnership();
	SnifferPacketBase *iSPB = iIP->m_iBase.get();
	size_t len = iIP->GetData().P-iSP->GetData().P;
	ptr<SnifferPacket> iNew = new(len+pos) SnifferPacket;
	iNew->Order = iSP->Order;
	iNew->Medium = PROTO_IP;
	iNew->Adapter = iSP->Adapter;
	iNew->TimeStamp = iSP->TimeStamp;
	iNew->Flags = 0;

	byte *p = (byte*)iNew->Data;
	const BYTE *q = iSPB->GetData().P;
	memcpy(p,q,len);
	*(WORD*)(p+2) = htons(WORD(len+pos));
	*(WORD*)(p+6) = 0;
	p += len;
	for (int i=0; i<item.size(); i++) {
		ConstBuf mb = item[i]->GetData();
		memcpy(p, mb.P, mb.Size);
		p += mb.Size;
	}                            //!!!? Calculate IP checksum

	LastFragments.erase(iter);

	//!!!ptr<SnifferPacket> iNew = m_iSite->CreatePacket(pNewBlock);
	ptr<PluginPacket> pp = CreatePacket(iNew);
	pp->PreAnalyze();
	if (CheckConditions(pp))
		SnifferPlugin::ProcessPacket(pp);
}

/*!!!
void Ip4Obj::ProcessSubAnalyzers(PluginPacket *iPacket)
{
IpPacket *ip = (IpPacket*)iPacket;
BYTE ipproto = ip->Protocol;
AnalyzerBinder::Map::iterator i = m_binder->m_mapIp.find(ipproto);
if (i != m_binder->m_mapIp.end())
{
AnalyzerBinder::Subscribers& subs = i->second;
for (AnalyzerBinder::Subscribers::iterator j=subs.begin(); j!=subs.end(); ++j)
(*j)->Analyze(iPacket);
}
}
*/

void Ip4Obj::ProcessPacket(PluginPacket *iPacket) {
	if (m_bSkipDuplicates) {
		ConstBuf mb = static_cast<MACPacket*>(iPacket->m_iBase.get())->GetData();
		if (mb.Size >= sizeof(ip)+sizeof(UInt64)) {
			ip *iph = (ip*)mb.P;
			if (*(byte*)iph == 0x45) {
				CIpSnap ipSnap;
				ipSnap.tcpPart = *(UInt64*)(iph+1);
				ipSnap.ip_src	= iph->ip_src;
				ipSnap.ip_dst	= iph->ip_dst;
				ipSnap.ip_len	= iph->ip_len;
				ipSnap.ip_id	= iph->ip_id;
				ipSnap.ip_off	= iph->ip_off;
				ipSnap.ip_tos	= iph->ip_tos;
				ipSnap.ip_p		= iph->ip_p;

//				cout << __FUNCTION__ << endl; //!!!D

				if (!m_lastIpSnaps.insert(ipSnap).second) { //!!!Q  What if the packet with bad CRC? we need remove it from cache, because repeate can be more correct
					return;
				}
			}
		}
	}

	//!!!  OleCheck(iSP->put_Layer(m_layer));
#if UCFG_SNIF_USE_ODDB
	if (m_obCond && Convert::ToBoolean(m_obCond.GetProperty("Save"))) {
		SnifferPacket *iSP = iPacket->GetRootPacket();
		iSP->Save(m_clPacket);
		m_collRaw.Add(iSP->GetODObject());
	}
#endif
	Ip4Packet *iIP = static_cast<Ip4Packet*>(iPacket);

	TRC(4, "IP Packet: " << iPacket->GetRootPacket()->TimeStamp.ToLocalTime().ToString(Microseconds()));

//!!!R	IpWrap ipw(iIP);
	if (g_opt_LogLevel >= 2) {
		ConstBuf mb = static_cast<MACPacket*>(iPacket->m_iBase.get())->GetData();;
		mb.Size = iIP->get_IHL()*4;
		if (CalculateWordSum(mb, 0, true)) {
			ILP_SnifferPacket iSP = iPacket->GetRootPacket();
			ostringstream os;
			os << iSP->TimeStamp;
			String s = os.str();
			cerr << "Bad IP Checksum from " << IPAddress(iIP->GetSrcAddr()) << endl;
			Throw(E_Sniffer_BadChecksum);
		}
	}

	bool bSkip = false;
	for (size_t i=m_subscribers.size(); i--;)
		if (!m_subscribers[i]->OnReceivedIp(iIP))
			bSkip = true;
	if (bSkip)
		return;

	if (iIP->FragmentOffset || iIP->MF) {		
		ptr<PluginPacket> iPP = iIP->MakePacketHeaped();
		FragmentedPacket((Ip4Packet*)iPP.get());
	} else
		SnifferPlugin::ProcessPacket(iPacket);		
}

void Ip4Obj::Analyze(SnifferPacketBase *iPacket) {
	Buf mb = iPacket->GetData();

	switch (*mb.P >> 4) {
	case 4:
		break;
	case 6:
		{
			auto it = m_binder->m_mapEthernet.find(ETHERTYPE_IPV6);
			if (it != m_binder->m_mapEthernet.end()) {
				for (auto j=it->second.begin(), e=it->second.end();  j!=e; ++j)
					(*j)->Analyze(iPacket);
			}
		}
		return;
	default:
		Throw(E_Sniffer_BadPacketFormat);
	}
	Ip4Packet packet;
	AnalyzeCreated(packet, iPacket);
}


/*!!!R
ptr<PluginPacket> Ip4Obj::CreateSubPluginPacket(ptr<PluginPacket> iNew)
{
IpPacket *ip = (IpPacket*)iNew.P;
BYTE ipproto = ip->Protocol;

AnalyzerBinder::Map::iterator i = m_binder->m_mapIp.find(ipproto);
if (i != m_binder->m_mapIp.end())
{
AnalyzerBinder::Subscribers& subs = i->second;
for (AnalyzerBinder::Subscribers::iterator j=subs.begin(); j!=subs.end(); ++j)
{
if (ptr<PluginPacket> iPP = (*j)->CreatePluginPacket(iNew))
return iPP;
}
}
return iNew;
}

*/

extern "C" { PluginClass<Ip4Obj, PROTO_IP> g_ip4Class; }

} // Snif::
