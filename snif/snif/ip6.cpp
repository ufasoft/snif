/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include <netinet/ip6.h>

#include "standard-plugin.h"
#include "tcpapi.h"

#if UCFG_GUI
#	include "plugin-gui.h"
#endif

namespace Snif {

class Ip6Obj : public IpObjBase {
	typedef IpObjBase base;
public:
	Ip6Obj();
	~Ip6Obj();
protected:
	void Analyze(SnifferPacketBase *iPacket) override;

	void Bind() override {
		m_binder->m_mapEthernet[ETHERTYPE_IPV6].insert(this);
		m_binder->m_mapIp[IPPROTO_IPV6].insert(this);
	}

	void UnbindPlugin() override	{
		m_binder->m_mapEthernet[ETHERTYPE_IPV6].erase(this);
		m_binder->m_mapIp[IPPROTO_IPV6].erase(this);
	}

	bool CheckConditions(PluginPacket *iPacket) override;

#if UCFG_SNIF_USE_ODDB
	void DefinePluginClasses(COdClass& clCond) override {
		clCond.CreateField("IPs", "string []");
		UpgradePluginClasses(clCond);
	}
#endif
};


#if UCFG_GUI

class CFormIP6 : public CConditionsView {
	DECLARE_DYNCREATE(CFormIP6)

	void SaveIPs();
public:
	//{{AFX_DATA(CFormIP)
	enum { IDD = IDD_IP };
	CListBox	m_lbxIPs;
	//}}AFX_DATA

	CFormIP6();

	//{{AFX_VIRTUAL(CFormIP)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

protected:
	~CFormIP6();

	//{{AFX_MSG(CFormIP)
	afx_msg void OnAdd();
	afx_msg void OnEdit();
	afx_msg void OnDelete();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};
#endif

class Ip6Packet : public IpPacket {
	typedef IpPacket base;
	typedef Ip6Packet class_type;

	DECLARE_DYNCREATE(Ip6Packet)
public:
	Ip6Packet()
		:	m_protocol(-1)
		,	m_localDataOffset(-1)
	{}

	Ip6Packet *Clone() const {
		return new Ip6Packet(_self);
	}

	void PreAnalyze() override {
		base::PreAnalyze();
		m_ip6 = (ip6_hdr*)GetChunk(0, sizeof(ip6_hdr));
	}

	ConstBuf GetSrcAddr() {
		return ConstBuf(&m_ip6->ip6_src, 16);
	}

	ConstBuf GetDstAddr() {
		return ConstBuf(&m_ip6->ip6_dst, 16);
	}

	int GetPayloadLength() { return GetHWord(4); }

	byte GetHopLimit() { return GetByte(7); }

	long GetProto() override {
		if (-1 == m_protocol)
			CalcFields();
		return m_protocol;
	}

	Buf GetData() {
		if (!m_mb.P) {
			Buf mb = PluginPacket::GetData();
			(m_mb=mb).Size = 40+GetPayloadLength()-GetLocalDataOffset(); //!!!
			if (m_mb.Size > mb.Size)
				Throw(E_Sniffer_BadPacketFormat);
		}
		return m_mb;
	}

#if UCFG_OLE
	void Info(CBag& bag) override;
#endif
protected:
	ip6_hdr *m_ip6;

	int GetLocalDataOffset() {
		if (-1 == m_localDataOffset)
			CalcFields();
		return m_localDataOffset;
	}
private:
	Buf m_mb;
	long m_protocol;
	int m_localDataOffset;

	void CalcFields() {
		byte nextHeader = GetByte(6);
		int off = 40;				// header size
		while (true) {
			const byte *p;
			switch (nextHeader) {
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS:
				p = GetChunk(off, 2);
				nextHeader = p[0];
				off += 8+(p[1]<<3);
				continue;
			case IPPROTO_FRAGMENT:
				p = GetChunk(off, 2);
				nextHeader = p[0];
				off += 8;
				continue;
			case IPPROTO_AH:
				p = GetChunk(off, 2);
				nextHeader = p[0];
				off += 8+(p[1]<<2);
				continue;
			case IPPROTO_ESP:
				Throw(E_NOTIMPL); //!!!
			}
			break;
		}
		m_protocol = nextHeader;
		m_localDataOffset = off;
	}
};

bool Ip6Obj::CheckConditions(PluginPacket *iPacket) {
	if (SnifferPlugin::CheckConditions(iPacket))
		return true;
#if UCFG_SNIF_USE_ODDB
	ptr<Ip6Packet> iIPP = static_cast<Ip6Packet*>(iPacket);
	IPAddress src(iIPP->GetSrcAddr()),
			dst(iIPP->GetDstAddr());
	CVariantIterator vi(m_obCond.GetProperty("IPs"));
	for (COleVariant v; vi.Next(v);) {
		IPAddress ip = IPAddress::Parse(Convert::ToString(v));
		if (src == ip || dst == ip)
			return true;
	}
#endif
	return false;
}


IMPLEMENT_DYNCREATE(Ip6Packet, PluginPacket)

#if UCFG_OLE
void Ip6Packet::Info(CBag& bag) {
	PluginPacket::Info(bag);
	CBag row;
	AddFieldInfo(row, "Source "+IPAddress(GetSrcAddr()).ToString(), 8, 16);
	AddFieldInfo(row, "Destination "+IPAddress(GetDstAddr()).ToString(), 24, 16);
	AddFieldInfo(row, "Next Header "+Convert::ToString(GetProto()), 6, 1);
	AddFieldInfo(row, "Payload Length "+Convert::ToString(GetPayloadLength()), 2, 2);
	AddFieldInfo(row, "Hop Limit "+Convert::ToString(GetHopLimit()), 7, 1);
	ConstBuf mb = GetData();
	//!!!OleCheck(m_iBase->GetData(&p, &len));
	long off = GetLocalDataOffset();
	//!!!AddFieldInfo(row,"Data", off, len-off);
	AddFieldInfo(row, "Data", off, mb.Size);
	bag.Add((CBag("IPv6"), row));
}
#endif



#if UCFG_GUI


IMPLEMENT_DYNCREATE(CFormIP6, CConditionsView)

BEGIN_MESSAGE_MAP(CFormIP6, CConditionsView)
	ON_BN_CLICKED(ID_ADD, &CFormIP6::OnAdd)
	ON_BN_CLICKED(ID_EDIT, &CFormIP6::OnEdit)
	ON_BN_CLICKED(ID_DELETE, &CFormIP6::OnDelete)
END_MESSAGE_MAP()

CFormIP6::CFormIP6()
:	CConditionsView(IDD)
{
}

CFormIP6::~CFormIP6() {
}

void CFormIP6::DoDataExchange(CDataExchange* pDX) {
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

void CFormIP6::OnAdd() {
	//!!!TODO
}

void CFormIP6::OnEdit() {
	//!!!TODO
}

void CFormIP6::OnDelete() {
	int idx = m_lbxIPs.CurSel;
	if (idx != -1) {
		m_lbxIPs.DeleteString(m_lbxIPs.CurSel);
		SaveIPs();
	}
}

void CFormIP6::SaveIPs() {
	COdCollection coll = m_pPlugin->m_obCond.GetProperty("IPs");
	coll.DeleteAll();
	for (int i=0; i<m_lbxIPs.Count; i++) {
		DWORD host = IPAddress::Parse(m_lbxIPs.GetText(i)).GetIP();
		coll.Add(COleVariant(long(host)));
	}
}
#endif

//!!!CIpPluginClass g_classIP;

int forceIP6;

ptr<SnifferPlugin> CreateIP6() {
	return new Ip6Obj;
}

Ip6Obj::Ip6Obj()
	:	base(PROTO_IP6)
{
	m_name = "IPv6";
	m_layer = PROTO_IP6;
#if UCFG_GUI
	m_pViewClass = RUNTIME_CLASS(CFormIP6);
#endif
	m_pPacketClass = RUNTIME_CLASS(Ip6Packet);
}

Ip6Obj::~Ip6Obj() {
}

void Ip6Obj::Analyze(SnifferPacketBase *iPacket) {
	Buf mb = iPacket->GetData();

	if ((*mb.P >> 4) != 6)
		Throw(E_Sniffer_BadPacketFormat);

	Ip6Packet packet;
	AnalyzeCreated(packet, iPacket);
}

extern "C" { PluginClass<Ip6Obj, PROTO_IP6> g_ip6Class; }

} // Snif::
