/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "standard-plugin.h"

#if UCFG_GUI
#	include "plugin-gui.h"
#endif

namespace Snif {

class UdpPacket : public PluginPacket {
	typedef UdpPacket class_type;

	DECLARE_DYNCREATE(UdpPacket)
public:
#ifdef _DEBUG //!!!D
	UdpPacket() {
		static int n = 0;
		n++;
	}
#endif

	WORD get_SrcPort() { return GetHWord(0); }
	DEFPROP_GET(WORD, SrcPort);

	WORD get_DstPort() { return GetHWord(2); }
	DEFPROP_GET(WORD, DstPort);

	WORD get_Length() { return GetHWord(4); }
	DEFPROP_GET(WORD, Length);

	WORD get_Checksum() { return GetHWord(5); }
	DEFPROP_GET(WORD, Checksum);

#if UCFG_OLE
	void Info(CBag& bag) override {
		ptr<PluginPacket> iPP = StaticCast<PluginPacket>(m_iBase);
		iPP->Info(bag);
		CBag row;
		AddFieldInfo(row,"Source Port "+Convert::ToString(SrcPort)+PortInfo(SrcPort), 0, 2);
		AddFieldInfo(row,"Destination Port "+Convert::ToString(DstPort)+PortInfo(DstPort), 2, 2);
		long off = GetLocalDataOffset();
		AddFieldInfo(row, "Data", off, GetData().Size);
		bag.Add((CBag("UDP"), row));
	}
#endif
protected:
	int GetLocalDataOffset() override {
		return 8;
	}

	String PortInfo(WORD port) {
		String s;
		if (servent *ent = getservbyport(htons(port),"udp"))
			s = ent->s_name;
		else
		{
			switch (port)
			{
			case 139:
				s = "SMB";
				break;
			case 4000:
				s = "ICQ";
				break;
			}
		}
		return s.IsEmpty()? "" : " "+s;
	}
};

IMPLEMENT_DYNCREATE(UdpPacket, PluginPacket)

#if UCFG_GUI

class CFormUDP : public CConditionsView {
	DECLARE_DYNCREATE(CFormUDP)

	void SavePorts();
public:
	CFormUDP();

	//{{AFX_DATA(CFormUDP)
	enum { IDD = IDD_UDP };
	CListBox	m_lbxPorts;
	//}}AFX_DATA

	//{{AFX_VIRTUAL(CFormUDP)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
//}}AFX_VIRTUAL
protected:

	//{{AFX_MSG(CFormUDP)
	afx_msg void OnAdd();
	afx_msg void OnEdit();
	afx_msg void OnDelete();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CFormUDP::CFormUDP()
:	CConditionsView(IDD)
{
//{{AFX_DATA_INIT(CDialogUDP)
//}}AFX_DATA_INIT
}

void CFormUDP::DoDataExchange(CDataExchange* pDX) {
	CConditionsView::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CFormUDP)
	DDX_Control(pDX, LBX_PORTS, m_lbxPorts);
	//}}AFX_DATA_MAP
	CVariantIterator vi(m_pPlugin->m_obCond.GetProperty("Ports"));
	for (COleVariant v; vi.Next(v);)
		m_lbxPorts.AddString(Convert::ToString(Convert::ToInt32(v)));
}

IMPLEMENT_DYNCREATE(CFormUDP, CConditionsView)

BEGIN_MESSAGE_MAP(CFormUDP, CConditionsView)
	ON_BN_CLICKED(ID_ADD, &CFormUDP::OnAdd)
	ON_BN_CLICKED(ID_EDIT, &CFormUDP::OnEdit)
	ON_BN_CLICKED(ID_DELETE, &CFormUDP::OnDelete)
END_MESSAGE_MAP()

void CFormUDP::OnAdd() {
	String s;
	if (InputQuery("AddPort","Enter port:", s)) {
		m_lbxPorts.AddString(s);
		SavePorts();
	}
}

void CFormUDP::OnEdit() {
	int i = m_lbxPorts.CurSel;
	String s = m_lbxPorts.GetText(i);
	if (InputQuery("AddPort","Enter port:", s)) {
		m_lbxPorts.DeleteString(i);
		m_lbxPorts.InsertString(i, s);
		SavePorts();
	}
}

void CFormUDP::OnDelete() {
	m_lbxPorts.DeleteString(m_lbxPorts.CurSel);
	SavePorts();	
}

void CFormUDP::SavePorts()
{
	COdCollection coll = m_pPlugin->m_obCond.GetProperty("Ports");
	coll.DeleteAll();
	for (int i=0; i<m_lbxPorts.Count; i++) {
		WORD port = (WORD)atoi(m_lbxPorts.GetText(i));
		coll.Add(COleVariant(long(port)));
	}
}

#endif

class UdpObj : public SnifferPlugin {
	DECLARE_DYNCREATE(UdpObj)
protected:
	bool CheckConditions(PluginPacket *iPacket) override {
		if (SnifferPlugin::CheckConditions(iPacket))
			return true;
#if UCFG_SNIF_USE_ODDB
		ptr<UdpPacket> iUP = static_cast<UdpPacket*>(iPacket);
		WORD src = iUP->SrcPort, dst = iUP->DstPort;
		CVariantIterator vi(m_obCond.GetProperty("Ports"));
		for (COleVariant v; vi.Next(v);) {
			WORD port = (WORD)Convert::ToInt32(v);
			if (src == port || dst == port)
				return true;
		}
#endif
		return false;
	}

#if UCFG_SNIF_USE_ODDB
	void DefinePluginClasses(COdClass& clCond) override {
		clCond.CreateField("Ports","word []");
	}
#endif
public:
	/*!!!  static CComObjectRootBase *_CreateInstance() {
	return new CUdpObj;
	}*/

	UdpObj() {
		m_name = "UDP";
		m_layer = PROTO_UDP;
#if UCFG_GUI
		m_pViewClass = RUNTIME_CLASS(CFormUDP);
#endif
		m_pPacketClass = RUNTIME_CLASS(UdpPacket);
	}

	void Bind() override {
		m_binder->m_mapIp[IPPROTO_UDP].insert(this);
	}

	void UnbindPlugin() override {
		m_binder->m_mapIp[IPPROTO_UDP].erase(this);
	}
};

IMPLEMENT_DYNCREATE(UdpObj, SnifferPlugin)

/*!!!
class CUdpPluginClass : public CStandardPluginClass {
public:
CUdpPluginClass()
:CStandardPluginClass(CLSID_UDP,CUdpObj::_CreateInstance,IDS_UDP)
{}

//!!!  void Register() {
//!!!    CStandardPluginClass::Register();
//!!!    CArray<String> ar;
//!!!    ar.Add(StringFromCLSID(CLSID_IP));
//!!!    RegistryKey(HKEY_CLASSES_ROOT,"CLSID\\"+StringFromCLSID(m_clsid)).SetValue("Dependencies",ar);
//!!!  }
};*/


//!!!CUdpPluginClass g_classUDP;

ptr<SnifferPlugin> CreateUDP() {
	return new UdpObj;
}

extern "C" { PluginClass<UdpObj,PROTO_UDP> g_udpClass; }


} // Snif::



