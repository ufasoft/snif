/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "standard-plugin.h"

#define XDLC_I		0x00	/* Information frames */
#define XDLC_S		0x01	/* Supervisory frames */
#define XDLC_U		0x03	/* Unnumbered frames */

#define	OUI_ENCAP_ETHER	0x000000	/* encapsulated Ethernet */
#define	OUI_CISCO	0x00000C	/* Cisco (future use) */
#define	OUI_CISCO_90	0x0000F8	/* Cisco (IOS 9.0 and above?) */
#define OUI_BRIDGED	0x0080C2	/* Bridged Frame-Relay, RFC 2427 */
					/* and Bridged ATM, RFC 2684 */
#define	OUI_ATM_FORUM	0x00A03E	/* ATM Forum */
#define OUI_CABLE_BPDU	0x00E02F	/* DOCSIS spanning tree BPDU */
#define	OUI_APPLE_ATALK	0x080007	/* Appletalk */

/*
 * U-format modifiers.
 */
#define XDLC_U_MODIFIER_MASK	0xEC
#define XDLC_UI		0x00	/* Unnumbered Information */
#define XDLC_UP		0x20	/* Unnumbered Poll */
#define XDLC_DISC	0x40	/* Disconnect (command) */
#define XDLC_RD		0x40	/* Request Disconnect (response) */
#define XDLC_UA		0x60	/* Unnumbered Acknowledge */
#define XDLC_SNRM	0x80	/* Set Normal Response Mode */
#define XDLC_TEST	0xE0	/* Test */
#define XDLC_SIM	0x04	/* Set Initialization Mode (command) */
#define XDLC_RIM	0x04	/* Request Initialization Mode (response) */
#define XDLC_FRMR	0x84	/* Frame reject */
#define XDLC_CFGR	0xC4	/* Configure */
#define XDLC_SARM	0x0C	/* Set Asynchronous Response Mode (command) */
#define XDLC_DM		0x0C	/* Disconnected mode (response) */
#define XDLC_SABM	0x2C	/* Set Asynchronous Balanced Mode */
#define XDLC_SARME	0x4C	/* Set Asynchronous Response Mode Extended */
#define XDLC_SABME	0x6C	/* Set Asynchronous Balanced Mode Extended */
#define XDLC_RESET	0x8C	/* Reset */
#define XDLC_XID	0xAC	/* Exchange identification */
#define XDLC_SNRME	0xCC	/* Set Normal Response Mode Extended */
#define XDLC_BCN	0xEC	/* Beacon */

#define	SAP_NULL		0x00
#define	SAP_LLC_SLMGMT		0x02
#define	SAP_SNA_PATHCTRL	0x04
#define	SAP_IP			0x06
#define	SAP_SNA1		0x08
#define	SAP_SNA2		0x0C
#define	SAP_PROWAY_NM_INIT	0x0E
#define	SAP_TI			0x18
#define	SAP_BPDU		0x42
#define	SAP_RS511		0x4E
#define	SAP_X25                 0x7E
#define	SAP_XNS			0x80
#define	SAP_NESTAR		0x86
#define	SAP_PROWAY_ASLM		0x8E
#define	SAP_ARP			0x98
#define	SAP_SNAP		0xAA
#define	SAP_ARP			0x98
#define	SAP_VINES1		0xBA
#define	SAP_VINES2		0xBC
#define	SAP_NETWARE		0xE0
#define	SAP_NETBIOS		0xF0
#define	SAP_IBMNM		0xF4
#define	SAP_RPL1		0xF8
#define	SAP_UB			0xFA
#define	SAP_RPL2		0xFC
#define	SAP_OSINL		0xFE
#define	SAP_GLOBAL		0xFF

#define	SSAP_CR_BIT	0x01

inline WORD pntohs(const BYTE *p) {
	return WORD(p[0])<<8 | WORD(p[1]);
}

#define XDLC_IS_INFORMATION(control) \
	(((control) & 0x1) == XDLC_I || (control) == (XDLC_UI|XDLC_U))

#if UCFG_GUI
#	include "plugin-gui.h"
#endif

namespace Snif {

#if UCFG_GUI

class CDialogMAC : public CDialog {
public:
	CDialogMAC(CWnd* pParent = NULL);   // standard constructor

	//{{AFX_DATA(CDialogMAC)
	enum { IDD = IDD_MAC };
	String	m_mac;
	//}}AFX_DATA


	//{{AFX_VIRTUAL(CDialogMAC)
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

protected:

	//{{AFX_MSG(CDialogMAC)
	// NOTE: the ClassWizard will add member functions here
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CDialogMAC::CDialogMAC(CWnd* pParent /*=NULL*/)
	:	CDialog(CDialogMAC::IDD, pParent)
{
	//{{AFX_DATA_INIT(CDialogMAC)
	m_mac = _T("");
	//}}AFX_DATA_INIT
}

void DDV_MAC(CDialogMAC& dlg, CDataExchange *pDX, RCString mac) {
	if (pDX->m_bSaveAndValidate) {
		bool b = false;
		if (mac.Length == 17) {
			for (int i=0; i<6; i++) {
				String ss = mac.Mid(i*3,2);
				char c = char(ss[0]);
				if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'))
					b = true;
				c = char(ss[1]);
				if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'))
					b = true;
			}
		}
		else
			b = true;
		if (b) {
			AfxMessageBox("Invalid MAC",MB_ICONEXCLAMATION);
			pDX->Fail();
		}
	}
}

void CDialogMAC::DoDataExchange(CDataExchange* pDX) {
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDialogMAC)
	DDX_Text(pDX, EDIT_MAC, m_mac);
	//}}AFX_DATA_MAP
	DDV_MAC(_self,pDX,m_mac);
}

BEGIN_MESSAGE_MAP(CDialogMAC, CDialog)
	//{{AFX_MSG_MAP(CDialogMAC)
	// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


IMPLEMENT_DYNCREATE(CFormMAC,CConditionsView)

BEGIN_MESSAGE_MAP(CFormMAC, CConditionsView)
	ON_BN_CLICKED(ID_ADD, &CFormMAC::OnAdd)
	ON_BN_CLICKED(ID_EDIT, &CFormMAC::OnEdit)
	ON_BN_CLICKED(ID_DELETE, &CFormMAC::OnDelete)
END_MESSAGE_MAP()

CFormMAC::CFormMAC(int idd)
	:	CConditionsView(idd)
{
}


CFormMAC::~CFormMAC() {
}

void CFormMAC::DoDataExchange(CDataExchange* pDX) {
	CConditionsView::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CFormMAC)
	DDX_Control(pDX, LBX_MACS, m_lbxMACs);
	//}}AFX_DATA_MAP
	if (!pDX->m_bSaveAndValidate) {
		CVariantIterator vi(m_pPlugin->m_obCond.GetProperty("MACs"));
		for (COleVariant v; vi.Next(v);)
			m_lbxMACs.AddString(MacAddress(AsOptionalBlob(v)).ToString());
	}
}

void CFormMAC::OnAdd() {
	CDialogMAC d;
	if (d.DoModal() == IDOK) {
		m_lbxMACs.AddString(d.m_mac);
		SaveMACs();
	}	
}

void CFormMAC::OnEdit() {
	CDialogMAC d;
	int i = m_lbxMACs.CurSel;
	d.m_mac = m_lbxMACs.GetText(i);
	if (d.DoModal() == IDOK) {
		m_lbxMACs.DeleteString(i);
		m_lbxMACs.InsertString(i,d.m_mac);
		SaveMACs();
	}
}

void CFormMAC::OnDelete() {
	m_lbxMACs.DeleteString(m_lbxMACs.CurSel);
	SaveMACs();	
}

void CFormMAC::SaveMACs() {
	COdCollection coll = m_pPlugin->m_obCond.GetProperty("MACs");
	coll.DeleteAll();
	for (int i=0; i<m_lbxMACs.Count; i++)
		coll.Add(Blob(MacAddress(m_lbxMACs.GetText(i))));
}

#endif // UCFG_GUI

#if UCFG_WIN32
#	include "pcap-int.h"
#endif

extern "C" {
	pcap_handler g_callback;
	u_char *pcap_userdata;
}


void MACObj::OnReceived(SnifferPacket *sp) {
	if (g_callback) {
		pcap_pkthdr hdr;
		sp->TimeStamp.ToTimeval(hdr.ts);
		hdr.len = hdr.caplen = (u_int)sp->Size;
		g_callback(pcap_userdata,&hdr, sp->Data);
	}
	try {
		DBG_LOCAL_IGNORE(E_Sniffer_BadPacketFormat);

		Analyze(sp);
	} catch (RCExc e) {
		switch (e.HResult) {
		case E_Sniffer_BadPacketFormat:
		case E_Sniffer_BadChecksum:		
			TRC(0, e.Message);
			break;
		default:
			throw;
		}
	}
}

MACExObj::MACExObj(BYTE medium)
	:	MACObj(medium)
{
#if UCFG_GUI
	m_pViewClass = RUNTIME_CLASS(CFormMAC);
#endif
}

/*!!!

long GetEtherType(WORD w)
{
switch (w)
{
case ETHERTYPE_IP: return PROTO_IP;
case 0x0805: return PROTO_X25L3;
case ETHERTYPE_ARP: return PROTO_ARP;
case 0x1984: return PROTO_TRAIN;
case 0x2001: return PROTO_CGMP;
case 0x3c07: return PROTO_3C_NBP_DGRAM;
case 0x6000: return PROTO_DEC;
case 0x6001: return PROTO_DNA_DL;
case ETHERTYPE_MOPRC: return PROTO_DNA_RC;
case ETHERTYPE_DN: return PROTO_DNA_RT;
case ETHERTYPE_LAT: return PROTO_LAT;
case 0x6005: return PROTO_DEC_DIAG;
case 0x6006: return PROTO_DEC_CUST;
case 0x6007: return PROTO_DEC_SCA;
case 0x6558: return PROTO_ETHBRIDGE;
case ETHERTYPE_REVARP: return PROTO_REVARP;
case 0x8038: return PROTO_DEC_LB;
case ETHERTYPE_ATALK: return PROTO_ATALK;
case 0x80d5: return PROTO_SNA;
case 0x80f3: return PROTO_AARP;
case ETHERTYPE_IPX: return PROTO_IPX;
case 0x8100: return PROTO_VLAN;
case 0x814c: return PROTO_SNMP;
case 0x80ff: return PROTO_WCP;
case ETHERTYPE_IPV6: return PROTO_IPv6;
case 0x880b: return PROTO_PPP;
case 0x8847: return PROTO_MPLS;
case 0x8848: return PROTO_MPLS_MULTI;
case 0x8863: return PROTO_PPPOED;
case 0x8864: return PROTO_PPPOES;
case 0x888e: return PROTO_EAPOL;
case 0x9000: return PROTO_LOOP;
default: return PROTO_UNKNOWN;
}
}

*/

long MACPacket::GetProto() {
	return m_bLLC ? m_ethertype : GetType();
}

#define XDLC_CONTROL_LEN(control, is_extended) \
	((((control) & 0x3) == XDLC_U || !(is_extended)) ? 1 : 2)

void MACPacket::PreAnalyze() {
	if (m_bLLC) {
		ConstBuf mb = GetRawData();
		const byte *p = mb.P;
		int off = GetLocalDataOffset();
		if (mb.Size < off+2)
			Throw(E_Sniffer_BadPacketFormat);
		bool bIsSnap = mb.P[off] == SAP_SNAP && mb.P[off+1] == SAP_SNAP;
		m_dataOffset += 2;
		WORD control = mb.P[off+2];
		switch (mb.P[off+2] & 3)
		{
		case XDLC_U:
			break;
		case XDLC_S:
		default:
			if (mb.P[off+1] & SSAP_CR_BIT)	{//!!!
			}
		}
		m_dataOffset += XDLC_CONTROL_LEN(control, true);
		if (bIsSnap)
			m_dataOffset += 5;
		if (bIsSnap) {
			int oui = p[off+3] << 16 | p[off+4] << 8 | p[off+5];
			if (XDLC_IS_INFORMATION(control)) {
				WORD etype = pntohs(&p[off+6]);
				switch (oui) {

		case OUI_ENCAP_ETHER:
		case OUI_CISCO_90:
		case OUI_APPLE_ATALK:
		case OUI_CISCO:
			m_ethertype = etype;
			//!!!          m_dataOffset += 2;
			break;	
				}
			}

		} else {
			switch (p[off])
			{
				case SAP_IP:
					m_ethertype = ETHERTYPE_IP;
					break;
				case SAP_NETWARE:
					m_ethertype = ETHERTYPE_IPX;
					break;
				case SAP_NETBIOS:
					if (p[off+1] == SAP_NETBIOS)
						m_ethertype = ETHERTYPE_MY_NETBEUI;
					break;
			}
		}
	}
}

String MACPacket::GetField(RCString fieldID) {
	String name = fieldID;
	if (name == "Source")
		return GetSource().ToString();
	else if (name == "Destination")
		return GetDestination().ToString();
	else
		return PluginPacket::GetField(fieldID);
}

#if UCFG_OLE
void MACPacket::Info(CBag& bag) {
	CBag row;
	AddFieldInfo(row,"Source "+GetSource().ToString(), 6, 6);
	AddFieldInfo(row,"Destination "+GetDestination().ToString(), 0, 6);
	ostringstream os;
	os << "Protocol 0x" << hex << GetType();
	AddFieldInfo(row,os.str(), 12, 2);
	bag.Add((CBag("MAC"), row));
}
#endif

} // Snif::
