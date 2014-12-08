/*###########################################################################################################################
# Copyright (c) 1997-2012 Ufasoft   http://ufasoft.com   mailto:support@ufasoft.com                                         #
#                                                                                                                           #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License #
# as published by the Free Software Foundation; either version 3, or (at your option) any later version.                    #                                                          #
#                                                                                                                           #
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied        #
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.     #
#                                                                                                                           #
# You should have received a copy of the GNU General Public License along with this program;                                #
# If not, see <http://www.gnu.org/licenses/>                                                                                #
###########################################################################################################################*/

#include <el/ext.h>

#include "standard-plugin.h"

//#include "netdissect.h"
//!!!#include "interface.h"  //!!!

#if UCFG_GUI
#	include "plugin-gui.h"
#endif

namespace Snif {


IMPLEMENT_DYNCREATE(IcmpPacket, PluginPacket)

struct tok {
	int v;			/* value */
	const char *s;		/* string */
};


static struct tok icmp2str[] = {
	{ ICMP_ECHOREPLY,		"echo reply" },
	{ ICMP_SOURCEQUENCH,		"source quench" },
	{ ICMP_ECHO,			"echo request" },
	{ ICMP_ROUTERSOLICIT,		"router solicitation" },
	{ ICMP_TSTAMP,			"time stamp request" },
	{ ICMP_TSTAMPREPLY,		"time stamp reply" },
	{ ICMP_IREQ,			"information request" },
	{ ICMP_IREQREPLY,		"information reply" },
	{ ICMP_MASKREQ,			"address mask request" },
	{ 0,				NULL }
};

String IcmpPacket::IcmpTypeToStr() {
	if (Type < _countof(icmp2str))
		return icmp2str[Type].s;
	else
		return "";
}

String IcmpPacket::IcmpCodeToStr() {
	return ""; //!!! dummy
}

#if UCFG_OLE
void IcmpPacket::Info(CBag& bag) {
  PluginPacket::Info(bag);
  CBag row;
  AddFieldInfo(row,"Type "+Convert::ToString(Type)+" "+IcmpTypeToStr(), 0, 1);
  AddFieldInfo(row,"Code "+Convert::ToString(Code)+" "+IcmpCodeToStr(), 1, 1);
  AddFieldInfo(row,"Checksum "+Convert::ToString(Checksum, "X8"), 2, 2);
  ConstBuf mb = GetData();
  long off = GetLocalDataOffset();
  AddFieldInfo(row,"Data", off, mb.Size);
  bag.Add((CBag("ICMP"), row));
}
#endif

#if UCFG_GUI
	class CFormICMP : public CConditionsView {
		DECLARE_DYNCREATE(CFormICMP)
	public:
		CFormICMP();

		//{{AFX_DATA(CFormICMP)
		enum { IDD = IDD_ICMP };
		//}}AFX_DATA

		//{{AFX_VIRTUAL(CFormICMP)
		protected:
		virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
		//}}AFX_VIRTUAL
	protected:

		//{{AFX_MSG(CFormICMP)

		//}}AFX_MSG
		DECLARE_MESSAGE_MAP()
	};

	CFormICMP::CFormICMP()
		:	CConditionsView(IDD)
	{
		//{{AFX_DATA_INIT(CDialogICMP)
		//}}AFX_DATA_INIT
	}

	void CFormICMP::DoDataExchange(CDataExchange* pDX) {
		CConditionsView::DoDataExchange(pDX);
		//{{AFX_DATA_MAP(CDialogICMP)
		//}}AFX_DATA_MAP
	}

	IMPLEMENT_DYNCREATE(CFormICMP, CConditionsView)

	BEGIN_MESSAGE_MAP(CFormICMP, CConditionsView)
		//{{AFX_MSG_MAP(CFormICMP)
		//}}AFX_MSG_MAP
	END_MESSAGE_MAP()

#endif

IcmpObj::IcmpObj() { 
  	m_name = "ICMP";
  	m_layer = PROTO_ICMP;
#if UCFG_GUI
  	m_pViewClass = RUNTIME_CLASS(CFormICMP);
#endif
  	m_pPacketClass = RUNTIME_CLASS(IcmpPacket);
}

void IcmpObj::ProcessPacket(PluginPacket *iPacket) {
	SnifferPlugin::ProcessPacket(iPacket);
	IcmpPacket *icmp = static_cast<IcmpPacket*>(iPacket);
	for (CSubscriber<IIcmpHook>::CSet::iterator i=m_subscriber.m_set.begin(), e=m_subscriber.m_set.end(); i!=e; ++i)
		(*i)->OnReceivedIcmp(icmp);
}



/*!!!class CIcmpPluginClass : public CStandardPluginClass
{
public:
  CIcmpPluginClass()
    :CStandardPluginClass(CLSID_ICMP,CIcmpObj::_CreateInstance,IDS_ICMP)
  {}*/

/*!!!  void Register()
  {
    CStandardPluginClass::Register();
    CArray<String> ar;
    ar.Add(StringFromCLSID(CLSID_IP));
    RegistryKey(HKEY_CLASSES_ROOT,"CLSID\\"+StringFromCLSID(m_clsid)).SetValue("Dependencies",ar);
  }*/
//!!!};


//!!!CIcmpPluginClass g_classICMP;

ptr<SnifferPlugin> CreateICMP() {
	return new IcmpObj;
}

extern "C" { PluginClass<IcmpObj,PROTO_ICMP> g_icmpClass; }

} // Snif::
