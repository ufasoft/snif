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

IMPLEMENT_DYNCREATE(NetBEUIPacket, PluginPacket)

WORD NetBEUIPacket::get_HeaderLength() {
	WORD w = GetWord(0);
	if (w > m_iBase->GetData().Size)
		Throw(E_Sniffer_BadPacketFormat);
	return w;
}

NetBEUIObj::NetBEUIObj() {
	m_name = "NetBEUI";
	m_layer = PROTO_NETBEUI;
#if UCFG_GUI
	m_pViewClass = RUNTIME_CLASS(CConditionsView);
#endif
	m_pPacketClass = RUNTIME_CLASS(NetBEUIPacket);
}

void NetBEUIObj::ProcessPacket(PluginPacket *iPacket) {
	SnifferPlugin::ProcessPacket(iPacket);
	NetBEUIPacket *netbeui = (NetBEUIPacket*)iPacket;
	for (CSubscriber<INetbeuiHook>::CSet::iterator i=m_subscriber.m_set.begin(), e=m_subscriber.m_set.end(); i!=e; ++i)
		(*i)->OnReceivedNetbeui(netbeui);
}


/*!!!
class CNetBEUIPluginClass : public CStandardPluginClass {
public:
	CNetBEUIPluginClass()
:	CStandardPluginClass(CLSID_NetBEUI,CNetBEUIObj::_CreateInstance,IDS_NETBEUI)
{}
} g_classNetBEUI;
*/

ptr<SnifferPlugin> CreateNetBEUI() {
	return new NetBEUIObj;
}

extern "C" { PluginClass<NetBEUIObj, PROTO_NETBEUI> g_netBEUIClass; }

} // Snif::
