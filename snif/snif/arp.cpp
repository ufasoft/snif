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

namespace Snif {

IMPLEMENT_DYNCREATE(ArpPacket, PluginPacket)

#if UCFG_OLE
void ArpPacket::Info(CBag& bag) {
	PluginPacket::Info(bag);
	CBag row;
//!!! TODO  AddFieldInfo(row, "Target", GetLocalDataOffset(),6);

	bag.Add((CBag("ARP"),row));
}
#endif

void ArpObj::ProcessPacket(PluginPacket *iPacket) {
	SnifferPlugin::ProcessPacket(iPacket);
	ArpPacket *iArp = static_cast<ArpPacket*>(iPacket);
	for (size_t i=m_subscribers.size(); i--;)
		m_subscribers[i]->OnReceivedArp(iArp);
}

ptr<ArpPacket> ArpObj::ComposePacket() {
	ptr<ArpPacket> r = new ArpPacket;
	r->m_iBase = new(12) SnifferPacket;
	return r;
}

ptr<SnifferPlugin> CreateARP() {
	return new ArpObj;
}

static PluginClass<ArpObj, PROTO_ARP> g_arpClass;

} // Snif::
