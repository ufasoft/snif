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

class IpxPacket : public PluginPacket {
	DECLARE_DYNCREATE(IpxPacket)
};

IMPLEMENT_DYNCREATE(IpxPacket, PluginPacket)

class IpxObj : public SnifferPlugin {
public:
	IpxObj() {
		m_name = "IPX";
		m_layer = PROTO_IPX;
#if UCFG_GUI
		m_pViewClass = RUNTIME_CLASS(CConditionsView);
#endif
		m_pPacketClass = RUNTIME_CLASS(IpxPacket);
	}

	void Bind() override {
		m_binder->m_mapEthernet[ETHERTYPE_IPX].insert(this);
	}

	void UnbindPlugin() override {
		m_binder->m_mapEthernet[ETHERTYPE_IPX].erase(this);
	}
};


/*!!!
class CIpxPluginClass : public CStandardPluginClass {
public:
CIpxPluginClass()
:CStandardPluginClass(CLSID_IPX,CIpxObj::_CreateInstance,IDS_IPX)
{}
} g_classIPX;
*/

ptr<SnifferPlugin> CreateIPX() {
	return new IpxObj;
}

static PluginClass<IpxObj, PROTO_IPX> g_ipxClass;

} // Snif::
