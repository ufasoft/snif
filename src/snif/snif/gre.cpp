/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "gre.h"

namespace Snif {



IMPLEMENT_DYNCREATE(GrePacket, PluginPacket)

class GreObj : public SnifferPlugin {
	typedef SnifferPlugin base;
public:
	GreObj() {
		m_name = "GRE";
		m_layer = PROTO_GRE;
		m_pPacketClass = RUNTIME_CLASS(GrePacket);
	}
protected:
	void Bind() override {
		m_binder->m_mapIp[IPPROTO_GRE].insert(this);
	}

	void UnbindPlugin() override {
		m_binder->m_mapIp[IPPROTO_GRE].erase(this);
	}

	AnalyzerBinder::Map *GetProtocolMap() override {
		return &m_binder->m_mapEthernet;
	}

	void ProcessSubAnalyzers(PluginPacket *iPacket) override {
		GrePacket *gre = static_cast<GrePacket*>(iPacket);
		if (gre->Ver == 1) {
			if (gre->PayloadLength != 0) {
				AnalyzerBinder::Map::iterator i = m_binder->m_map.find(PROTO_WAN);
				if (i !=  m_binder->m_map.end()) { 
					AnalyzerBinder::Subscribers& subs = i->second;
					for (AnalyzerBinder::Subscribers::iterator j=subs.begin(); j!=subs.end(); ++j)
						(*j)->Analyze(iPacket);
				}
			}
		} else
			base::ProcessSubAnalyzers(iPacket);
	}
};

extern "C" { PluginClass<GreObj, PROTO_GRE> g_greClass; }

} // Snif::
