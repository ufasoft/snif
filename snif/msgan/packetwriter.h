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

#pragma once
#include <el/ext.h>

using namespace Snif;

class PacketWriter : public CProtoEng, public IMacHook {
	ptr<MACObj> m_macObj;
	ptr<MACObj> m_pppObj;
	bool m_bCreated;
public:
	void OnReceivedMac(MACPacket *sp) {
		cout << "X" << endl;
		if (g_opt_write_traffic) {
			ofstream out("traffic.dat", ios::app|ios::binary);
			ConstBuf mb = sp->GetRawData();
			out.write((char*)&mb.Size,4);
			out.write((char*)mb.P, mb.Size);
		}
	}
	PacketWriter()
		:	CProtoEng(true)
		,	m_bCreated(false)
	{
		m_bDirectThread = true;
		(m_macObj = GetMACObj(PROTO_ETHERNET))->SubscribeHook(this);
//		(m_pppObj = GetMACObj(PROTO_WAN))->SubscribeHook(this);
	}

	~PacketWriter() {
		m_macObj->UnsubscribeHook(this);
	}
};
