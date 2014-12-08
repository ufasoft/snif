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

#include "snif.h"
#include "sniffeng.h"

namespace Snif {

class PcapSnifEng : public SnifEngBase {
public:
	PcapSnifEng()
	{
	}

	void OpenAdapters();
	void Create(bool bEnabled);
	void BreakLoop();
private:
	CThreadRef m_tr;

//!!!	typedef CMTQueue<ILP_SnifferPacket> CPacketQueue;
//!!!	CPacketQueue m_queue;

friend class PcapAdapter;
};


} // Snif::


