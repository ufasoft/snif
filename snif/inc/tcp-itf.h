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

namespace Snif {

#ifndef ENUM_CLASS		//!!! from libext
#	define ENUM_CLASS(name) struct enum_##name { enum E
#	define ENUM_CLASS_BASED(name, base) struct enum_##name { enum E : base
#	define END_ENUM_CLASS(name) ; }; typedef enum_##name::E name; inline name operator|(name a, name b) { return (name)((int)a|(int)b); }
#endif

ENUM_CLASS(Direction) {
	Unknown,
	Outgoing,
	Incoming
} END_ENUM_CLASS(Direction);

interface IDisconnectable {
	virtual void Disconnect() =0;
};

interface ISimpleConnection : IDisconnectable {
	virtual Direction GetDirection() =0;
};

interface ISimpleTcpConnection : ISimpleConnection {
public:
	virtual DWORD GetSrcIP() =0;
	virtual DWORD GetDstIP() =0;
	virtual WORD GetSrcPort() =0;
	virtual WORD GetDstPort() =0;
};

} // Snif::


