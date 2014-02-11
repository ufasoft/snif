/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#pragma once

#include "standard-plugin.h"

namespace Snif {


class GrePacket : public PluginPacket {
	DECLARE_DYNCREATE(GrePacket)
public:
	typedef GrePacket class_type;

	bool get_BitC() { return GetByte(0) & 0x80; }
	DEFPROP_GET(bool, BitC);

	bool get_BitR() { return GetByte(0) & 0x40; }
	DEFPROP_GET(bool, BitR);

	bool get_BitK() { return GetByte(0) & 0x20; }
	DEFPROP_GET(bool, BitK);

	bool get_BitS() { return GetByte(0) & 0x10; }
	DEFPROP_GET(bool, BitS);

	bool get_BitA() { return GetByte(1) & 0x80; }
	DEFPROP_GET(bool, BitA);

	byte get_Ver() { return GetByte(1) & 7; }
	DEFPROP_GET(byte, Ver);

	WORD get_Protocol() { return GetHWord(2); }
	DEFPROP_GET(WORD, Protocol);

	WORD get_PayloadLength() { return GetHWord(4); }
	DEFPROP_GET(WORD, PayloadLength);

	int GetSeqOffset() {
		int r = 4;
		if (BitC || BitR)
			r += 4;
		if (BitK)
			r += 4;
		return r;
	}

	DWORD get_Sequence() { return GetHDWord(GetSeqOffset()); }
	DEFPROP_GET(DWORD, Sequence);

	long GetProto() override {
		switch (Ver) {
		case 0:
			return PayloadLength ? Protocol : 0;
		default:
			return Protocol;
		}
	}

#if UCFG_OLE
	void Info(CBag& bag) override {
		PluginPacket::Info(bag);
		CBag row;
		AddFieldInfo(row, "Protocol "+Convert::ToString(Protocol), 2, 2);
		if (BitS)
			AddFieldInfo(row, "Seq "+Convert::ToString(Sequence), GetSeqOffset(), 4);
		ConstBuf mb = GetData();
		long off = GetLocalDataOffset();
		AddFieldInfo(row,"Data", off, mb.Size);
		bag.Add((CBag("GRE"), row));
	}
#endif

	Buf GetData() override {
		if (!m_mb.P) {
			m_mb = PluginPacket::GetData();
			m_mb.Size = PayloadLength; //!!!
			switch (Ver) {
			case 1:
				m_mb.P -= 2;
				m_mb.Size += 2;
				break;
			}

			/*!!!

				
				break;
			case 1:					// PPTP, RFC2637
#ifdef _DEBUG//!!!D
				m_mb.Size += 0;
#endif
				break;
			}*/
		}
		return m_mb;
	}

protected:
	int GetLocalDataOffset() override {
		int r = 4;
		switch (Ver) {
		case 0:
		case 1:
			if (BitC || BitR)
				r += 4;
			if (BitK)
				r += 4;
			if (BitS)
				r += 4;
			if (BitR)
				r += 4;
			if (BitA)
				r += 4;
			break;
		}
		return r;
	}

	Buf m_mb;

};


} // Snif::
