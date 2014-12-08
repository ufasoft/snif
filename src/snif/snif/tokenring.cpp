/*######     Copyright (c) 1997-2013 Ufasoft  http://ufasoft.com  mailto:support@ufasoft.com,  Sergey Pavlov  mailto:dev@ufasoft.com #######################################
#                                                                                                                                                                          #
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation;  #
# either version 3, or (at your option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the      #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details. You should have received a copy of the GNU #
# General Public License along with this program; If not, see <http://www.gnu.org/licenses/>                                                                               #
##########################################################################################################################################################################*/

#include <el/ext.h>

#include "standard-plugin.h"

namespace Snif {

class TokenRingPacket : public MACPacket {
	DECLARE_DYNCREATE(TokenRingPacket)
protected:
	MacAddress GetSource() {
		Blob blob(GetChunk(8,6),6);
		*blob.data() &= 0x7F;
		return MacAddress(ConstBuf(blob));
	}

	MacAddress GetDestination() { return MacAddress(ConstBuf(GetChunk(2,6),6)); }
	WORD GetType() { return GetHWord(GetLocalDataOffset()-2); }

	void PreAnalyze() override {
		ConstBuf mb = GetRawData();
		const byte *p = mb.P;
		//!!!R    long len = mb.m_len;
		int offset = 0;
		bool source_routed = p[8] & 0x80; //!!! was &=
		int trn_rif_bytes = p[14] & 31;
		int actual_rif_bytes = 0;
		int frame_type = (p[1] & 192) >> 6;
		if (source_routed) {
			actual_rif_bytes = trn_rif_bytes;
		} else {
			trn_rif_bytes = 0;
			actual_rif_bytes = 0;
		}

		if ((source_routed && trn_rif_bytes == 2 && frame_type == 1) ||
			(!source_routed && frame_type == 1)) {
				/* look for SNAP or IPX only */
				if ( (p[0x20] == 0xaa && p[0x21] == 0xaa && p[0x22] == 03) ||
					(p[0x20] == 0xe0 && p[0x21] == 0xe0) ) {
						actual_rif_bytes = 18;
				} else if (
					p[0x23] == 0 &&
					p[0x24] == 0 &&
					p[0x25] == 0 &&
					p[0x26] == 0x00 &&
					p[0x27] == 0x11) {

						actual_rif_bytes = 18;

						/* Linux 2.0.x also requires drivers pass up a fake SNAP and LLC header before th
						real LLC hdr for all Token Ring frames that arrive with DSAP and SSAP != 0xAA
						(i.e. for non SNAP frames e.g. for Netware frames)
						the fake SNAP header has the ETH_P_TR_802_2 ether type (0x0011) and the protocol id
						bytes as zero frame looks like :-
						TR Header | Fake LLC | Fake SNAP | Wire LLC | Rest of data */
						offset += 8; /* Skip fake LLC and SNAP */
				}
		}


		m_dataOffset = actual_rif_bytes + 14;

		if (frame_type == 1) {
			m_bLLC = true;
			MACPacket::PreAnalyze();
		}
	}
};

class TokenRingObj : public MACExObj {
public:
	TokenRingObj()
		:	MACExObj(PROTO_TOKENRING)
	{
		m_name = "TokenRing";
		m_layer = PROTO_TOKENRING;
		m_pPacketClass = RUNTIME_CLASS(TokenRingPacket);
	}
};

IMPLEMENT_DYNCREATE(TokenRingPacket, PluginPacket)


//!!!CStandardPluginClass g_classTokenRing(CLSID_TokenRing,CTokenRingObj::_CreateInstance,IDS_TOKENRING);


ptr<MACObj> CreateTokenRing() {
	return new TokenRingObj;
}

extern "C" { PluginClass<TokenRingObj,PROTO_TOKENRING> g_tokenRingClass; }

} // Snif::
