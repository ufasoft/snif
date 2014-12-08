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

const size_t MAX_RECOGNIZE = 8192;
const size_t MAX_COUT_MESSAGE_LEN = 2000;

const size_t HTTP_MAX_CONTENT = 65535;

const int HTTP_SKIP_TIME = 60,
					HTTP_EXPIRE_TIME = 600,
					HTTP_MAX_RECORDS = 1000;


const u_int64_t SMB_MAX_SIZE = 10000000; // 10 MB			

const DWORD EMAIL_MAX_SIZE = 5000000; // 5 MB			


} // Snif::