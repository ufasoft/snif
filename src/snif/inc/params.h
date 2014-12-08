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

const size_t MAX_PACKET_SIZE = 1000000;
const size_t PACKETS_AT_ONCE = 20;

const size_t DEFAULT_PACKET_QUEUE_SIZE = 65535; // (power of 2)-1
const int SPOOF_PERIOD = 40; // s

const size_t MAX_PACKETS_FROM_QUEUE = DEFAULT_PACKET_QUEUE_SIZE;

const size_t DRIVER_BUFFER_SIZE = 8*1024*1024, // 8 MB is enough for 1Gbps LAN
             MIN_DRIVER_BUFFER_SIZE = 100000,
						 MAX_DRIVER_BUFFER_SIZE = 100000000,
						 SENTARP_CACHE_SIZE = 10000,
						 RECV_QUEUE_SIZE = 256*1024,
             SEND_QUEUE_SIZE = 512*1024;


const int SNIF_POLL_TIME = 5;

const int SLEEP_TIME = 500;




const int VERIFY_HOSTS_PERIOD = 20; // s

const size_t MAXIMUM_PACKETS = 40000;

// IP
const size_t IP_MAX_FRAGMENTED_NUMBER = 256;

// TCP
const size_t TCP_MAX_PACKETS_AFTER_HOLE = 20;
const size_t TCP_DEFAULT_MAX_CONNECTIONS = 1000;


} // Snif::
