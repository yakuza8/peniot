/* packet-btle.c
 * Routines for Bluetooth Low Energy dissection
 * Copyright 2013, Mike Ryan, mikeryan /at/ isecpartners /dot/ com
 * Copyright 2014, Nordic Semiconductor ASA
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
 
// #include <wireshark/config.h> /* needed for epan/gcc-4.x */
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>
#include <stdio.h>


/* LL control opcodes */
#define LL_CONNECTION_UPDATE_REQ 0x00 
#define LL_CHANNEL_MAP_REQ 0x01 
#define LL_TERMINATE_IND 0x02
#define LL_ENC_REQ 0x03
#define LL_ENC_RSP 0x04 
#define LL_START_ENC_REQ 0x05
#define LL_START_ENC_RSP 0x06
#define LL_UNKNOWN_RSP 0x07
#define LL_FEATURE_REQ 0x08
#define LL_FEATURE_RSP 0x09
#define LL_PAUSE_ENC_REQ 0x0A
#define LL_PAUSE_ENC_RSP 0x0B
#define LL_VERSION_IND 0x0C
#define LL_REJECT_IND 0x0D


/* function prototypes */
void proto_reg_handoff_btle(void);

/* initialize the protocol and registered fields */
static int proto_btle = -1;
static int hf_btle_pkthdr = -1;
static int hf_btle_aa = -1;
static int hf_btle_type = -1;
static int hf_btle_randomized_tx = -1;
static int hf_btle_randomized_rx = -1;
static int hf_btle_length = -1;
static int hf_btle_adv_addr = -1;
static int hf_btle_adv_data = -1;
static int hf_btle_init_addr = -1;
static int hf_btle_scan_addr = -1;
static int hf_btle_scan_rsp_data = -1;
static int hf_btle_connect = -1;
static int hf_btle_connect_aa = -1;
static int hf_btle_crc_init = -1;
static int hf_btle_win_size = -1;
static int hf_btle_win_offset = -1;
static int hf_btle_interval = -1;
static int hf_btle_min_interval = -1;
static int hf_btle_max_interval = -1;
static int hf_btle_latency = -1;
static int hf_btle_timeout = -1;
static int hf_btle_hop_interval = -1;
static int hf_btle_sleep_clock_accuracy = -1;
static int hf_btle_data = -1;
static int hf_btle_data_llid = -1;
static int hf_btle_data_nesn = -1;
static int hf_btle_data_sn = -1;
static int hf_btle_data_md = -1;
static int hf_btle_data_rfu = -1;
static int hf_btle_ll_control = -1;
static int hf_btle_ll_control_opcode = -1;
static int hf_btle_ll_control_data = -1;
static int hf_btle_ll_control_ll_enc_req = -1;
static int hf_btle_ll_control_ll_enc_req_rand = -1;
static int hf_btle_ll_control_ll_enc_req_ediv = -1;
static int hf_btle_ll_control_ll_enc_req_skdm = -1;
static int hf_btle_ll_control_ll_enc_req_ivm = -1;
static int hf_btle_ll_control_ll_enc_rsp = -1;
static int hf_btle_ll_control_ll_enc_rsp_skds = -1;
static int hf_btle_ll_control_ll_enc_rsp_ivs = -1;
static int hf_btle_crc = -1;
static int hf_btle_instant = -1;
static int hf_btle_channel_map = -1;
static int hf_btle_enabled_channels = -1;
static int hf_btle_error_code = -1;
static int hf_btle_unknown_type = -1;
static int hf_btle_feature_set = -1;
static int hf_btle_supported_feature = -1;
static int hf_btle_unsupported_feature = -1;
static int hf_btle_bt_version = -1;
static int hf_btle_company_id = -1;
static int hf_btle_sub_version_num = -1;

static int hf_btle_adv_data_attr = -1;
static int hf_btle_adv_data_attr_type = -1;
static int hf_btle_adv_data_attr_length = -1;
static int hf_btle_adv_data_attr_value = -1;
static int hf_btle_adv_data_attr_value_string = -1;

// #if 0
// static int hf_btle_adv_data_flags = -1;
// static int hf_btle_adv_data_inc_16b_uuids = -1;
// static int hf_btle_adv_data_com_16b_uuids = -1;
// static int hf_btle_adv_data_inc_32b_uuids = -1;
// static int hf_btle_adv_data_com_32b_uuids = -1;
// static int hf_btle_adv_data_inc_128b_uuids = -1;
// static int hf_btle_adv_data_com_128b_uuids = -1;
// static int hf_btle_adv_data_short_local_name = -1;
// static int hf_btle_adv_data_com_local_name = -1;
// static int hf_btle_adv_data_tx_power = -1;
// static int hf_btle_adv_data_dev_class = -1;
// static int hf_btle_adv_data_pair_hash_c = -1;
// static int hf_btle_adv_data_pair_rand_r = -1;
// static int hf_btle_adv_data_dev_id = -1;
// static int hf_btle_adv_data_sec_man_oob_flags = -1;
// static int hf_btle_adv_data_conn_int_range = -1;
// static int hf_btle_adv_data_16b_service_uuids = -1;
// static int hf_btle_adv_data_128b_service_uuids = -1;
// static int hf_btle_adv_data_service_data = -1;
// static int hf_btle_adv_data_pub_target_addr = -1;
// static int hf_btle_adv_data_rand_target_addr = -1;
// static int hf_btle_adv_data_appearance = -1;
// static int hf_btle_adv_data_adv_int = -1;
// static int hf_btle_adv_data_manufacturer = -1;


#define index_hf_btle_adv_data_flags 1
#define index_hf_btle_adv_data_inc_16b_uuids 2
#define index_hf_btle_adv_data_com_16b_uuids 3
#define index_hf_btle_adv_data_inc_32b_uuids 4
#define index_hf_btle_adv_data_com_32b_uuids 5
#define index_hf_btle_adv_data_inc_128b_uuids 6
#define index_hf_btle_adv_data_com_128b_uuids 7
#define index_hf_btle_adv_data_short_local_name 8
#define index_hf_btle_adv_data_com_local_name 9
#define index_hf_btle_adv_data_tx_power 10
#define index_hf_btle_adv_data_dev_class 13
#define index_hf_btle_adv_data_pair_hash_c 14
#define index_hf_btle_adv_data_pair_rand_r 15
#define index_hf_btle_adv_data_dev_id 16
#define index_hf_btle_adv_data_sec_man_oob_flags 17
#define index_hf_btle_adv_data_conn_int_range 18
#define index_hf_btle_adv_data_16b_service_uuids 20
#define index_hf_btle_adv_data_128b_service_uuids 21
#define index_hf_btle_adv_data_service_data 22
#define index_hf_btle_adv_data_pub_target_addr 23
#define index_hf_btle_adv_data_rand_target_addr 24
#define index_hf_btle_adv_data_appearance 25
#define index_hf_btle_adv_data_adv_int 26
#define index_hf_btle_adv_data_service_data_32b 0x20
#define index_hf_btle_adv_data_service_data_128b 0x21
// #define index_hf_btle_adv_data_manufacturer 255


static int hf_btle_adv_data_attrs[40] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
static int hf_btle_adv_data_manufacturer = -1;
static int hf_btle_adv_data_unknown = -1;

static int hf_btle_adv_data_flag_le_limited_discoverable = -1;
static int hf_btle_adv_data_flag_le_general_discoverable = -1;
static int hf_btle_adv_data_flag_br_edr_not_supported = -1;
static int hf_btle_adv_data_flag_simultaneous_le_br_edr_controller = -1;
static int hf_btle_adv_data_flag_simultaneous_le_br_edr_host = -1;

static int hf_btle_128b_uuid = -1;
static int hf_btle_32b_uuid = -1;
static int hf_btle_16b_uuid = -1;

static int hf_service_data_value = -1;
static int hf_btle_adv_data_adv_int_ms = -1;


// static expert_field ei_btle_packet_too_short = EI_INIT;
// static expert_field ei_btle_packet_too_long = EI_INIT;


// #endif


static const value_string packet_types[] = {
	{ 0x0, "ADV_IND" },
	{ 0x1, "ADV_DIRECT_IND" },
	{ 0x2, "ADV_NONCONN_IND" },
	{ 0x3, "SCAN_REQ" },
	{ 0x4, "SCAN_RSP" },
	{ 0x5, "CONNECT_REQ" },
	{ 0x6, "ADV_SCAN_IND" },
	{ 0, NULL }
};

static const value_string llid_codes[] = {
	{ 0x0, "undefined" },
	{ 0x1, "Continuation fragment of an L2CAP message" },
	{ 0x2, "Start of an L2CAP message or no fragmentation" },
	{ 0x3, "LL Control PDU" },
	{ 0, NULL }
};

static const value_string ll_control_opcodes[] = {
	{ 0x00, "LL_CONNECTION_UPDATE_REQ" },
	{ 0x01, "LL_CHANNEL_MAP_REQ" },
	{ 0x02, "LL_TERMINATE_IND" },
	{ 0x03, "LL_ENC_REQ" },
	{ 0x04, "LL_ENC_RSP" },
	{ 0x05, "LL_START_ENC_REQ" },
	{ 0x06, "LL_START_ENC_RSP" },
	{ 0x07, "LL_UNKNOWN_RSP" },
	{ 0x08, "LL_FEATURE_REQ" },
	{ 0x09, "LL_FEATURE_RSP" },
	{ 0x0A, "LL_PAUSE_ENC_REQ" },
	{ 0x0B, "LL_PAUSE_ENC_RSP" },
	{ 0x0C, "LL_VERSION_IND" },
	{ 0x0D, "LL_REJECT_IND" },
	{ 0, NULL }
};

static const value_string adv_data_attr_types[] = {
	{ 0x01, "Flags" },
	{ 0x02, "Incomplete List of 16-bit Service Class UUIDs" },
	{ 0x03, "Complete List of 16-bit Service Class UUIDs" },
	{ 0x04, "Incomplete List of 32-bit Service Class UUIDs" },
	{ 0x05, "Complete List of 32-bit Service Class UUIDs" },
	{ 0x06, "Incomplete List of 128-bit Service Class UUIDs" },
	{ 0x07, "Complete List of 128-bit Service Class UUIDs" },
	{ 0x08, "Shortened Local Name" },
	{ 0x09, "Complete Local Name" },
	{ 0x0A, "Tx Power Level" },
	{ 0x0D, "Class of Device" },
	{ 0x0E, "Simple Pairing Hash C" },
	{ 0x0F, "Simple Pairing Randomizer R" },
	{ 0x10, "Device ID / Security Manager TK Value" },
	{ 0x11, "Security Manager Out of Band Flags" },
	{ 0x12, "Slave Connection Interval Range" },
	{ 0x14, "List of 16-bit Service Solicitation UUIDs" },
	{ 0x15, "List of 128-bit Service Solicitation UUIDs" },
	{ 0x16, "Service Data for 16 bit UUID." },
	{ 0x17, "Public Target Address" },
	{ 0x18, "Random Target Address" },
	{ 0x19, "Appearance" },
	{ 0x1A, "Advertising Interval" },
	{ 0x20, "Service Data for 32 bit UUID." },
	{ 0x21, "Service Data for 128 bit UUID." },
	{ 0x21, "Advertising Interval" },
	{ 0xFF, "Manufacturer Specific Data" },
	{ 0xFE, "Unknown type" }

};

static const value_string sleep_clock_accuracy_values[] = {
	{ 0x00, "251 ppm to 500 ppm" },
	{ 0x01, "151 ppm to 250 ppm" },
	{ 0x02, "101 ppm to 150 ppm" },
	{ 0x03, "76 ppm to 100 ppm" },
	{ 0x04, "51 ppm to 75 ppm" },
	{ 0x05, "31 ppm to 50 ppm" },
	{ 0x06, "21 ppm to 30 ppm" },
	{ 0x07, "0 ppm to 20 ppm" }

};

static const value_string error_codes[] = {
	{ 0x00, "Success" },
	{ 0x01, "Unknown HCI Command" },
	{ 0x02, "Unknown Connection Identifier" },
	{ 0x03, "Hardware Failure" },
	{ 0x04, "Page Timeout" },
	{ 0x05, "Authentication Failure" },
	{ 0x06, "PIN or Key Missing" },
	{ 0x07, "Memory Capacity Exceeded" },
	{ 0x08, "Connection Timeout" },
	{ 0x09, "Connection Limit Exceeded" },
	{ 0x0A, "Synchronous Connection Limit To A Device Exceeded" },
	{ 0x0B, "ACL Connection Already Exists" },
	{ 0x0C, "Command Disallowed" },
	{ 0x0D, "Connection Rejected due to Limited Resources" },
	{ 0x0E, "Connection Rejected Due To Security Reasons" },
	{ 0x0F, "Connection Rejected due to Unacceptable BD_ADDR" },
	{ 0x10, "Connection Accept Timeout Exceeded" },
	{ 0x11, "Unsupported Feature or Parameter Value" },
	{ 0x12, "Invalid HCI Command Parameters" },
	{ 0x13, "Remote User Terminated Connection" },
	{ 0x14, "Remote Device Terminated Connection due to Low Resources" },
	{ 0x15, "Remote Device Terminated Connection due to Power Off" },
	{ 0x16, "Connection Terminated By Local Host" },
	{ 0x17, "Repeated Attempts" },
	{ 0x18, "Pairing Not Allowed" },
	{ 0x19, "Unknown LMP PDU" },
	{ 0x1A, "Unsupported Remote Feature / Unsupported LMP Feature" },
	{ 0x1B, "SCO Offset Rejected" },
	{ 0x1C, "SCO Interval Rejected" },
	{ 0x1D, "SCO Air Mode Rejected" },
	{ 0x1E, "Invalid LMP Parameters" },
	{ 0x1F, "Unspecified Error" },
	{ 0x20, "Unsupported LMP Parameter Value" },
	{ 0x21, "Role Change Not Allowed" },
	{ 0x22, "LMP Response Timeout / LL Response Timeout" },
	{ 0x23, "LMP Error Transaction Collision" },
	{ 0x24, "LMP PDU Not Allowed" },
	{ 0x25, "Encryption Mode Not Acceptable" },
	{ 0x26, "Link Key cannot be Changed" },
	{ 0x27, "Requested QoS Not Supported" },
	{ 0x28, "Instant Passed" },
	{ 0x29, "Pairing With Unit Key Not Supported" },
	{ 0x2A, "Different Transaction Collision" },
	{ 0x2B, "Reserved" },
	{ 0x2C, "QoS Unacceptable Parameter" },
	{ 0x2D, "QoS Rejected" },
	{ 0x2E, "Channel Classification Not Supported" },
	{ 0x2F, "Insufficient Security" },
	{ 0x30, "Parameter Out Of Mandatory Range" },
	{ 0x31, "Reserved" },
	{ 0x32, "Role Switch Pending" },
	{ 0x33, "Reserved" },
	{ 0x34, "Reserved Slot Violation" },
	{ 0x35, "Role Switch Failed" },
	{ 0x36, "Extended Inquiry Response Too Large" },
	{ 0x37, "Secure Simple Pairing Not Supported By Host." },
	{ 0x38, "Host Busy - Pairing" },
	{ 0x39, "Connection Rejected due to No Suitable Channel Found" },
	{ 0x3A, "Controller Busy" },
	{ 0x3B, "Unacceptable Connection Interval" },
	{ 0x3C, "Directed Advertising Timeout" },
	{ 0x3D, "Connection Terminated due to MIC Failure" },
	{ 0x3E, "Connection Failed to be Established" },
	{ 0x3F, "MAC Connection Failed" }
};

/* These are the BR/EDR features. They are not used presently, but might be later. */
/* See below for LE feature set. */
static const value_string features[] = {
	{ 0, "3 slot packets" },
	{ 1, "5 slot packets" },
	{ 2, "Encryption" },
	{ 3, "Slot offset" },
	{ 4, "Timing accuracy" },
	{ 5, "Role switch" },
	{ 6, "Hold mode" },
	{ 7, "Sniff mode" },
	{ 8, "Park state" },
	{ 9, "Power control requests" },
	{ 10, "Channel quality driven data rate (CQDDR)" },
	{ 11, "SCO link" },
	{ 12, "HV2 packets " },
	{ 13, "HV3 packets" },
	{ 14, "mu-law log synchronous data" },
	{ 15, "A-law log synchronous data" },
	{ 16, "CVSD synchronous data" },
	{ 17, "Paging parameter negotiation" },
	{ 18, "Power control" },
	{ 19, "Transparent synchronous data" },
	{ 20, "Flow control lag (least significant bit)" },
	{ 21, "Flow control lag (middle bit)" },
	{ 22, "Flow control lag (most significant bit)" },
	{ 23, "Broadcast Encryption" },
	{ 24, "Reserved" },
	{ 25, "Enhanced Data Rate ACL 2 Mbps mode" },
	{ 26, "Enhanced Data Rate ACL 3 Mbps mode" },
	{ 27, "Enhanced inquiry scan" },
	{ 28, "Interlaced inquiry scan" },
	{ 29, "Interlaced page scan" },
	{ 30, "RSSI with inquiry results" },
	{ 31, "Extended SCO link (EV3 packets)" },
	{ 32, "EV4 packets" },
	{ 33, "EV5 packets" },
	{ 34, "Reserved" },
	{ 35, "AFH capable slave " },
	{ 36, "AFH classification slave " },
	{ 37, "BR/EDR Not Supported" },
	{ 38, "LE Supported (Controller)" },
	{ 39, "3-slot Enhanced Data Rate ACL packets" },
	{ 40, "5-slot Enhanced Data Rate ACL packets" },
	{ 41, "Sniff subrating" },
	{ 42, "Pause encryption" },
	{ 43, "AFH capable master " },
	{ 44, "AFH classification master " },
	{ 45, "Enhanced Data Rate eSCO 2 Mbps mode" },
	{ 46, "Enhanced Data Rate eSCO 3 Mbps mode" },
	{ 47, "3-slot Enhanced Data Rate eSCO packets" },
	{ 48, "Extended Inquiry Response" },
	{ 49, "Simultaneous LE and BR/EDR to Same Device Capable (Controller)" },
	{ 50, "Reserved" },
	{ 51, "Secure Simple Pairing" },
	{ 52, "Encapsulated PDU" },
	{ 53, "Erroneous Data Reporting" },
	{ 54, "Non-flushable Packet Boundary Flag" },
	{ 55, "Reserved" },
	{ 56, "Link Supervision Timeout Changed Event" },
	{ 57, "Inquiry TX Power Level" },
	{ 58, "Enhanced Power Control" },
	{ 59, "Reserved" },
	{ 60, "Reserved" },
	{ 61, "Reserved" },
	{ 62, "Reserved" },
	{ 63, "Extended features" }
};

static const value_string le_features[] = {
	{ 0, "LE Encryption"}
};

static const true_false_string addr_flag_tfs = 
{
	"random",
	"public"
};


static const guint32 ADV_AA = 0x8e89bed6;
static const char nondirect_dst[] = "<broadcast>";
static const guint8 nondirect_dst_string_length = 12;

static const char implicit_src[] = "<implicit>";
static const guint8 implicit_src_string_length = 11;

static const char implicit_dst[] = "<implicit>";
static const guint8 implicit_dst_string_length = 11;

/* initialize the subtree pointers */
static gint ett_btle = -1;
static gint ett_btle_pkthdr = -1;
static gint ett_btle_connect = -1;
static gint ett_btle_data = -1;
static gint ett_ll_enc_req = -1;
static gint ett_ll_enc_rsp = -1;
static gint ett_ll_control = -1;
static gint ett_ll_control_data = -1;
static gint ett_feature_set = -1;
static gint ett_channel_map = -1;

static gint ett_adv_data = -1;
static gint ett_adv_data_attr = -1;
static gint ett_adv_data_flags = -1;
static gint ett_uuids = -1;

/* subdissectors */
static dissector_handle_t btl2cap_handle = NULL;


void
reverse_byte_order(guint8* dest, const guint8* src, guint size)
{
	guint i;
	for (i = 0; i < size; i++)
	{
		dest[i] = src[size-1-i];
	}
}

void
reverse_byte_order_inplace(guint8* array, guint size)
{
	guint i;
	guint8 tmp;
	for (i = 0; i < size/2; i++)
	{
		tmp = array[i];
		array[i] = array[size-1-i];
		array[size-1-i] = tmp;
	}
}

void
dissect_feature_set(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree* feature_set_tree;
	proto_item* feature_set_item;
	int i;
	guint64 feature_set;
	
	feature_set_item = proto_tree_add_item (tree, hf_btle_feature_set,	tvb, offset, 8, ENC_LITTLE_ENDIAN);
	feature_set_tree = proto_item_add_subtree(feature_set_item, ett_feature_set);
	
	feature_set = tvb_get_letoh64(tvb, offset);
	
	for (i = 0; i < 1; i++)
	{
		if (feature_set & ((guint64)1 << i))
		{
			proto_tree_add_uint(feature_set_tree, hf_btle_supported_feature, tvb, offset+(i/8), 1, i);
		}
		else
		{
			proto_tree_add_uint(feature_set_tree, hf_btle_unsupported_feature, tvb, offset+(i/8), 1, i);
		}
	}
}

void
dissect_channel_map(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item* map_item;
	proto_tree* map_tree;
	int i;
	guint64 map;
	gchar format[200] = "Enabled channels: ";
	gchar* format_pointer = &format[18];
	
	map_item = proto_tree_add_item(tree, hf_btle_channel_map, tvb, offset, 5, ENC_LITTLE_ENDIAN);
	map_tree = proto_item_add_subtree(map_item, ett_channel_map);
	
	map = tvb_get_letoh64(tvb, offset);
	for (i = 0; i < 37; i++)
	{
		if (map & ((guint64)1 << i))
		{
			sprintf(format_pointer, "%2d, ", i);
		}
		else
		{
			sprintf(format_pointer, "  , ", i);
		}
		// format_pointer = (i<10) ? format_pointer+3 : format_pointer+4;
		format_pointer = format_pointer+4;
	}
	proto_tree_add_text(map_tree, tvb, offset, 5, &format[0]);
}


proto_tree* add_adv_data_attr(proto_tree* tree, tvbuff_t* tvb, const int hf, const guint8 length, const guint enc)
{
	proto_item* attr_item;
	proto_tree* attr_tree;
	guint8 type;
	attr_item = proto_tree_add_item(tree, hf, tvb, 2, length-1, enc);
	attr_tree = proto_item_add_subtree(attr_item, ett_adv_data_flags);
	
	type = tvb_get_guint8(tvb, 1);
	
	proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_length, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	if (hf == hf_btle_adv_data_unknown)
	{
		proto_tree_add_uint_format_value(attr_tree, hf_btle_adv_data_attr_type, tvb, 1, 1, type, "Unknown type (%#2x)", type);
	}
	else
	{
		proto_tree_add_uint(attr_tree, hf_btle_adv_data_attr_type, tvb, 1, 1, type);
	}
	// proto_tree_add_item(attr_tree, hf_btle_adv_data_attrs[type], tvb, 2, length-1, enc);
	
	return attr_tree;
}

// void
// dissect_service_data(proto_tree *tree, tvbuff_t *tvb, length)
// {
// }

void
dissect_adv_data_attr(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo)
{
	// proto_item* attr_length_item;
	// proto_item* attr_type_item;
	// proto_item* attr_value_item;
	// proto_item* attr_value_string_item;
	// proto_item* attr_item;
	proto_tree* attr_tree;
	int i;
	guint8* name;
	guint8* uuids;
	gint8 tx_power;
	gfloat min_interval, max_interval, adv_interval, tmp;
	guint16 max_interval_raw;
	// guint8 temp_uuid[16];
	wmem_allocator_t* epan_scope_mem_pool;
	guint8 address[6];

	
	guint8 length, type;
	
	length = tvb_get_guint8(tvb, 0);
	type = tvb_get_guint8(tvb, 1);
	
	// if (type == 0 || type == 11 || type == 12 || type == 19 || (type > 26 && type != 255))
		// return;

	// attr_item 		 = proto_tree_add_item(tree, hf_btle_adv_data_attrs[type], tvb, 0, tvb_length(tvb), ENC_LITTLE_ENDIAN);
	// attr_tree 		 = proto_item_add_subtree(attr_item, ett_adv_data_attr);
	
	// attr_length_item = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_length, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	// attr_type_item 	 = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_type, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	 
	
	switch(type){
		case index_hf_btle_adv_data_flags:
			// attr_item = proto_tree_add_item(tree, hf_btle_adv_data_attrs[type], tvb, 2, length-1, ENC_LITTLE_ENDIAN);
			// attr_tree = proto_item_add_subtree(attr_item, ett_adv_data_flags);
			// attr_length_item = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_length, tvb, 0, 1, ENC_LITTLE_ENDIAN);
			// attr_type_item 	 = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_type, tvb, 1, 1, ENC_LITTLE_ENDIAN);
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			proto_tree_add_bits_item(attr_tree, hf_btle_adv_data_flag_simultaneous_le_br_edr_host, 		 tvb, 3*8 - 5, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_bits_item(attr_tree, hf_btle_adv_data_flag_simultaneous_le_br_edr_controller, tvb, 3*8 - 4, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_bits_item(attr_tree, hf_btle_adv_data_flag_br_edr_not_supported, 			 tvb, 3*8 - 3, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_bits_item(attr_tree, hf_btle_adv_data_flag_le_general_discoverable, 			 tvb, 3*8 - 2, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_bits_item(attr_tree, hf_btle_adv_data_flag_le_limited_discoverable, 			 tvb, 3*8 - 1, 1, ENC_LITTLE_ENDIAN);
			break;
		case index_hf_btle_adv_data_com_128b_uuids:
		case index_hf_btle_adv_data_inc_128b_uuids:
		case index_hf_btle_adv_data_128b_service_uuids:
			// attr_item = proto_tree_add_item(tree, hf_btle_adv_data_attrs[type], tvb, 2, length-1, ENC_LITTLE_ENDIAN);
			// attr_tree = proto_item_add_subtree(attr_item, ett_uuids);
			// attr_length_item = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_length, tvb, 0, 1, ENC_LITTLE_ENDIAN);
			// attr_type_item 	 = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_type, tvb, 1, 1, ENC_LITTLE_ENDIAN);
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			epan_scope_mem_pool = wmem_epan_scope();
			uuids = wmem_alloc(epan_scope_mem_pool, length);
			for (i = 2; i < length; i += 16)
			{
				tvb_memcpy(tvb, &uuids[i], i, 16);
				reverse_byte_order_inplace(&uuids[i], 16);
				proto_tree_add_bytes(attr_tree, hf_btle_128b_uuid, tvb, i, 16, &uuids[i]);
			} 
			break;
		case index_hf_btle_adv_data_com_32b_uuids:
		case index_hf_btle_adv_data_inc_32b_uuids:
			// attr_item = proto_tree_add_item(tree, hf_btle_adv_data_attrs[type], tvb, 2, length-1, ENC_LITTLE_ENDIAN);
			// attr_tree = proto_item_add_subtree(attr_item, ett_uuids);
			// attr_length_item = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_length, tvb, 0, 1, ENC_LITTLE_ENDIAN);
			// attr_type_item 	 = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_type, tvb, 1, 1, ENC_LITTLE_ENDIAN);
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			for (i = 2; i < length; i += 4)
			{
				proto_tree_add_item(attr_tree, hf_btle_32b_uuid, tvb, i, 4, ENC_LITTLE_ENDIAN);
			}
			break;
		case index_hf_btle_adv_data_com_16b_uuids:
		case index_hf_btle_adv_data_inc_16b_uuids:
		case index_hf_btle_adv_data_16b_service_uuids:
			// attr_item = proto_tree_add_item(tree, hf_btle_adv_data_attrs[type], tvb, 2, length-1, ENC_LITTLE_ENDIAN);
			// attr_tree = proto_item_add_subtree(attr_item, ett_uuids);
			// attr_length_item = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_length, tvb, 0, 1, ENC_LITTLE_ENDIAN);
			// attr_type_item 	 = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_type, tvb, 1, 1, ENC_LITTLE_ENDIAN);
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			for (i = 2; i < length; i += 2)
			{
				proto_tree_add_item(attr_tree, hf_btle_16b_uuid, tvb, i, 2, ENC_LITTLE_ENDIAN);
			}
			break;
		case index_hf_btle_adv_data_short_local_name:
		case index_hf_btle_adv_data_com_local_name:
			// attr_item = proto_tree_add_item(tree, hf_btle_adv_data_attrs[type], tvb, 2, length-1, ENC_UTF_8);
			// attr_tree = proto_item_add_subtree(attr_item, ett_uuids);
			// attr_length_item = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_length, tvb, 0, 1, ENC_LITTLE_ENDIAN);
			// attr_type_item 	 = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_type, tvb, 1, 1, ENC_LITTLE_ENDIAN);
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_UTF_8);
			proto_tree_add_item(attr_tree, hf_btle_adv_data_attrs[type], tvb, 2, length-1, ENC_UTF_8);
			epan_scope_mem_pool = wmem_epan_scope();
			name = wmem_alloc(epan_scope_mem_pool, length);
			tvb_memcpy(tvb, name, 2, length-1);
			name[length-1] = '\0';
			SET_ADDRESS(&pinfo->src, AT_STRINGZ, length, name);
			break;
		case index_hf_btle_adv_data_service_data:
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(attr_tree, hf_btle_16b_uuid, tvb, 2, 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(attr_tree, hf_service_data_value, tvb, 4, length-3, ENC_LITTLE_ENDIAN);	
			break;
		case index_hf_btle_adv_data_service_data_32b:
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(attr_tree, hf_btle_32b_uuid, tvb, 2, 4, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(attr_tree, hf_service_data_value, tvb, 6, length-5, ENC_LITTLE_ENDIAN);	
			break;
		case index_hf_btle_adv_data_service_data_128b:
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(attr_tree, hf_btle_128b_uuid, tvb, 2, 16, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(attr_tree, hf_service_data_value, tvb, 18, length-17, ENC_LITTLE_ENDIAN);	
			break;
		case index_hf_btle_adv_data_conn_int_range:
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			min_interval = (gfloat)tvb_get_letohs(tvb, 2) * (gfloat)1.25;
			max_interval_raw = tvb_get_letohs(tvb, 4);
			if (max_interval_raw == 0xFFFF)
			{
				tmp = 0.0;
				max_interval = (gfloat)1.0/tmp;
			}
			else
			{
				max_interval = (gfloat)max_interval_raw * (gfloat)1.25;
			}
			proto_tree_add_float(attr_tree, hf_btle_min_interval, tvb, 2, 2, min_interval);
			proto_tree_add_float(attr_tree, hf_btle_max_interval, tvb, 4, 2, max_interval);
			break;


		case index_hf_btle_adv_data_tx_power:
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			tx_power = tvb_get_guint8(tvb, 2);
			tx_power -= 127;
			proto_tree_add_int(attr_tree, hf_btle_adv_data_attrs[type], tvb, 2, 1, tx_power);
			break;
		// case index_hf_btle_adv_data_dev_class:
		// case index_hf_btle_adv_data_pair_hash_c:
		// case index_hf_btle_adv_data_pair_rand_r:
		// case index_hf_btle_adv_data_dev_id:
		// case index_hf_btle_adv_data_sec_man_oob_flags:
		case index_hf_btle_adv_data_pub_target_addr:
		case index_hf_btle_adv_data_rand_target_addr:
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			tvb_memcpy(tvb, &address[0], 2, 6);
			reverse_byte_order_inplace(address, 6);
			proto_tree_add_ether(attr_tree, hf_btle_adv_data_attrs[type], tvb, 2, 1, address);
			break;
		case index_hf_btle_adv_data_adv_int:
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			adv_interval = (gfloat)tvb_get_letohs(tvb, 2) * (gfloat)0.625;
			proto_tree_add_float(attr_tree, hf_btle_adv_data_adv_int_ms, tvb, 2, 2, adv_interval);
			break;
		
		case index_hf_btle_adv_data_appearance:
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_attrs[type], length, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(attr_tree, hf_btle_adv_data_attrs[type], tvb, 2, length-1, ENC_LITTLE_ENDIAN);
			break;
			
		case 255:
			// attr_item = proto_tree_add_item(tree, hf_btle_adv_data_manufacturer, tvb, 2, length-1, ENC_LITTLE_ENDIAN);
			// attr_tree = proto_item_add_subtree(attr_item, ett_uuids);
			// attr_length_item = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_length, tvb, 0, 1, ENC_LITTLE_ENDIAN);
			// attr_type_item 	 = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_type, tvb, 1, 1, ENC_LITTLE_ENDIAN);
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_manufacturer, length, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(attr_tree, hf_btle_adv_data_manufacturer, tvb, 2, length-1, ENC_LITTLE_ENDIAN);
			break;
		default:
			// attr_item = proto_tree_add_item(tree, hf_btle_adv_data_unknown, tvb, 2, length-1, ENC_LITTLE_ENDIAN);
			// attr_tree = proto_item_add_subtree(attr_item, ett_uuids);
			// attr_length_item = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_length, tvb, 0, 1, ENC_LITTLE_ENDIAN);
			// attr_type_item 	 = proto_tree_add_item(attr_tree, hf_btle_adv_data_attr_type, tvb, 1, 1, ENC_LITTLE_ENDIAN);
			attr_tree = add_adv_data_attr(tree, tvb, hf_btle_adv_data_unknown, length, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(attr_tree, hf_btle_adv_data_unknown, tvb, 2, length-1, ENC_LITTLE_ENDIAN);
			break;
	}
}

void
dissect_adv_data(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo)
{
	guint i;
	// proto_item* adv_data_item;
	// proto_tree* adv_data_tree;
	
	
	
	for (i = 0; i < tvb_length(tvb); i += tvb_get_guint8(tvb, i) + 1)
	{
		tvbuff_t* attr_tvb;
		guint8 length;
		
		length = tvb_get_guint8(tvb, i) + 1; /* <length> + the length byte itself */
		attr_tvb = tvb_new_subset(tvb, i, length, length);
		
		dissect_adv_data_attr(tree, attr_tvb, pinfo);
	}

	
}

void
dissect_adv_ind_or_nonconn_or_scan(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int datalen)
{
	// const guint8 *adv_addr;
	// guint64 adv_addr;
	// guint i;
	proto_item* data_item;
	proto_tree* data_tree;
	tvbuff_t* data_tvb;
	guint8* adv_addr_le;
	guint8* adv_addr_be;
	wmem_allocator_t* epan_scope_mem_pool;

	epan_scope_mem_pool = wmem_epan_scope();
	adv_addr_le = wmem_alloc(epan_scope_mem_pool, 6);
	adv_addr_be = wmem_alloc(epan_scope_mem_pool, 6);
	
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	tvb_memcpy(tvb, adv_addr_le, offset, 6);
	reverse_byte_order(adv_addr_be, adv_addr_le, 6); /* little endian -> big endian for display/filter purposes */
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, adv_addr_be);
	SET_ADDRESS(&pinfo->dst, AT_STRINGZ, nondirect_dst_string_length, nondirect_dst);

	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset, 6, adv_addr_be);
	data_item = proto_tree_add_item(tree, hf_btle_adv_data, tvb, offset + 6, datalen, ENC_LITTLE_ENDIAN);
	data_tree = proto_item_add_subtree(data_item, ett_adv_data);
	
	data_tvb = tvb_new_subset(tvb, offset + 6, datalen, datalen);
	
	dissect_adv_data(data_tree, data_tvb, pinfo);
}

void
dissect_adv_direct_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	guint8 *adv_addr_le, *init_addr_le;
	guint8 *adv_addr_be, *init_addr_be;
	wmem_allocator_t* epan_scope_mem_pool;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);
	
	epan_scope_mem_pool = wmem_epan_scope();
	adv_addr_le = wmem_alloc(epan_scope_mem_pool, 6);
	adv_addr_be = wmem_alloc(epan_scope_mem_pool, 6);
	init_addr_le = wmem_alloc(epan_scope_mem_pool, 6);
	init_addr_be = wmem_alloc(epan_scope_mem_pool, 6);

	tvb_memcpy(tvb, adv_addr_le, offset, 6);
	reverse_byte_order(adv_addr_be, adv_addr_le, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, adv_addr_be);
	tvb_memcpy(tvb, init_addr_le, offset+6, 6);
	reverse_byte_order(init_addr_be, init_addr_le, 6);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, init_addr_be);

	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset, 6, adv_addr_be);
	proto_tree_add_ether(tree, hf_btle_init_addr, tvb, offset + 6, 6, init_addr_be);
}

void
dissect_scan_req(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{

	guint8 *adv_addr_le, *scan_addr_le;
	guint8 *adv_addr_be, *scan_addr_be;
	wmem_allocator_t* epan_scope_mem_pool;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);
	
	epan_scope_mem_pool = wmem_epan_scope();
	adv_addr_le = wmem_alloc(epan_scope_mem_pool, 6);
	adv_addr_be = wmem_alloc(epan_scope_mem_pool, 6);
	scan_addr_le = wmem_alloc(epan_scope_mem_pool, 6);
	scan_addr_be = wmem_alloc(epan_scope_mem_pool, 6);

	tvb_memcpy(tvb, scan_addr_le, offset, 6);
	reverse_byte_order(scan_addr_be, scan_addr_le, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, scan_addr_be);
	tvb_memcpy(tvb, adv_addr_le, offset+6, 6);
	reverse_byte_order(adv_addr_be, adv_addr_le, 6);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, adv_addr_be);

	proto_tree_add_ether(tree, hf_btle_init_addr, tvb, offset, 6, scan_addr_be);
	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset + 6, 6, adv_addr_be);
	// offset += 12;
}

void
dissect_scan_rsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int datalen)
{
	proto_item* data_item;
	proto_tree* data_tree;
	tvbuff_t* data_tvb;
	guint8* adv_addr_le;
	guint8* adv_addr_be;
	wmem_allocator_t* epan_scope_mem_pool;

	epan_scope_mem_pool = wmem_epan_scope();
	adv_addr_le = wmem_alloc(epan_scope_mem_pool, 6);
	adv_addr_be = wmem_alloc(epan_scope_mem_pool, 6);

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	tvb_memcpy(tvb, adv_addr_le, offset, 6);
	reverse_byte_order(adv_addr_be, adv_addr_le, 6); /* little endian -> big endian for display/filter purposes */
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, adv_addr_be);
	SET_ADDRESS(&pinfo->dst, AT_STRINGZ, nondirect_dst_string_length, nondirect_dst);

	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset, 6, adv_addr_be);
	
	data_item = proto_tree_add_item(tree, hf_btle_scan_rsp_data, tvb, offset + 6, datalen, ENC_LITTLE_ENDIAN);
	data_tree = proto_item_add_subtree(data_item, ett_adv_data);
	
	data_tvb = tvb_new_subset(tvb, offset + 6, datalen, datalen);
	
	dissect_adv_data(data_tree, data_tvb, pinfo);
}

void
dissect_connect_req(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	proto_item *connect_item;
	proto_tree *connect_tree;
	guint8 *adv_addr_le, *init_addr_le;
	guint8 *adv_addr_be, *init_addr_be;
	gint16 conn_timeout;
	float window_size, window_offset, conn_interval;
	wmem_allocator_t* epan_scope_mem_pool;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);
	
	epan_scope_mem_pool = wmem_epan_scope();
	adv_addr_le = wmem_alloc(epan_scope_mem_pool, 6);
	adv_addr_be = wmem_alloc(epan_scope_mem_pool, 6);
	init_addr_le = wmem_alloc(epan_scope_mem_pool, 6);
	init_addr_be = wmem_alloc(epan_scope_mem_pool, 6);

	tvb_memcpy(tvb, init_addr_le, offset, 6);
	reverse_byte_order(init_addr_be, init_addr_le, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, init_addr_be);
	tvb_memcpy(tvb, adv_addr_le, offset+6, 6);
	reverse_byte_order(adv_addr_be, adv_addr_le, 6);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, adv_addr_be);

	proto_tree_add_ether(tree, hf_btle_init_addr, tvb, offset, 6, init_addr_be);
	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset + 6, 6, adv_addr_be);
	offset += 12;

	connect_item = proto_tree_add_item(tree, hf_btle_connect, tvb, offset, 22, ENC_LITTLE_ENDIAN);
	connect_tree = proto_item_add_subtree(connect_item, ett_btle_connect);
	
	window_size 	= (float)(tvb_get_guint8(tvb, offset+ 7)*1.25);
	window_offset 	= (float)(((gint)tvb_get_guint8(tvb, offset+ 8) + (gint)(tvb_get_guint8(tvb, offset+ 9) << 8))*1.25);
	conn_interval 	= (float)(((gint)tvb_get_guint8(tvb, offset+ 10) + (gint)(tvb_get_guint8(tvb, offset+ 11) << 8))*1.25);
	conn_timeout 	= ((gint16)tvb_get_guint8(tvb, offset+ 14) + (gint16)(tvb_get_guint8(tvb, offset+ 15) << 8))*10;

	proto_tree_add_item (connect_tree, hf_btle_connect_aa,	tvb, offset+ 0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item (connect_tree, hf_btle_crc_init,	tvb, offset+ 4, 3, ENC_LITTLE_ENDIAN);
	proto_tree_add_float(connect_tree, hf_btle_win_size,	tvb, offset+ 7, 1, window_size);
	proto_tree_add_float(connect_tree, hf_btle_win_offset,	tvb, offset+ 8, 2, window_offset);
	proto_tree_add_float(connect_tree, hf_btle_interval,	tvb, offset+10, 2, conn_interval);
	proto_tree_add_item (connect_tree, hf_btle_latency,		tvb, offset+12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint (connect_tree, hf_btle_timeout,		tvb, offset+14, 2, conn_timeout);
	dissect_channel_map(connect_tree, tvb, offset+16);
	proto_tree_add_bits_item(connect_tree, hf_btle_hop_interval, tvb, ((offset + 21) * 8) + 3, 5, ENC_LITTLE_ENDIAN);
	proto_tree_add_bits_item(connect_tree, hf_btle_sleep_clock_accuracy, tvb, (offset + 21) * 8, 3, ENC_LITTLE_ENDIAN);
	
}

void
dissect_ll_enc_req(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	// proto_item *ll_enc_req_item;
	// proto_tree *ll_enc_req_tree;

	// ll_enc_req_item = proto_tree_add_item(tree, hf_btle_ll_control_ll_enc_req, tvb, offset + 1, 22, ENC_LITTLE_ENDIAN);
	// ll_enc_req_tree = proto_item_add_subtree(ll_enc_req_item, ett_ll_enc_req);

	// proto_tree_add_item(ll_enc_req_tree, hf_btle_ll_control_ll_enc_req_rand, tvb, offset + 1,  8, ENC_LITTLE_ENDIAN);
	// proto_tree_add_item(ll_enc_req_tree, hf_btle_ll_control_ll_enc_req_ediv, tvb, offset + 9,  2, ENC_LITTLE_ENDIAN);
	// proto_tree_add_item(ll_enc_req_tree, hf_btle_ll_control_ll_enc_req_skdm, tvb, offset + 11, 8, ENC_LITTLE_ENDIAN);
	// proto_tree_add_item(ll_enc_req_tree, hf_btle_ll_control_ll_enc_req_ivm,  tvb, offset + 19, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_btle_ll_control_ll_enc_req_rand, tvb, offset + 1,  8, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_btle_ll_control_ll_enc_req_ediv, tvb, offset + 9,  2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_btle_ll_control_ll_enc_req_skdm, tvb, offset + 11, 8, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_btle_ll_control_ll_enc_req_ivm,  tvb, offset + 19, 4, ENC_LITTLE_ENDIAN);
}

void
dissect_ll_enc_rsp(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	// proto_item *ll_enc_rsp_item;
	// proto_tree *ll_enc_rsp_tree;

	// ll_enc_rsp_item = proto_tree_add_item(tree, hf_btle_ll_control_ll_enc_rsp, tvb, offset + 1, 12, ENC_LITTLE_ENDIAN);
	// ll_enc_rsp_tree = proto_item_add_subtree(ll_enc_rsp_item, ett_ll_enc_rsp);

	// proto_tree_add_item(ll_enc_rsp_tree, hf_btle_ll_control_ll_enc_rsp_skds, tvb, offset + 1, 8, ENC_LITTLE_ENDIAN);
	// proto_tree_add_item(ll_enc_rsp_tree, hf_btle_ll_control_ll_enc_rsp_ivs,  tvb, offset + 9, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_btle_ll_control_ll_enc_rsp_skds, tvb, offset + 1, 8, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_btle_ll_control_ll_enc_rsp_ivs,  tvb, offset + 9, 4, ENC_LITTLE_ENDIAN);
}

dissect_ll_conn_update_req(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	float window_size, window_offset, conn_interval;
	gint16 conn_timeout;
	
	window_size = (float)(tvb_get_guint8(tvb, offset+ 1)*1.25);
	window_offset = (float)(((gint)tvb_get_guint8(tvb, offset+ 2) + (gint)(tvb_get_guint8(tvb, offset+ 3) << 8))*1.25);
	conn_interval = (float)(((gint)tvb_get_guint8(tvb, offset+ 4) + (gint)(tvb_get_guint8(tvb, offset+ 5) << 8))*1.25);
	conn_timeout = ((gint16)tvb_get_guint8(tvb, offset+ 8) + (gint16)(tvb_get_guint8(tvb, offset+ 9) << 8))*10;

	proto_tree_add_float(tree, hf_btle_win_size,	tvb, offset+ 1, 1, window_size);
	proto_tree_add_float(tree, hf_btle_win_offset,	tvb, offset+ 2, 2, window_offset);
	proto_tree_add_float(tree, hf_btle_interval,	tvb, offset+ 4, 2, conn_interval);
	proto_tree_add_item (tree, hf_btle_latency,		tvb, offset+ 6, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint (tree, hf_btle_timeout,		tvb, offset+ 8, 2, conn_timeout);
	proto_tree_add_item (tree, hf_btle_instant,		tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
	
}

dissect_ll_channel_map_req(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	// proto_tree_add_item (tree, hf_btle_channel_map,	tvb, offset+ 1, 5, ENC_LITTLE_ENDIAN);
	dissect_channel_map(tree, tvb, offset+1);
	proto_tree_add_item (tree, hf_btle_instant,		tvb, offset+ 6, 2, ENC_LITTLE_ENDIAN);
}

dissect_ll_terminate_ind(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item (tree, hf_btle_error_code,	tvb, offset+ 1, 1, ENC_LITTLE_ENDIAN);
}

dissect_ll_start_enc_req(proto_tree *tree, tvbuff_t *tvb, int offset)
{

}

dissect_ll_start_enc_rsp(proto_tree *tree, tvbuff_t *tvb, int offset)
{

}

dissect_ll_unknown_rsp(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item (tree, hf_btle_unknown_type,	tvb, offset+ 1, 1, ENC_LITTLE_ENDIAN);
}


dissect_ll_feature_req(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	dissect_feature_set(tree, tvb, offset+1);
	// proto_tree_add_item (tree, hf_btle_feature_set,	tvb, offset+ 1, 8, ENC_LITTLE_ENDIAN);
}

dissect_ll_feature_rsp(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	dissect_feature_set(tree, tvb, offset+1);
	// proto_tree_add_item (tree, hf_btle_feature_set,	tvb, offset+ 1, 8, ENC_LITTLE_ENDIAN);
}

dissect_ll_pause_enc_req(proto_tree *tree, tvbuff_t *tvb, int offset)
{

}

dissect_ll_pause_enc_rsp(proto_tree *tree, tvbuff_t *tvb, int offset)
{

}

dissect_ll_version_ind(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item (tree, hf_btle_bt_version,		tvb, offset+ 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item (tree, hf_btle_company_id,		tvb, offset+ 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item (tree, hf_btle_sub_version_num,	tvb, offset+ 4, 2, ENC_LITTLE_ENDIAN);
}

dissect_ll_reject_ind(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_tree_add_item (tree, hf_btle_error_code,	tvb, offset+ 1, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_ll_control(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, guint8 length)
{
	guint8 ll_control_opcode;
	// proto_item* data_item;
	proto_item* control_item;
	// proto_tree* data_tree;
	proto_tree* control_tree;

	
	ll_control_opcode = tvb_get_guint8(tvb, offset);
	
	control_item =	proto_tree_add_uint(tree, hf_btle_ll_control, tvb, offset, length, ll_control_opcode);
	control_tree = 	proto_item_add_subtree(control_item, ett_ll_control);
					proto_tree_add_item(control_tree, hf_btle_ll_control_opcode, tvb, offset, 1, ENC_NA);
	// data_item =		proto_tree_add_item(control_tree, hf_btle_ll_control_data, tvb, offset+1, length-1, ENC_NA);
	// data_tree = 	proto_item_add_subtree(data_item, ett_ll_control_data);

	if (ll_control_opcode <= 0x0d) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "LL Control PDU: %s",
				ll_control_opcodes[ll_control_opcode].strptr);

		switch (ll_control_opcode) {
			case LL_CONNECTION_UPDATE_REQ:
				dissect_ll_conn_update_req(control_tree, tvb, offset);
				break;
			case LL_CHANNEL_MAP_REQ:
				dissect_ll_channel_map_req(control_tree, tvb, offset);
				break;
			case LL_TERMINATE_IND:
				dissect_ll_terminate_ind(control_tree, tvb, offset);
				break;
			case LL_ENC_REQ:
				dissect_ll_enc_req(control_tree, tvb, offset);
				break;
			case LL_ENC_RSP:
				dissect_ll_enc_rsp(control_tree, tvb, offset);
				break;
			case LL_START_ENC_REQ:
				dissect_ll_start_enc_req(control_tree, tvb, offset);
				break;
			case LL_START_ENC_RSP:
				dissect_ll_start_enc_rsp(control_tree, tvb, offset);
				break;
			case LL_UNKNOWN_RSP:
				dissect_ll_unknown_rsp(control_tree, tvb, offset);
				break;
			case LL_FEATURE_REQ:
				dissect_ll_feature_req(control_tree, tvb, offset);
				break;
			case LL_FEATURE_RSP:
				dissect_ll_feature_rsp(control_tree, tvb, offset);
				break;
			case LL_PAUSE_ENC_REQ:
				dissect_ll_pause_enc_req(control_tree, tvb, offset);
				break;
			case LL_PAUSE_ENC_RSP:
				dissect_ll_pause_enc_rsp(control_tree, tvb, offset);
				break;
			case LL_VERSION_IND:
				dissect_ll_version_ind(control_tree, tvb, offset);
				break;
			case LL_REJECT_IND:
				dissect_ll_reject_ind(control_tree, tvb, offset);
				break;
			default:
				/* Impossible */
				break;
		}
	} else {
		
		col_set_str(pinfo->cinfo, COL_INFO, "LL Control PDU: unknown");
		if (length > 1)
			proto_tree_add_item(control_tree, hf_btle_ll_control_data, tvb, offset + 1, length-1, ENC_LITTLE_ENDIAN);
		expert_add_info_format(pinfo, control_item, PI_SEQUENCE, PI_WARN, "Unknown LL Control opcode");
	}
}

/* dissect a packet */
static void
dissect_btle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *btle_item, *pkthdr_item, *data_item, *length_item;
	proto_tree *btle_tree, *pkthdr_tree, *data_tree;
	int offset;
	guint32 aa;
	guint8 type, length;
	guint8 llid;
	tvbuff_t *pld_tvb;

	/*
	 * FIXME
	 * I have no idea what this does, but the L2CAP dissector segfaults
	 * without it.
	 */
	guint16 fake_acl_data;

	/* sanity check: length */
	if (tvb_length(tvb) > 0 && tvb_length(tvb) < 9)
	{
		/* bad length: too short */
		//expert_add_info(pinfo, NULL, &ei_btle_packet_too_short);
	}
	
	/* make entries in protocol column and info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bluetooth LE");
	

	aa = tvb_get_letohl(tvb, 0);

	// advertising packet
	if (aa == ADV_AA) {
		type = tvb_get_guint8(tvb, 4) & 0xf;
		length = tvb_get_guint8(tvb, 5) & 0x3f;
		
		if ((guint)(length + 9) < tvb_length(tvb))
		{
			/* not supported before 1.11.0 */
			//expert_add_info(pinfo, NULL, &ei_btle_packet_too_long);	
		} 
		else if ((guint)(length + 9) > tvb_length(tvb))
		{
			/* not supported before 1.11.0 */
			//expert_add_info(pinfo, NULL, &ei_btle_packet_too_short);
		}

		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLE ADV");
		/* see if we are being asked for details */
		if (tree) {

			/* create display subtree for the protocol */
			offset = 0;
			btle_item = proto_tree_add_item(tree, proto_btle, tvb, offset, -1, ENC_LITTLE_ENDIAN);
			btle_tree = proto_item_add_subtree(btle_item, ett_btle);

			proto_tree_add_item(btle_tree, hf_btle_aa, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			/* packet header */
			pkthdr_item = proto_tree_add_item(btle_tree, hf_btle_pkthdr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			pkthdr_tree = proto_item_add_subtree(pkthdr_item, ett_btle_pkthdr);

			if (type == 0x1 || type == 0x3 || type == 0x5)
			{
				proto_tree_add_bits_item(pkthdr_tree, hf_btle_randomized_rx, tvb, offset * 8, 1, ENC_LITTLE_ENDIAN);
			}
			proto_tree_add_bits_item(pkthdr_tree, hf_btle_randomized_tx, tvb, offset * 8 + 1, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_bits_item(pkthdr_tree, hf_btle_type, tvb, offset * 8 + 4, 4, ENC_LITTLE_ENDIAN);
			offset += 1;

			length_item = proto_tree_add_item(pkthdr_tree, hf_btle_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			if ((guint)(length + 9) < tvb_length(tvb))
			{
				//expert_add_info(pinfo, length_item, &ei_btle_packet_too_long);	
			} 
			else if ((guint)(length + 9) > tvb_length(tvb))
			{
				//expert_add_info(pinfo, length_item, &ei_btle_packet_too_short);
			}
			
			offset += 1;

			if (check_col(pinfo->cinfo, COL_INFO)) {
				if (type <= 0x6) {
					col_set_str(pinfo->cinfo, COL_INFO, packet_types[type].strptr);
				} else {
					col_set_str(pinfo->cinfo, COL_INFO, "Unknown");
				}
			}

			/* payload */
			switch (type) {
			case 0x0: // ADV_IND
			case 0x2: // ADV_NONCONN_IND
			case 0x6: // ADV_SCAN_IND
				dissect_adv_ind_or_nonconn_or_scan(btle_tree, tvb, pinfo, offset, length - 6);
				break;
			case 0x1: // ADV_DIRECT_IND
				dissect_adv_direct_ind(btle_tree, tvb, pinfo, offset);
				break;
			case 0x3:
				dissect_scan_req(btle_tree, tvb, pinfo, offset);
				break;
			case 0x4: // SCAN_RSP
				dissect_scan_rsp(btle_tree, tvb, pinfo, offset, length - 6);
				break;
			case 0x5: // CONNECT_REQ
				dissect_connect_req(btle_tree, tvb, pinfo, offset);
				break;
			default:
				break;
			}

			offset += length;
			proto_tree_add_item(btle_tree, hf_btle_crc, tvb, offset, 3, ENC_BIG_ENDIAN);
		}
	}

	// data PDU
	else {
		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLE Data");
		
		
		length = tvb_get_guint8(tvb, 5) & 0x3f;
		
		if ((guint)(length + 9) < tvb_length(tvb))
		{
			/* not supported before 1.11.0 */
			//expert_add_info(pinfo, NULL, &ei_btle_packet_too_long);	
		} 
		else if ((guint)(length + 9) > tvb_length(tvb))
		{
			/* not supported before 1.11.0 */
			//expert_add_info(pinfo, NULL, &ei_btle_packet_too_short);
		}
		
		if (tree) {
			col_set_str(pinfo->cinfo, COL_INFO, "Data");

			length = tvb_get_guint8(tvb, 5) & 0x1f;

			/* create display subtree for the protocol */
			offset = 0;
			btle_item = proto_tree_add_item(tree, proto_btle, tvb, offset, -1, ENC_LITTLE_ENDIAN);
			btle_tree = proto_item_add_subtree(btle_item, ett_btle);

			proto_tree_add_item(btle_tree, hf_btle_aa, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;

			// data PDU header
			data_item = proto_tree_add_item(btle_tree, hf_btle_data, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			data_tree = proto_item_add_subtree(data_item, ett_btle_data);

			proto_tree_add_item(data_tree, hf_btle_data_rfu, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(data_tree, hf_btle_data_md, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(data_tree, hf_btle_data_sn, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(data_tree, hf_btle_data_nesn, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(data_tree, hf_btle_data_llid, tvb, offset, 1, ENC_NA);
			llid = tvb_get_guint8(tvb, offset) & 0x3;
			offset += 1;

			length_item = proto_tree_add_item(data_tree, hf_btle_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			if ((guint)(length + 9) < tvb_length(tvb))
			{
				/* not supported before 1.11.0 */
				//expert_add_info(pinfo, length_item, &ei_btle_packet_too_long);	
			} 
			else if ((guint)(length + 9) > tvb_length(tvb))
			{
				/* not supported before 1.11.0 */
				//expert_add_info(pinfo, length_item, &ei_btle_packet_too_short);
			}
			offset += 1;

			// LL control PDU
			if (llid == 0x3) {
				dissect_ll_control(btle_tree, tvb, pinfo, offset, length);
			}

			// L2CAP
			else if (llid == 0x1 || llid == 0x2) {
					
				if (length > 0 && btl2cap_handle) {
					pinfo->private_data = &fake_acl_data;
					pld_tvb = tvb_new_subset(tvb, offset, length, length);
					// call_dissector(btl2cap_handle, pld_tvb, pinfo, btle_tree);
					call_dissector(btl2cap_handle, pld_tvb, pinfo, tree);
				}
				else if (length == 0) {
					col_set_str(pinfo->cinfo, COL_INFO, "Empty Data PDU");
				}
			}

			offset += length;

			proto_tree_add_item(btle_tree, hf_btle_crc, tvb, offset, 3, ENC_BIG_ENDIAN);
		}
	}

	return;
}

/* register the protocol with Wireshark */
void
proto_register_btle(void)
{

	/* list of fields */
	static hf_register_info hf[] = {
		{ &hf_btle_aa,
			{ "Access Address", "btle.aa",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_btle_pkthdr,
			{ "Packet Header", "btle.pkthdr",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_btle_type,
			{ "TYPE", "btle.type",
			FT_UINT8, BASE_HEX, VALS(packet_types), 0x0,
			"Packet Type", HFILL }
		},
		{ &hf_btle_randomized_tx,
			{ "TX Address", "btle.tx_addr_flag",
			// FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
			FT_BOOLEAN, BASE_NONE, &addr_flag_tfs, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_randomized_rx,
			{ "RX Address", "btle.rx_addr_flag",
			// FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
			FT_BOOLEAN, BASE_NONE, &addr_flag_tfs, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_length,
			{ "Length", "btle.length",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_addr,
			{ "Advertising Address", "btle.adv_addr",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_init_addr,
			{ "Init Address", "btle.init_addr",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_scan_addr,
			{ "Scan Address", "btle.scan_addr",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data,
			{ "Advertising Data", "btle.adv_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_scan_rsp_data,
			{ "Scan Response Data", "btle.scan_rsp_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

		// connection packet fields
		{ &hf_btle_connect,
			{ "Connection Request", "btle.connect",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_connect_aa,
			{ "Connection Access Address", "btle.connect.aa",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_crc_init,
			{ "CRC Init", "btle.connect.crc_init",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_win_size,
			{ "Window Size (ms)", "btle.connect.win_size",
			FT_FLOAT, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_win_offset,
			{ "Window Offset (ms)", "btle.connect.win_offset",
			FT_FLOAT, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_interval,
			{ "Interval (ms)", "btle.connect.interval",
			FT_FLOAT, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_min_interval,
			{ "Minimum interval (ms)", "btle.connect.min_interval",
			FT_FLOAT, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_max_interval,
			{ "Maximum interval (ms)", "btle.connect.max_interval",
			FT_FLOAT, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_latency,
			{ "Latency", "btle.connect.latency",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_timeout,
			{ "Timeout (ms)", "btle.connect.timeout",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_hop_interval,
			{ "Hop interval", "btle.connect.hop_interval",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_sleep_clock_accuracy,
			{ "Sleep Clock Accuracy", "btle.connect.sca",
			FT_UINT8, BASE_DEC, VALS(sleep_clock_accuracy_values), 0x0,
			NULL, HFILL }
		},

		// data header
		{ &hf_btle_data,
			{ "Data PDU Header", "btle.data",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_data_llid,
			{ "LLID", "btle.data.llid",
			FT_UINT8, BASE_DEC, VALS(llid_codes), 0x3,
			NULL, HFILL }
		},
		{ &hf_btle_data_nesn,
			{ "NESN", "btle.data.nesn",
			FT_UINT8, BASE_DEC, NULL, 0x4,
			"Next Expected Sequence Number", HFILL }
		},
		{ &hf_btle_data_sn,
			{ "SN", "btle.data.sn",
			FT_UINT8, BASE_DEC, NULL, 0x8,
			"Sequence Number", HFILL }
		},
		{ &hf_btle_data_md,
			{ "MD", "btle.data.md",
			FT_UINT8, BASE_DEC, NULL, 0x10,
			"More Data", HFILL }
		},
		{ &hf_btle_data_rfu,
			{ "RFU", "btle.data.rfu",
			FT_UINT8, BASE_DEC, NULL, 0xe0,
			"Reserved for Future Use (must be zero)", HFILL }
		},

		{ &hf_btle_ll_control,
			{ "LL Control PDU", "btle.ll_control",
			FT_UINT8, BASE_HEX, VALS(ll_control_opcodes), 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_ll_control_opcode,
			{ "LL Control Opcode", "btle.ll_control_opcode",
			FT_UINT8, BASE_HEX, VALS(ll_control_opcodes), 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_ll_control_data,
			{ "LL Control Data", "btle.ll_control_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_btle_ll_control_ll_enc_req,
			{ "Encryption Request", "btle.ll_enc_req",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_req_rand,
			{ "Rand", "btle.ll_enc_req.rand",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_req_ediv,
			{ "EDIV", "btle.ll_enc_req.ediv",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Encrypted Diversifier", HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_req_skdm,
			{ "SKDm", "btle.ll_enc_req.skdm",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Master's Session Key Identifier", HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_req_ivm,
			{ "IVm", "btle.ll_enc_req.ivm",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Master's Initialization Vector", HFILL }
		},

		{ &hf_btle_ll_control_ll_enc_rsp,
			{ "Encryption Response", "btle.ll_enc_rsp",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_rsp_skds,
			{ "SKDs", "btle.ll_enc_rsp.skds",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Slave's Session Key Identifier", HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_rsp_ivs,
			{ "IVs", "btle.ll_enc_rsp.ivs",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Slave's Initialization Vector", HFILL }
		},


		{ &hf_btle_crc,
			{ "CRC", "btle.crc",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			"Cyclic Redundancy Check", HFILL }
		},
		
		
		{ &hf_btle_instant,
			{ "Instant field", "btle.instant",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_channel_map,
			{ "Channel map", "btle.map",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_enabled_channels,
			{ "Enabled channels", "btle.enabled_channels",
			FT_STRINGZ, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_error_code,
			{ "Error code", "btle.error",
			FT_UINT8, BASE_HEX, VALS(error_codes), 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_unknown_type,
			{ "Unknown type", "btle.unknown_type",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_feature_set,
			{ "Feature set", "btle.feature_set",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_supported_feature,
			{ "Supported feature", "btle.supported_feature",
			FT_UINT8, BASE_DEC, VALS(le_features), 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_unsupported_feature,
			{ "Unsupported feature", "btle.unsupported_feature",
			FT_UINT8, BASE_DEC, VALS(le_features), 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_bt_version,
			{ "Bletooth version", "btle.bluetooth_version",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_company_id,
			{ "Company ID", "btle.company_id",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_sub_version_num,
			{ "Sub-version number", "btle.sub_version_num",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		
		
		
		{ &hf_btle_adv_data_attr,
			{ "Attribute", "btle.adv_data.attr",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attr_type,
			{ "type", "btle.adv_data.attr.type",
			FT_UINT8, BASE_HEX, VALS(adv_data_attr_types), 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attr_length,
			{ "length", "btle.adv_data.attr.length",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attr_value,
			{ "value (hex)", "btle.adv_data.attr.value",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attr_value_string,
			{ "value (ASCII)", "btle.adv_data.attr.value_string",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_flags],
			{"flags", "btle.adv_data.flags",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_inc_16b_uuids],
			{"16 bit uuids (incomplete)", "btle.adv_data.inc_16b_uuids",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_com_16b_uuids],
			{"16 bit uuids (complete)", "btle.adv_data.com_16b_uuids",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_inc_32b_uuids],
			{"32 bit uuids (incomplete)", "btle.adv_data.inc_32b_uuids",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_com_32b_uuids],
			{"32 bit uuids (complete)", "btle.adv_data.com_32b_uuids",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_inc_128b_uuids],
			{"128 bit uuids (incomplete)", "btle.adv_data.inc_128b_uuids",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_com_128b_uuids],
			{"128 bit uuids (complete)", "btle.adv_data.com_128b_uuids",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL}
		},
		{ &hf_btle_128b_uuid,
			{"128 bit uuid", "btle.128b_uuid",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_32b_uuid,
			{"32 bit uuid", "btle.32b_uuid",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_16b_uuid,
			{"16 bit uuid", "btle.16b_uuid",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_short_local_name],
			{"local name (short)", "btle.adv_data.short_local_name",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_com_local_name],
			{"local name", "btle.adv_data.complete_local_name",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_tx_power],
			{"TX power level", "btle.adv_data.tx_power",
			FT_INT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_dev_class],
			{"device class", "btle.adv_data.device_class",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_pair_hash_c],
			{"simple hash", "btle.adv_data.simple_hash",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_pair_rand_r],
			{"simple randomizer", "btle.adv_data.simple_randomizer",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_dev_id],
			{"TK value", "btle.adv_data.tk_value",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_sec_man_oob_flags],
			{"OOB flags", "btle.adv_data.oob_flags",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_conn_int_range],
			{"conn interval range", "btle.adv_data.conn_interval_range",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_16b_service_uuids],
			{"16 b service uuids", "btle.adv_data.16b_service_uuids",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_128b_service_uuids],
			{"128 b service uuids", "btle.adv_data.128b_service_uuids",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_service_data],
			{"service data", "btle.adv_data.service_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_service_data_32b],
			{"service data for 32 bit UUID.", "btle.adv_data.service_data_32b",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_service_data_128b],
			{"service data for 128 bit UUID", "btle.adv_data.service_data_128b",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_service_data_value,
			{"service data value", "btle.adv_data.service_data.value",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_pub_target_addr],
			{"public target address", "btle.adv_data.public_target_address",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_rand_target_addr],
			{"random target address", "btle.adv_data.random_target_address",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_appearance],
			{"appearance", "btle.adv_data.appearance",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_attrs[index_hf_btle_adv_data_adv_int],
			{"advertising interval", "btle.adv_data.advertising_interval",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_adv_int_ms,
			{"advertising interval (ms)", "btle.adv_data.advertising_interval_ms",
			FT_FLOAT, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_manufacturer,
			{"manufacturer specific data", "btle.adv_data.manufacturer_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_unknown,
			{"Unknown advertising data attribute", "btle.adv_data.unknown",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_flag_le_limited_discoverable,
			{"LE limited discoverable", "btle.adv_data.flag.le_limited_discoverable",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_flag_le_general_discoverable,
			{"LE general discoverable", "btle.adv_data.flag.le_general_discoverable",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_flag_br_edr_not_supported,
			{"BR/EDR not supported", "btle.adv_data.flag.br_edr_not_supported",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data_flag_simultaneous_le_br_edr_controller,
			{"Simultaneous LE and BR/EDR (Controller)", "btle.adv_data.flag.simultaneous_le_br_edr_controller",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Simultaneous LE and BR/EDR to Same Device Capable (Controller)", HFILL }
		},
		{ &hf_btle_adv_data_flag_simultaneous_le_br_edr_host,
			{"Simultaneous LE and BR/EDR (Host)", "btle.adv_data.flag.simultaneous_le_br_edr_host",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"Simultaneous LE and BR/EDR to Same Device Capable (Host)", HFILL }
		}

		// #endif
	};

	/* protocol subtree arrays */
	static gint *ett[] = {
		&ett_btle,
		&ett_btle_pkthdr,
		&ett_btle_connect,
		&ett_btle_data,
		&ett_ll_enc_req,
		&ett_ll_enc_rsp,
		&ett_ll_control,
		&ett_ll_control_data,
		&ett_feature_set,
		&ett_channel_map,
		&ett_adv_data,
		&ett_adv_data_attr,
		&ett_adv_data_flags,
		&ett_uuids
	};
	
	// static ei_register_info ei[] = {
		// { &ei_btle_packet_too_short, { "btle.length.short", PI_MALFORMED, PI_ERROR, "Packet buffer is too short or reported length is too long.", EXPFILL }},
		// { &ei_btle_packet_too_long, { "btle.length.long", PI_MALFORMED, PI_ERROR, "Packet buffer is too long or reported length is too short.", EXPFILL }},
	// };
	
	//expert_module_t* expert_ip;
	/* register the protocol name and description */
	proto_btle = proto_register_protocol(
		"Bluetooth Low Energy",	/* full name */
		"BTLE",			/* short name */
		"btle"			/* abbreviation (e.g. for filters) */
		);

	register_dissector("btle", dissect_btle, proto_btle);
	
	//expert_ip = expert_register_protocol(proto_btle);
	//expert_register_field_array(expert_ip, ei, array_length(ei));

	/* register the header fields and subtrees used */
	proto_register_field_array(proto_btle, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btle(void)
{
	static gboolean inited = FALSE;

	if (!inited) {
		// dissector_handle_t btle_handle;

		// btle_handle = new_create_dissector_handle(dissect_btle, proto_btle);
		// dissector_add("ppi.dlt", 147, btle_handle);

		btl2cap_handle = find_dissector("btl2cap");

		inited = TRUE;
	}
}
