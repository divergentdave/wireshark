/* packet-ge-srtp.c
 * Routines for GE SRTP dissection.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * SRTP, or Service Request Transport Protocol, is a field bus protocol
 * developed by GE Intelligent Platforms. (originally GE Fanuc) SRTP is
 * used over Ethernet, typically on TCP port 18245. SRTP is closely related to
 * SNP, or Series 90 Protocol, which is used over serial ports.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include <epan/conversation.h>

#include <epan/prefs.h>

#include <epan/dissectors/packet-tcp.h>

#include <stdlib.h>

void proto_register_ge_srtp(void);
void proto_reg_handoff_ge_srtp(void);

static int proto_ge_srtp = -1;

static int hf_ge_srtp_reqframe = -1;
static int hf_ge_srtp_respframe = -1;
static int hf_ge_srtp_type = -1;
static int hf_ge_srtp_seq_num = -1;
static int hf_ge_srtp_next_msg_len = -1;

static int hf_ge_srtp_mbox_todo = -1;

/* Mailbox messages */
static int hf_ge_srtp_mbox_timestamp = -1;
static int hf_ge_srtp_mbox_seq_num = -1;
static int hf_ge_srtp_mbox_type = -1;
static int hf_ge_srtp_mbox_src_id = -1;
static int hf_ge_srtp_mbox_dst_id = -1;
static int hf_ge_srtp_mbox_packet_num = -1;
static int hf_ge_srtp_mbox_total_packets = -1;

/* Initial request/Initial request with text buffer */
static int hf_ge_srtp_mbox_svc_req_code = -1;
static int hf_ge_srtp_mbox_svc_req_data = -1;

static int hf_ge_srtp_mbox_svc_req_data_len = -1;

/* Completion ACK/Completion ACK with text buffer */
static int hf_ge_srtp_mbox_status_code = -1;
static int hf_ge_srtp_mbox_status_data = -1;
static int hf_ge_srtp_mbox_response_data = -1;
static int hf_ge_srtp_mbox_piggyback_status = -1;
static int hf_ge_srtp_mbox_control_program_num = -1;
static int hf_ge_srtp_mbox_privilege_level = -1;
static int hf_ge_srtp_mbox_last_sweep = -1;
static int hf_ge_srtp_mbox_plc_status_word = -1;
static int hf_ge_srtp_mbox_plc_status_word_oversweep = -1;
static int hf_ge_srtp_mbox_plc_status_word_constant_sweep_mode = -1;
static int hf_ge_srtp_mbox_plc_status_word_new_plc_fault = -1;
static int hf_ge_srtp_mbox_plc_status_word_new_io_fault = -1;
static int hf_ge_srtp_mbox_plc_status_word_plc_fault = -1;
static int hf_ge_srtp_mbox_plc_status_word_io_fault = -1;
static int hf_ge_srtp_mbox_plc_status_word_programmer_attached = -1;
static int hf_ge_srtp_mbox_plc_status_word_outputs_switch = -1;
static int hf_ge_srtp_mbox_plc_status_word_run_switch = -1;
static int hf_ge_srtp_mbox_plc_status_word_oem_protection = -1;
static int hf_ge_srtp_mbox_plc_status_word_plc_state = -1;

static int hf_ge_srtp_mbox_response_data_len = -1;

/* Error NACK */
static int hf_ge_srtp_mbox_major_error_status = -1;
static int hf_ge_srtp_mbox_minor_error_status = -1;

static int hf_ge_srtp_text_buffer = -1;

#define GE_SRTP_TCP_PORT 18245
#define NEXT_MESSAGE_LENGTH_OFFSET 4
#define SRTP_MAILBOX_MESSAGE_LENGTH 56

static gint ett_ge_srtp = -1;
static gint ett_piggyback = -1;

static const value_string ge_srtp_mbox_type[] = {
    { 0x80, "Initial Request with Text Buffer" },
    { 0x94, "Completion ACK with Text Buffer" },
    { 0xC0, "Initial Request" },
    { 0xD1, "Erorr NACK" },
    { 0xD4, "Completion ACK" },
    { 0, NULL }
};

static const value_string ge_srtp_svc_req_type[] = {
    { 0x00, "PLC Short Status Request" },
    { 0x01, "PLC Long Status Request" },
    { 0x02, "PLC Memory Usage Request" },
    { 0x03, "Return Control Program Name" },
    { 0x04, "Read System Memory" },
    { 0x05, "Read Task Memory" },
    { 0x06, "Read Program Block Memory" },
    { 0x07, "Write System Memory" },
    { 0x08, "Write Task Memory" },
    { 0x09, "Write Program Block Memory" },
    { 0x0A, "Define Symbol" },
    { 0x0B, "Delete Symbol" },
    { 0x0C, "Read System Memory Symbolic Variable" },
    { 0x0D, "Read Task Memory Symbolic Variable" },
    { 0x0E, "Read Program Block Memory Symbolic Variable" },
    { 0x0F, "Write System Memory Symbolic Variable" },
    { 0x10, "Write Task Memory Symbolic Variable" },
    { 0x11, "Write Program Block Memory Symbolic Variable" },
    { 0x12, "Resolve System Memory Name" },
    { 0x13, "Resolve Task Memory Name" },
    { 0x14, "Resolve Program Block Memory Name" },
    { 0x15, "Establish Datagram" },
    { 0x16, "Update Datagram" },
    { 0x17, "Cancel Datagram" },
    { 0x18, "Format Disk" },
    { 0x19, "Open File" },
    { 0x1A, "Close File" },
    { 0x1B, "Create File" },
    { 0x1C, "Unlink File" },
    { 0x1D, "Read File" },
    { 0x1E, "Write File" },
    { 0x1F, "Seek File" },
    { 0x20, "Programmer Logon" },
    { 0x21, "Change PLC CPU Privilege Level" },
    { 0x22, "Set PLC CPU Controller ID" },
    { 0x23, "Set PLC State" },
    { 0x24, "Set PLC Time/Date" },
    { 0x25, "Return PLC Time/Date" },
    { 0x26, "Return Program Block Sizes" },
    { 0x27, "Return Program Block List" },
    { 0x28, "Store Program Block" },
    { 0x29, "Sequence Control" },
    { 0x2A, "Program Block Program Store" },
    { 0x2B, "Program Block Load" },
    { 0x2C, "Program Block Program Load" },
    { 0x2D, "Verify Program Block" },
    { 0x2E, "Delete Program Block" },
    { 0x2F, "Change Program Block Size" },
    { 0x30, "Declare Interrupt" },
    { 0x31, "Clear Configuration" },
    { 0x32, "Autoconfigure I/O" },
    { 0x33, "Replace I/O Module" },
    { 0x34, "Verify Configuration Block" },
    { 0x35, "Clear All PLC Memory" },
    { 0x36, "Clear Reference Memory" },
    { 0x37, "Clear Logic Memory" },
    { 0x38, "Return Fault Table" },
    { 0x39, "Clear Fault Table" },
    { 0x3A, "Create Configuration Parameter Task" },
    { 0x3B, "Delete Configuration Parameter Task" },
    { 0x3C, "Return Configuration Sizes" },
    { 0x3D, "Store Block" },
    { 0x3E, "Load Block" },
    { 0x3F, "Program Store" },
    { 0x40, "Program Load" },
    { 0x41, "Program Change" },
    { 0x42, "Verify Program" },
    { 0x43, "Return Controller Type and ID Information" },
    { 0x44, "Toggle Force System Memory" },
    { 0x45, "Access EEPROM" },
    { 0x46, "Manage Block" },
    { 0x47, "Lock/Unlock OEM" },
    { 0x48, "Write Datagram" },
    { 0x49, "Access FA Card" },
    { 0x4A, "Read Configuration Parameter" },
    { 0x4B, "Write Slot Configuration" },
    { 0x4C, "Rename Task" },
    { 0x4D, "Return Function Supported" },
    { 0x4E, "Store Subrequest" },
    { 0x4F, "Session Control" },
    { 0x50, "Return Subrequest List" },
    { 0x51, "Extra Piggyback Data" },
    { 0x52, "Store OS Extension" },
    { 0x53, "Load OS Extension" },
    { 0x54, "Delete OS Extension" },
    { 0x55, "Delete Subrequest" },
    { 0x56, "Share PLC Data" },
    { 0x57, "Toggle Force Program Block Memory" },
    { 0x58, "SFC Event Q Service" },
    { 0x59, "Interrogate I/O" },
    { 0x5A, "Program Store Extended" },
    { 0x5B, "Program Load Extended" },
    { 0x5C, "Program Verify Extended" },
    { 0x5D, "Activate Debugger" },
    { 0x5E, "Configuration Change Control" },
    { 0x5F, "Remote Server Register" },
    { 0x60, "Clear Selected Fault" },
    { 0x61, "Return PLC Features Supported" },
    { 0, NULL }
};

static const value_string ge_srtp_plc_state[] = {
    { 0, "Run I/O enabled" },
    { 1, "Run I/O disabled" },
    { 2, "Stop I/O disabled" },
    { 3, "CPU stop faulted" },
    { 4, "CPU halted" },
    { 5, "CPU suspended" },
    { 6, "Stop I/O enabled" },
    { 0, NULL }
};

static const value_string ge_srtp_major_error_status[] = {
    { 1, "Illegal service request" },
    { 2, "Insufficient privilege" },
    { 4, "Protocol sequence error" },
    { 5, "Service request error" },
    { 6, "Illegal mailbox type" },
    { 7, "Service request queue is full" },
    { 0, NULL },
};

static const value_string ge_srtp_minor_error_status[] = {
    { 0x50, "Problem with sending mail to the slave service request task" },
    { 0x51, "Problem with getting mail from the slave service request task" },
    { 0x55, "Slave SNP task timed out before receiving SRP response" },
    { 0x56, "Slave SNP task could not find the requested datagram connection" },
    { 0x57, "Slave SNP task encountered an error in trying to write the datagram" },
    { 0x58, "Slave SNP task encountered an error in trying to update the datagram" },
    { 0xB2, "Program block already exists and cannot be replaced" },
    { 0xB3, "Length limit exceeded" },
    { 0xB4, "Attempt to alter interrupt list in MAIN DECL BLOCK during run mode" },
    { 0xB5, "Additive checksum comparison in verify failed" },
    { 0xB6, "CRC checksum comparison in verify failed" },
    { 0xB7, "Segment length in verify not equal to the segment length of block in the PLC" },
    { 0xB8, "Size of the segment selector table in TYPDEF record is not correct" },
    { 0xB9, "Executable flag in TYPDEF record not set" },
    { 0xBA, "Block set already exists, cannot create" },
    { 0xBB, "Maximum length of a partial store exceeded" },
    { 0xBC, "Block type not found" },
    { 0xBD, "Block set not found" },
    { 0xBE, "Bad block type given in load/store" },
    { 0xBF, "Illegal OMF record type/data contents" },
    { 0xC0, "Bad OMF record checksum in store" },
    { 0xC1, "Invalid block state transition" },
    { 0xC2, "The OEM key is NULL" },
    { 0xC3, "Text length does not match traffic type" },
    { 0xC4, "Verify with flash card or EEPROM failed" },
    { 0xC5, "No task-level rack/slot configuration to read or delete" },
    { 0xC6, "Control program tasks exist but requestor not logged into main control program" },
    { 0xC7, "Passwords are set to inactive and cannot be enabled or disabled" },
    { 0xC8, "Passwords already enabled and cannot be forced inactive" },
    { 0xC9, "Login using non-zero buffer size required for block commands" },
    { 0xCA, "Device is write protected" },
    { 0xCB, "A communications or write verify error occurred during save or restore" },
    { 0xCC, "Data stored on device has been corrupted and is no longer reliable" },
    { 0xCD, "Attempt was made to read a device but no data has been stored in it" },
    { 0xCE, "Specified device has insufficient memory to handle request" },
    { 0xCF, "Specified device is not available in the system" },
    { 0xD0, "One or more PLC modules configured have unsupported revision" },
    { 0xD1, "Packet size or total program size does not match input" },
    { 0xD2, "Invalid write mode parameter" },
    { 0xD3, "User program module read or write exceeded block end" },
    { 0xD4, "Mismatch of configuration checksum" },
    { 0xD5, "Invalid block name specified in datagram" },
    { 0xD6, "Datagram connection boundary exceeded" },
    { 0xD7, "Invalid datagram type specified" },
    { 0xD8, "Point length not allowed" },
    { 0xD9, "Transfer type invalid for this selector" },
    { 0xDA, "Null pointer to data in segment selector" },
    { 0xDB, "Invalid segment selector in datagram" },
    { 0xDC, "Unable to find connection address" },
    { 0xDD, "Unable to locate given connection ID" },
    { 0xDE, "Size of datagram connection invalid" },
    { 0xDF, "Invalid datagram connection address" },
    { 0xE0, "Service in process cannot login" },
    { 0xE1, "No I/O configuration to read or delete" },
    { 0xE2, "IOS could not delete configuration or bad type" },
    { 0xE3, "CPU revision number does not match" },
    { 0xE4, "Segment for this selector does not exist" },
    { 0xE5, "DOS file area not formatted" },
    { 0xE6, "CPU model number does not match" },
    { 0xE7, "Configuration is not valid" },
    { 0xE8, "No user memory is available to allocate" },
    { 0xE9, "Segment selector is not valid in context" },
    { 0xEA, "Not logged in to process service request" },
    { 0xEB, "Task unable to be deleted" },
    { 0xEC, "Task unable to be created" },
    { 0xED, "VMEbus error encountered" },
    { 0xEE, "Could not return block sizes" },
    { 0xEF, "Programmer is already attached" },
    { 0xF0, "Request only valid in stop mode" },
    { 0xF1, "Request only valid from programmer" },
    { 0xF2, "Invalid program cannot log in" },
    { 0xF3, "I/O configuration mismatch" },
    { 0xF4, "Invalid input parameter in request" },
    { 0xF5, "Invalid password" },
    { 0xF6, "Invalid sweep state to set" },
    { 0xF7, "Required to log in to a task for service" },
    { 0xF8, "Invalid task name referenced" },
    { 0xF9, "Task address out of range" },
    { 0xFA, "Cannot replace I/O module" },
    { 0xFB, "Cannot clear I/O configuration" },
    { 0xFC, "I/O configuration is invalid" },
    { 0xFD, "Unable to perform auto configuration" },
    { 0xFE, "No privilege for attempted operation" },
    { 0xFF, "Service request has been aborted" },
    { 0, NULL },
};

static const value_string ge_srtp_control_program_num[] = {
    { -1, "SNP master is not logged into a control program" },
    { 0, "SNP master is logged into control program task 0" },
    { 0, NULL },
};

static const true_false_string tfs_oversweep = {
    "The constant sweep value has been exceeded",
    "Sweep time is OK"
}, tfs_constant_sweep_mode = {
    "Constant sweep mode is active",
    "Constant sweep mode is not active"
}, tfs_new_plc_fault = {
    "The PLC fault table has changed since it was last read by this device",
    "The PLC fault table has not changed since it was last read by this device"
}, tfs_new_io_fault = {
    "The I/O fault table has changed since it was last read by this device",
    "The I/O fault table has not changed since it was last read by this device"
}, tfs_plc_fault = {
    "One or more PLC faults are present in the PLC fault table",
    "The PLC fault table is empty"
}, tfs_io_fault = {
    "One or more I/O faults are present in the I/O fault table",
    "The I/O fault table is empty"
}, tfs_programmer_attached = {
    "Programmer is attached",
    "Programmer is not attached"
}, tfs_outputs_switch = {
    "Outputs disabled",
    "Outputs enabled"
}, tfs_run_switch = {
    "Run",
    "Stop"
}, tfs_oem_protection = {
    "OEM protection is enabled",
    "There is no OEM protection"
};

struct ge_srtp_request_key {
    guint32 conversation;
    guint16 srtp_seq_num;
    guint8 mbox_seq_num;
};

struct ge_srtp_request_val {
    guint req_num;
    guint resp_num;
    guint8 svc_req_type;
};

static GHashTable *ge_srtp_request_hash = NULL;

static int
bcd_decode_byte(guint8 byte)
{
    guint8 low_nibble, high_nibble;
    low_nibble = byte & 0x0f;
    high_nibble = (byte & 0xf0) >> 4;
    if (low_nibble > 9 || high_nibble > 9)
        return -1;
    return high_nibble * 10 + low_nibble;
}

// Equal function for request hash table
static gint
ge_srtp_equal(gconstpointer v, gconstpointer w)
{
    const struct ge_srtp_request_key *v1 = (const struct ge_srtp_request_key *)v;
    const struct ge_srtp_request_key *v2 = (const struct ge_srtp_request_key *)w;

    if (v1->conversation == v2->conversation &&
        v1->srtp_seq_num == v2->srtp_seq_num &&
        v1->mbox_seq_num == v2->mbox_seq_num) {
        return 1;
    }

    return 0;
}

// Hash function for request hash table
static guint
ge_srtp_hash(gconstpointer v)
{
    const struct ge_srtp_request_key *key = (const struct ge_srtp_request_key *)v;
    guint val;

    val = key->conversation + 251 * key->srtp_seq_num + 32749 * key->mbox_seq_num;

    return val;
}

static void
ge_srtp_init_protocol(void)
{
    ge_srtp_request_hash = g_hash_table_new(ge_srtp_hash, ge_srtp_equal);
}

static void
ge_srtp_cleanup_protocol(void)
{
    g_hash_table_destroy(ge_srtp_request_hash);
}

#define FRAME_HEADER_LEN 18

static int
dissect_ge_srtp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti, *piggyback_item;
    proto_tree *ge_srtp_tree, *piggyback_tree;
    conversation_t *conversation;
    struct ge_srtp_request_key request_key, *new_request_key;
    struct ge_srtp_request_val *request_val = NULL;

    guint8 mbox_type;
    int timestamp_hr, timestamp_min, timestamp_sec;
    guint next_message_len;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GE SRTP");

    conversation = find_or_create_conversation(pinfo);

    request_key.conversation = conversation->conv_index;
    request_key.srtp_seq_num = tvb_get_guint16(tvb, 2, ENC_LITTLE_ENDIAN);
    request_key.mbox_seq_num = tvb_get_guint8(tvb, 30);

    request_val = (struct ge_srtp_request_val *)g_hash_table_lookup(
            ge_srtp_request_hash, &request_key);

    // Only allocate a new hash element when dissecting a request
    // (0xC0 is Initial Request, 0x80 is Initial Request with Text Buffer)
    mbox_type = tvb_get_guint8(tvb, 31);
    if (!pinfo->fd->flags.visited) {
        if (!request_val && (mbox_type == 0x80 || mbox_type == 0xC0)) {
            new_request_key = wmem_new(wmem_file_scope(),
                    struct ge_srtp_request_key);
            *new_request_key = request_key;

            request_val = wmem_new(wmem_file_scope(),
                    struct ge_srtp_request_val);
            request_val->req_num = pinfo->num;
            request_val->resp_num = 0;
            request_val->svc_req_type = tvb_get_guint8(tvb, 42);

            g_hash_table_insert(ge_srtp_request_hash, new_request_key,
                    request_val);
        }
        // (0xD4 is Completion ACK, 0x94 is Completion ACK with Text Buffer,
        // and 0xD1 is Error NACK)
        if (request_val && (mbox_type == 0xD4 || mbox_type == 0x94 ||
                    mbox_type == 0xD1)) {
            request_val->resp_num = pinfo->num;
        }
    }

    col_clear(pinfo->cinfo, COL_INFO);
    if (mbox_type == 0xC0 || mbox_type == 0x80) {
        guint8 svc_req_code = tvb_get_guint8(tvb, 42);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%s)",
                val_to_str(mbox_type, ge_srtp_mbox_type, "unused"),
                val_to_str(svc_req_code, ge_srtp_svc_req_type,
                    "Service request 0x%02x"));
    } else if (request_val) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%s)",
                val_to_str(mbox_type, ge_srtp_mbox_type, "unused"),
                val_to_str(request_val->svc_req_type, ge_srtp_svc_req_type,
                    "Service request 0x%02x"));
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                val_to_str(mbox_type, ge_srtp_mbox_type, "Unknown (0x%02x)"));
    }

    if (tree) {
        ti = proto_tree_add_item(tree, proto_ge_srtp, tvb, 0, -1, ENC_NA);
        ge_srtp_tree = proto_item_add_subtree(ti, ett_ge_srtp);

        if (mbox_type == 0xC0 || mbox_type == 0x80) {
            if (request_val) {
                if (request_val->resp_num) {
                    proto_tree_add_uint_format(ge_srtp_tree, hf_ge_srtp_respframe,
                            tvb, 0, 0, request_val->resp_num,
                            "The reply to this request is in frame %u",
                            request_val->resp_num);
                }
            }
        } else if (mbox_type == 0xD4 || mbox_type == 0x94 ||
                mbox_type == 0xD1) {
            if (request_val) {
                proto_tree_add_uint(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_code,
                        tvb, 0, 0, request_val->svc_req_type);
                if (request_val->req_num) {
                    proto_tree_add_uint_format(ge_srtp_tree, hf_ge_srtp_reqframe,
                            tvb, 0, 0, request_val->req_num,
                            "This is a reply to a request in frame %u",
                            request_val->req_num);
                }
            }
        }

        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_type,
                tvb, 0, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_seq_num,
                tvb, 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_next_msg_len,
                tvb, NEXT_MESSAGE_LENGTH_OFFSET , 2, ENC_LITTLE_ENDIAN);
        next_message_len = (guint)tvb_get_letohs(tvb, NEXT_MESSAGE_LENGTH_OFFSET) + SRTP_MAILBOX_MESSAGE_LENGTH;

        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_todo,
                tvb, 6, 18, ENC_NA);

        timestamp_hr = bcd_decode_byte(tvb_get_guint8(tvb, 26));
        timestamp_min = bcd_decode_byte(tvb_get_guint8(tvb, 27));
        timestamp_sec = bcd_decode_byte(tvb_get_guint8(tvb, 28));
        if (timestamp_hr != -1 && timestamp_min != -1 && timestamp_sec != -1) {
            proto_tree_add_bytes_format_value(ge_srtp_tree,
                    hf_ge_srtp_mbox_timestamp,
                    tvb, 26, 3, NULL, "%02d:%02d:%02d",
                    timestamp_hr, timestamp_min, timestamp_sec);
        } else {
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_timestamp,
                    tvb, 26, 3, ENC_LITTLE_ENDIAN);
        }
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_seq_num,
                tvb, 30, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_type,
                tvb, 31, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_src_id,
                tvb, 32, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_dst_id,
                tvb, 36, 4, ENC_LITTLE_ENDIAN);

        if (mbox_type == 0x80) {  // Initial Request with Text Buffer
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_code,
                    tvb, 42, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_data_len,
                    tvb, 43, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_packet_num,
                    tvb, 48, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_total_packets,
                    tvb, 49, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_data,
                    tvb, 51, 5, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_text_buffer,
                    tvb, SRTP_MAILBOX_MESSAGE_LENGTH, next_message_len,
                    ENC_LITTLE_ENDIAN);
        } else if (mbox_type == 0x94) {  // Completion ACK with Text Buffer
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_response_data_len,
                    tvb, 42, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_packet_num,
                    tvb, 48, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_total_packets,
                    tvb, 49, 1, ENC_LITTLE_ENDIAN);
            piggyback_item = proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_piggyback_status,
                    tvb, 50, 6, ENC_NA);
            piggyback_tree = proto_item_add_subtree(piggyback_item, ett_piggyback);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_control_program_num,
                    tvb, 50, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_privilege_level,
                    tvb, 51, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_last_sweep,
                    tvb, 52, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_oversweep,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_constant_sweep_mode,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_new_plc_fault,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_new_io_fault,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_plc_fault,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_io_fault,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_programmer_attached,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_outputs_switch,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_run_switch,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_oem_protection,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_plc_state,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_text_buffer,
                    tvb, SRTP_MAILBOX_MESSAGE_LENGTH, next_message_len,
                    ENC_LITTLE_ENDIAN);
        } else if (mbox_type == 0xC0) {  // Initial Request
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_packet_num,
                    tvb, 40, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_total_packets,
                    tvb, 41, 1, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_code,
                    tvb, 42, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_data,
                    tvb, 43, 13, ENC_LITTLE_ENDIAN);
        } else if (mbox_type == 0xD1) {  // Error Nack
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_packet_num,
                    tvb, 40, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_total_packets,
                    tvb, 41, 1, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_major_error_status,
                    tvb, 42, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_minor_error_status,
                    tvb, 43, 1, ENC_LITTLE_ENDIAN);
        } else if (mbox_type == 0xD4) {  // Completion ACK
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_packet_num,
                    tvb, 40, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_total_packets,
                    tvb, 41, 1, ENC_LITTLE_ENDIAN);

            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_status_code,
                    tvb, 42, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_status_data,
                    tvb, 43, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_response_data,
                    tvb, 44, 6, ENC_LITTLE_ENDIAN);
            piggyback_item = proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_piggyback_status,
                    tvb, 50, 6, ENC_NA);
            piggyback_tree = proto_item_add_subtree(piggyback_item, ett_piggyback);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_control_program_num,
                    tvb, 50, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_privilege_level,
                    tvb, 51, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_last_sweep,
                    tvb, 52, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_oversweep,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_constant_sweep_mode,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_new_plc_fault,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_new_io_fault,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_plc_fault,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_io_fault,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_programmer_attached,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_outputs_switch,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_run_switch,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_oem_protection,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(piggyback_tree, hf_ge_srtp_mbox_plc_status_word_plc_state,
                    tvb, 54, 2, ENC_LITTLE_ENDIAN);
        }
    }

    return tvb_reported_length(tvb);
}

static guint
get_ge_srtp_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
        void *data _U_)
{
    return (guint)tvb_get_letohs(tvb, offset + NEXT_MESSAGE_LENGTH_OFFSET) + SRTP_MAILBOX_MESSAGE_LENGTH;
}

static int
dissect_ge_srtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
            get_ge_srtp_message_len, dissect_ge_srtp_message, data);
    return tvb_reported_length(tvb);
}

void
proto_register_ge_srtp(void)
{
    static hf_register_info hf[] = {
        { &hf_ge_srtp_reqframe,
          { "Request Frame", "ge_srtp.reqframe",
            FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_ge_srtp_respframe,
          { "Response Frame", "ge_srtp.respframe",
            FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_ge_srtp_type,
          { "SRTP Packet Type", "ge_srtp.type",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_seq_num,
          { "SRTP Sequence Number", "ge_srtp.seq_num",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_next_msg_len,
          { "Next Message Length", "ge_srtp.next_msg_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_todo,
          { "TODO", "ge_srtp.todo",
            FT_NONE, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_timestamp,
          { "Timestamp", "ge_srtp.timestamp",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            "Timestamp (optional)", HFILL }
        },
        { &hf_ge_srtp_mbox_seq_num,
          { "Mailbox Sequence Number", "ge_srtp.mbox_seq_num",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            "Mailbox message sequence number", HFILL }
        },
        { &hf_ge_srtp_mbox_type,
          { "Mailbox Type", "ge_srtp.mbox_type",
            FT_UINT8, BASE_HEX,
            VALS(ge_srtp_mbox_type), 0,
            "Mailbox message type code", HFILL }
        },
        { &hf_ge_srtp_mbox_src_id,
          { "Mailbox Source ID", "ge_srtp.mbox_src_id",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_dst_id,
          { "Mailbox Destination ID", "ge_srtp.mbox_dst_id",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_packet_num,
          { "Packet number", "ge_srtp.packet_num",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_total_packets,
          { "Total packets", "ge_srtp.total_packets",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_svc_req_code,
          { "Service request code", "ge_srtp.svc_req_code",
            FT_UINT8, BASE_HEX,
            VALS(ge_srtp_svc_req_type), 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_svc_req_data,
          { "Service request data", "ge_srtp.svc_req_data",
            FT_BYTES, SEP_SPACE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_svc_req_data_len,
          { "Service request data length", "ge_srtp.svc_req_data_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_status_code,
          { "Status code", "ge_srtp.status_code",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_status_data,
          { "Status data", "ge_srtp.status_data",
            FT_BYTES, SEP_SPACE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_response_data,
          { "Response data", "ge_srtp.response_data",
            FT_BYTES, SEP_SPACE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_piggyback_status,
          { "Piggyback status information", "ge_srtp.piggyback_status",
            FT_NONE, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_control_program_num,
          { "Control program number", "ge_srtp.control_program_num",
            FT_INT8, BASE_DEC,
            VALS(ge_srtp_control_program_num), 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_privilege_level,
          { "Privilege level", "ge_srtp.privilege_level",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_last_sweep,
          { "Last sweep time", "ge_srtp.last_sweep",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            "Last sweep time (ms)", HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word,
          { "PLC status word", "ge_srtp.plc_status_word",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_oversweep,
          { "Oversweep flag", "ge_srtp.plc_status_word.oversweep",
            FT_BOOLEAN, 16,
            TFS(&tfs_oversweep), 0x0001,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_constant_sweep_mode,
          { "Constant sweep mode", "ge_srtp.plc_status_word.constant_sweep_mode",
            FT_BOOLEAN, 16,
            TFS(&tfs_constant_sweep_mode), 0x0002,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_new_plc_fault,
          { "New PLC fault", "ge_srtp.plc_status_word.new_plc_fault",
            FT_BOOLEAN, 16,
            TFS(&tfs_new_plc_fault), 0x0004,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_new_io_fault,
          { "New I/O fault", "ge_srtp.plc_status_word.new_io_fault",
            FT_BOOLEAN, 16,
            TFS(&tfs_new_io_fault), 0x0008,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_plc_fault,
          { "PLC fault present", "ge_srtp.plc_status_word.plc_fault",
            FT_BOOLEAN, 16,
            TFS(&tfs_plc_fault), 0x0010,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_io_fault,
          { "I/O fault present", "ge_srtp.plc_status_word.io_fault",
            FT_BOOLEAN, 16,
            TFS(&tfs_io_fault), 0x0020,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_programmer_attached,
          { "Programmer attachment flag", "ge_srtp.plc_status_word.programmer_attached",
            FT_BOOLEAN, 16,
            TFS(&tfs_programmer_attached), 0x0040,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_outputs_switch,
          { "Outputs enabled/disabled switch", "ge_srtp.plc_status_word.outputs_switch",
            FT_BOOLEAN, 16,
            TFS(&tfs_outputs_switch), 0x0080,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_run_switch,
          { "Run/stop switch", "ge_srtp.plc_status_word.run_switch",
            FT_BOOLEAN, 16,
            TFS(&tfs_run_switch), 0x0100,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_oem_protection,
          { "OEM protection", "ge_srtp.plc_status_word.oem_protection",
            FT_BOOLEAN, 16,
            TFS(&tfs_oem_protection), 0x0200,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_plc_status_word_plc_state,
          { "PLC state", "ge_srtp.plc_status_word.plc_state",
            FT_UINT16, BASE_DEC,
            VALS(ge_srtp_plc_state), 0xf000,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_response_data_len,
          { "Response data length", "ge_srtp.response_data_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_major_error_status,
          { "Major error status", "ge_srtp.major_error_status",
            FT_UINT8, BASE_HEX,
            VALS(ge_srtp_major_error_status), 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_mbox_minor_error_status,
          { "Minor error status", "ge_srtp.minor_error_status",
            FT_UINT8, BASE_HEX,
            VALS(ge_srtp_minor_error_status), 0,
            NULL, HFILL }
        },
        { &hf_ge_srtp_text_buffer,
          { "Text Buffer", "ge_srtp.text_buffer",
            FT_NONE, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_ge_srtp,
        &ett_piggyback,
    };

    proto_ge_srtp = proto_register_protocol("GE SRTP", "GE SRTP", "ge_srtp");

    proto_register_field_array(proto_ge_srtp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_init_routine(ge_srtp_init_protocol);
    register_cleanup_routine(ge_srtp_cleanup_protocol);

    prefs_register_protocol(proto_ge_srtp, proto_reg_handoff_ge_srtp);
}

void
proto_reg_handoff_ge_srtp(void)
{
    dissector_handle_t ge_srtp_handle;

    ge_srtp_handle = create_dissector_handle(dissect_ge_srtp, proto_ge_srtp);
    dissector_add_uint_with_preference("tcp.port", GE_SRTP_TCP_PORT, ge_srtp_handle);
}
