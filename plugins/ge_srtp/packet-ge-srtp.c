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
#include <epan/expert.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>

#include <epan/prefs.h>

#include <stdlib.h>

void proto_register_ge_srtp(void);
void proto_reg_handoff_ge_srtp(void);

static int proto_ge_srtp = -1;

static int hf_ge_srtp_mbox_todo_1 = -1;
static int hf_ge_srtp_mbox_todo_2 = -1;

/* Mailbox messages */
static int hf_ge_srtp_mbox_reserved_1 = -1; // TODO: what's the best practices on reserved fields?
static int hf_ge_srtp_mbox_timestamp = -1; // TODO: BCD decode time
static int hf_ge_srtp_mbox_reserved_2 = -1;
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
static int hf_ge_srtp_mbox_svc_req_reserved = -1;
static int hf_ge_srtp_mbox_packet_num_2 = -1; // TODO: coalescse these into one field, read it from different places
static int hf_ge_srtp_mbox_total_packets_2 = -1;

/* Completion ACK/Completion ACK with text buffer */
static int hf_ge_srtp_mbox_status_code = -1;
static int hf_ge_srtp_mbox_status_data = -1;
static int hf_ge_srtp_mbox_response_data = -1;
static int hf_ge_srtp_mbox_control_program_num = -1; // TODO: subtree for piggyback
static int hf_ge_srtp_mbox_privilege_level = -1;
static int hf_ge_srtp_mbox_last_sweep = -1;
static int hf_ge_srtp_mbox_plc_status_word = -1; // TODO: bitfield

static int hf_ge_srtp_mbox_response_data_len = -1;
static int hf_ge_srtp_mbox_ack_reserved = -1;
static int hf_ge_srtp_mbox_packet_num_3 = -1;
static int hf_ge_srtp_mbox_total_packets_3 = -1;

/* Error NACK */
static int hf_ge_srtp_mbox_major_error_status = -1;
static int hf_ge_srtp_mbox_minor_error_status = -1;
static int hf_ge_srtp_mbox_nack_reserved = -1;

static expert_field ei_ge_srtp_mbox_type_unknown = EI_INIT;

#define GE_SRTP_TCP_PORT 18245

static gint ett_ge_srtp = -1;

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
    { 0x03, "Return Control Program Name" },
    { 0x04, "Read System Memory" },
    { 0x05, "Read Task Memory" },
    { 0x06, "Read Program Block Memory" },
    { 0x07, "Write System Memory" },
    { 0x08, "Write Task Memory" },
    { 0x09, "Write Program Block Memory" },
    { 0x15, "Establish Datagram" },
    { 0x16, "Update Datagram" },
    { 0x17, "Cancel Datagram" },
    { 0x20, "Programmer Logon" },
    { 0x21, "Change PLC CPU Privilege Level" },
    { 0x22, "Set PLC CPU Controller ID" },
    { 0x23, "Set PLC State" },
    { 0x24, "Set PLC Time/Date" },
    { 0x25, "Return PLC Time/Date" },
    { 0x38, "Return Fault Table" },
    { 0x39, "Clear Fault Table" },
    { 0x3F, "Program Store" },
    { 0x40, "Program Load" },
    { 0x43, "Return Controller Type and ID Information" },
    { 0x44, "Toggle Force System Memory" },
    { 0x48, "Write Datagram" },
    { 0, NULL }
};

/* Packet length must be at least 32 for there to be a valid mailbox message */
#define GE_SRTP_MIN_LENGTH 32

static int
dissect_ge_srtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_item *mbox_type_ti;
    proto_tree *ge_srtp_tree;
    gint todo_2_remaining;

    if (tvb_reported_length(tvb) < GE_SRTP_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GE SRTP");

    ti = proto_tree_add_item(tree, proto_ge_srtp, tvb, 0, -1, ENC_NA);
    ge_srtp_tree = proto_item_add_subtree(ti, ett_ge_srtp);
    proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_todo_1,
            tvb, 0, 24, ENC_NA);
    todo_2_remaining = tvb_captured_length_remaining(tvb, 56);
    if (todo_2_remaining > 0) {
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_todo_2,
                tvb, 56, todo_2_remaining, ENC_NA);
    }

    proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_reserved_1,
            tvb, 24, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_timestamp,
            tvb, 26, 3, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_reserved_2,
            tvb, 29, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_seq_num,
            tvb, 30, 1, ENC_LITTLE_ENDIAN);
    mbox_type_ti = proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_type,
            tvb, 31, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_src_id,
            tvb, 32, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_dst_id,
            tvb, 36, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_packet_num,
            tvb, 40, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_total_packets,
            tvb, 41, 1, ENC_LITTLE_ENDIAN);

    guint8 mbox_type = tvb_get_guint8(tvb, 31);
    col_clear(pinfo->cinfo, COL_INFO);
    if (mbox_type == 0xC0 || mbox_type == 0x80) {
        guint8 svc_req_code = tvb_get_guint8(tvb, 42);
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%s)",
                val_to_str(mbox_type, ge_srtp_mbox_type, "unused"),
                val_to_str(svc_req_code, ge_srtp_svc_req_type,
                    "Service request 0x%02x"));
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                val_to_str(mbox_type, ge_srtp_mbox_type, "Unknown (0x%02x)"));
    }
    if (mbox_type == 0x80) {
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_code,
                tvb, 42, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_data_len,
                tvb, 43, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_reserved,
                tvb, 47, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_packet_num_2,
                tvb, 48, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_total_packets_2,
                tvb, 49, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_data,
                tvb, 51, 5, ENC_LITTLE_ENDIAN);
    } else if (mbox_type == 0x94) {
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_response_data_len,
                tvb, 42, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_ack_reserved,
                tvb, 44, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_packet_num_3,
                tvb, 48, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_total_packets_3,
                tvb, 49, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_control_program_num,
                tvb, 50, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_privilege_level,
                tvb, 51, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_last_sweep,
                tvb, 52, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_plc_status_word,
                tvb, 54, 2, ENC_LITTLE_ENDIAN);
    } else if (mbox_type == 0xC0) {
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_code,
                tvb, 42, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_svc_req_data,
                tvb, 43, 13, ENC_LITTLE_ENDIAN);
    } else if (mbox_type == 0xD1) {
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_major_error_status,
                tvb, 42, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_minor_error_status,
                tvb, 43, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_nack_reserved,
                tvb, 44, 12, ENC_LITTLE_ENDIAN);
    } else if (mbox_type == 0xD4) {
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_status_code,
                tvb, 42, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_status_data,
                tvb, 43, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_response_data,
                tvb, 44, 6, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_control_program_num,
                tvb, 50, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_privilege_level,
                tvb, 51, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_last_sweep,
                tvb, 52, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_plc_status_word,
                tvb, 54, 2, ENC_LITTLE_ENDIAN);
    } else {
        expert_add_info(pinfo, mbox_type_ti, &ei_ge_srtp_mbox_type_unknown);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_ge_srtp(void)
{
    expert_module_t *expert_ge_srtp;

    static hf_register_info hf[] = {
        { &hf_ge_srtp_mbox_todo_1,
          { "TODO", "ge_srtp.todo_1",
            FT_NONE, BASE_NONE,
            NULL, 0,
            "TODO", HFILL }
        },
        { &hf_ge_srtp_mbox_reserved_1,
          { "Reserved (0)", "ge_srtp.reserved_2",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            "Reserved field, must be zero", HFILL }
        },
        { &hf_ge_srtp_mbox_timestamp,
          { "Timestamp", "ge_srtp.timestamp",
            FT_UINT24, BASE_HEX,
            NULL, 0,
            "Timestamp (optional)", HFILL }
        },
        { &hf_ge_srtp_mbox_reserved_2,
          { "Reserved (0)", "ge_srtp.reserved_2",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            "Reserved field, must be zero", HFILL }
        },
        { &hf_ge_srtp_mbox_seq_num,
          { "Sequence Number", "ge_srtp.mbox_seq_num",
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
            "Mailbox source ID", HFILL }
        },
        { &hf_ge_srtp_mbox_dst_id,
          { "Mailbox Destination ID", "ge_srtp.mbox_dst_id",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            "Mailbox destination ID", HFILL }
        },
        { &hf_ge_srtp_mbox_packet_num,
          { "Packet number", "ge_srtp.packet_num",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            "Packet number", HFILL }
        },
        { &hf_ge_srtp_mbox_total_packets,
          { "Total packets", "ge_srtp.total_packets",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            "Total packets", HFILL }
        },
        { &hf_ge_srtp_mbox_todo_2,
          { "TODO", "ge_srtp.todo_2",
            FT_NONE, BASE_NONE,
            NULL, 0,
            "TODO", HFILL }
        },
        { &hf_ge_srtp_mbox_svc_req_code,
          { "Service request code", "ge_srtp.svc_req_code",
            FT_UINT8, BASE_HEX,
            VALS(ge_srtp_svc_req_type), 0,
            "Service request code", HFILL }
        },
        { &hf_ge_srtp_mbox_svc_req_data,
          { "Service request data", "ge_srtp.svc_req_data",
            FT_BYTES, SEP_SPACE,
            NULL, 0,
            "Service request data", HFILL }
        },
        { &hf_ge_srtp_mbox_svc_req_data_len,
          { "Service request data length", "ge_srtp.svc_req_data_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            "Service request data length", HFILL }
        },
        { &hf_ge_srtp_mbox_svc_req_reserved,
          { "Reserved", "ge_srtp.svc_req_reserved",
            FT_NONE, BASE_NONE,
            NULL, 0,
            "Reserved", HFILL }
        },
        { &hf_ge_srtp_mbox_packet_num_2,
          { "Packet number", "ge_srtp.packet_num_2",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            "Packet number", HFILL }
        },
        { &hf_ge_srtp_mbox_total_packets_2,
          { "Total packets", "ge_srtp.total_packets_2",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            "Total packets", HFILL }
        },
        { &hf_ge_srtp_mbox_status_code,
          { "Status code", "ge_srtp.status_code",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            "Status code", HFILL }
        },
        { &hf_ge_srtp_mbox_status_data,
          { "Status data", "ge_srtp.status_data",
            FT_BYTES, SEP_SPACE,
            NULL, 0,
            "Status data", HFILL }
        },
        { &hf_ge_srtp_mbox_response_data,
          { "Response data", "ge_srtp.response_data",
            FT_BYTES, SEP_SPACE,
            NULL, 0,
            "Response data", HFILL }
        },
        { &hf_ge_srtp_mbox_control_program_num,
          { "Control program number", "ge_srtp.control_program_num",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            "Control program number", HFILL }
        },
        { &hf_ge_srtp_mbox_privilege_level,
          { "Privilege level", "ge_srtp.privilege_level",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            "Privilege level", HFILL }
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
            "PLC status word", HFILL }
        },
        { &hf_ge_srtp_mbox_response_data_len,
          { "Response data length", "ge_srtp.response_data_len",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            "Response data length", HFILL }
        },
        { &hf_ge_srtp_mbox_ack_reserved,
          { "Reserved", "ge_srtp.ack_reserved",
            FT_NONE, BASE_NONE,
            NULL, 0,
            "Reserved", HFILL }
        },
        { &hf_ge_srtp_mbox_packet_num_3,
          { "Packet number", "ge_srtp.packet_num_3",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            "Packet number", HFILL }
        },
        { &hf_ge_srtp_mbox_total_packets_3,
          { "Total packets", "ge_srtp.total_packets_3",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            "Total packets", HFILL }
        },
        { &hf_ge_srtp_mbox_major_error_status,
          { "Major error status", "ge_srtp.major_error_status",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            "Major error status", HFILL }
        },
        { &hf_ge_srtp_mbox_minor_error_status,
          { "Minor error status", "ge_srtp.minor_error_status",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            "Minor error status", HFILL }
        },
        { &hf_ge_srtp_mbox_nack_reserved,
          { "Reserved", "ge_srtp.nack_reserved",
            FT_NONE, BASE_NONE,
            NULL, 0,
            "Reserved", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_ge_srtp
    };

    static ei_register_info ei[] = {
        { &ei_ge_srtp_mbox_type_unknown,
          { "ge_srtp.mbox_type_unknown", PI_UNDECODED, PI_WARN,
            "Mailbox message type code was not recognized", EXPFILL }
        }
    };

    proto_ge_srtp = proto_register_protocol("GE SRTP", "GE SRTP", "ge_srtp");

    proto_register_field_array(proto_ge_srtp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_ge_srtp = expert_register_protocol(proto_ge_srtp);
    expert_register_field_array(expert_ge_srtp, ei, array_length(ei));

    prefs_register_protocol(proto_ge_srtp, proto_reg_handoff_ge_srtp);
}

void
proto_reg_handoff_ge_srtp(void)
{
    dissector_handle_t ge_srtp_handle;

    ge_srtp_handle = create_dissector_handle(dissect_ge_srtp, proto_ge_srtp);
    dissector_add_uint_with_preference("tcp.port", GE_SRTP_TCP_PORT, ge_srtp_handle);
}
