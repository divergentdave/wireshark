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
static int hf_ge_srtp_mbox_type = -1;
static expert_field ei_ge_srtp_todo = EI_INIT;

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

/* Packet length must be at least 32 for there to be a valid mailbox message */
#define GE_SRTP_MIN_LENGTH 32

static int
dissect_ge_srtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_item *mbox_type_ti;
    proto_tree *ge_srtp_tree;

    if (tvb_reported_length(tvb) < GE_SRTP_MIN_LENGTH)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GE SRTP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_ge_srtp, tvb, 0, -1, ENC_NA);
    ge_srtp_tree = proto_item_add_subtree(ti, ett_ge_srtp);
    mbox_type_ti = proto_tree_add_item(ge_srtp_tree, hf_ge_srtp_mbox_type,
            tvb, 31, 1, ENC_BIG_ENDIAN);

    guint8 mbox_type = tvb_get_guint8(tvb, 31);
    if (mbox_type == 0x80 || mbox_type == 0x94 || mbox_type == 0xC0 ||
            mbox_type == 0xD1 || mbox_type == 0xD4) {
        proto_item_append_text(mbox_type_ti, ": %s",
                val_to_str(mbox_type, ge_srtp_mbox_type, "N/A"));
    }

    return tvb_captured_length(tvb);
}

void
proto_register_ge_srtp(void)
{
    expert_module_t *expert_ge_srtp;

    static hf_register_info hf[] = {
        { &hf_ge_srtp_mbox_type,
          { "GE SRTP Mailbox Type", "ge_srtp.mbox_type",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_ge_srtp
    };

    static ei_register_info ei[] = {
        { &ei_ge_srtp_todo,
          { "ge_srtp.EXPERTABBREV", PI_MALFORMED, PI_ERROR,
            "EXPERTDESCR", EXPFILL }
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
