/* Native UHR helpers. SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef PACKET_IEEE80211_UHR_H
#define PACKET_IEEE80211_UHR_H

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>

void register_uhr_fields(int proto_wlan, module_t *module, expert_module_t *expert);
void dissect_uhr_operation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                           int len);
void dissect_uhr_capabilities(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                              int len, bool from_ap);
void dissect_uhr_smd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int len);
void dissect_uhr_mode_change(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,
                             int len);
unsigned dissect_uhr_action(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

#endif
