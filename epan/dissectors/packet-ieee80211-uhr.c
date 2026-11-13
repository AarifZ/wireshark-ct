/* Native IEEE 802.11bn UHR decoding using public Linux reference layouts.
 * Copyright 2026 Mohammad Aarif
 * SPDX-License-Identifier: GPL-2.0-or-later
 * See doc/README.uhr for pinned sources and interpretation limits.
 */
#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include "packet-ieee80211-uhr.h"

enum {
    LAYOUT,
    OP_CONTROL,
    BASIC_MCS,
    TAIL,
    DUO,
    DPS_CONTROL,
    NPCA_CONTROL,
    NPCA_OFFSET,
    NPCA_BITMAP,
    PEDCA_CONTROL,
    DBE_CONTROL,
    DBE_BITMAP,
    MAC,
    PHY,
    PHY_RESERVED,
    OM_TIMEOUT,
    TIM_INTERVAL,
    DBE_CAP,
    DBE_SWITCH,
    DBE_INTERVAL,
    DBE_MCS160,
    DBE_MCS320,
    DBE_BWCAP,
    SMD_ID,
    SMD_CAP,
    SMD_TIMEOUT,
    MODE_CONTROL,
    MODE_ID,
    MODE_ENABLE,
    MODE_UPDATE,
    MODE_LENGTH,
    MODE_SPECIFIC,
    MODE_DATA,
    ACTION,
    ACTION_TOKEN,
    ACTION_TYPE,
    ACTION_COUNT,
    B_UHR_OPER_PARAMS_DPS_ENA,
    B_UHR_OPER_PARAMS_NPCA_ENA,
    B_UHR_OPER_PARAMS_PEDCA_ENA,
    B_UHR_OPER_PARAMS_DBE_ENA,
    B_UHR_OPER_PARAMS_DBE_BW,
    B_UHR_OPER_PARAMS_ELR_RX,
    B_UHR_OPER_PARAMS_DUO_PRES,
    B_UHR_OPER_PARAMS_DPS_PRES,
    B_UHR_OPER_PARAMS_NPCA_PRES,
    B_UHR_OPER_PARAMS_PEDCA_PRES,
    B_UHR_OPER_PARAMS_DBE_PRES,
    B_UHR_DPS_PADDING_DELAY,
    B_UHR_DPS_TRANSITION_DELAY,
    B_UHR_DPS_ICF_REQUIRED,
    B_UHR_DPS_PARAMETERIZED_FLAG,
    B_UHR_DPS_LC_MODE_BW,
    B_UHR_DPS_LC_MODE_NSS,
    B_UHR_DPS_LC_MODE_MCS,
    B_UHR_DPS_MOBILE_AP_DPS_STATIC_HCM,
    B_UHR_NPCA_PARAMS_PRIMARY_CHAN,
    B_UHR_NPCA_PARAMS_MIN_DUR_THRESH,
    B_UHR_NPCA_PARAMS_SWITCH_DELAY,
    B_UHR_NPCA_PARAMS_SWITCH_BACK_DELAY,
    B_UHR_NPCA_PARAMS_INIT_QSRC,
    B_UHR_NPCA_PARAMS_MOPLEN,
    B_UHR_NPCA_PARAMS_DIS_SUBCH_BMAP_PRES,
    B_UHR_P_EDCA_ECWMIN,
    B_UHR_P_EDCA_ECWMAX,
    B_UHR_P_EDCA_AIFSN,
    B_UHR_P_EDCA_CW_DS,
    B_UHR_P_EDCA_PSRC_THRESHOLD,
    B_UHR_P_EDCA_QSRC_THRESHOLD,
    B_UHR_DBE_OPER_BANDWIDTH,
    B_UHR_DBE_OPER_DIS_SUBCHANNEL_BITMAP_PRES,
    B_UHR_MAC_CAP_DBE_MAX_BW,
    B_UHR_MAC_CAP_DBE_EHT_MCS_MAP_160_PRES,
    B_UHR_MAC_CAP_DBE_EHT_MCS_MAP_320_PRES,
    B_UHR_MAC_CAP_DBE_CAP_NUM_SND_DIMS,
    B_UHR_MAC_CAP_DBE_CAP_NON_OFDMA_UL_MUMIMO,
    B_UHR_MAC_CAP_DBE_CAP_MU_BEAMFORMER,
    B_UHR_MAC_CAP_DBE_CAP_BEAMFORMEE_SS,
    B_UHR_MAC_CAP0_DPS_SUPP,
    B_UHR_MAC_CAP0_DPS_ASSIST_SUPP,
    B_UHR_MAC_CAP0_DPS_AP_STATIC_HCM_SUPP,
    B_UHR_MAC_CAP0_NPCA_SUPP,
    B_UHR_MAC_CAP0_ENH_BSR_SUPP,
    B_UHR_MAC_CAP0_ADD_MAP_TID_SUPP,
    B_UHR_MAC_CAP0_EOTSP_SUPP,
    B_UHR_MAC_CAP1_DSO_SUPP,
    B_UHR_MAC_CAP1_PEDCA_SUPP,
    B_UHR_MAC_CAP1_DBE_SUPP,
    B_UHR_MAC_CAP1_UL_LLI_SUPP,
    B_UHR_MAC_CAP1_P2P_LLI_SUPP,
    B_UHR_MAC_CAP1_PUO_SUPP,
    B_UHR_MAC_CAP1_AP_PUO_SUPP,
    B_UHR_MAC_CAP1_DUO_SUPP,
    B_UHR_MAC_CAP2_OMC_UL_MU_DIS_RX_SUPP,
    B_UHR_MAC_CAP2_AOM_SUPP,
    B_UHR_MAC_CAP2_IFCS_LOC_SUPP,
    B_UHR_MAC_CAP2_UHR_TRS_SUPP,
    B_UHR_MAC_CAP2_TXSPG_SUPP,
    B_UHR_MAC_CAP2_TXOP_RET_IN_TXSPG,
    B_UHR_MAC_CAP2_UHR_OM_PU_TO_LOW,
    B_UHR_MAC_CAP3_UHR_OM_PU_TO_HIGH,
    B_UHR_MAC_CAP3_PARAM_UPD_ADV_NOTIF_INTV,
    B_UHR_MAC_CAP3_UPD_IND_TIM_INTV_LOW,
    B_UHR_MAC_CAP4_UPD_IND_TIM_INTV_HIGH,
    B_UHR_MAC_CAP4_BOUNDED_ESS,
    B_UHR_MAC_CAP4_BTM_ASSURANCE,
    B_UHR_MAC_CAP4_CO_BF_SUPP,
    B_UHR_MAC_CAP4_CO_SR_SUPP,
    B_UHR_MAC_CAP5_MAPC_ENH_MSRMT_SUPP,
    B_UHR_PHY_CAP_MAX_NSS_RX_SND_NDP_LE80,
    B_UHR_PHY_CAP_MAX_NSS_RX_DL_MU_LE80,
    B_UHR_PHY_CAP_MAX_NSS_RX_SND_NDP_160,
    B_UHR_PHY_CAP_MAX_NSS_RX_DL_MU_160,
    B_UHR_PHY_CAP_MAX_NSS_RX_SND_NDP_320,
    B_UHR_PHY_CAP_MAX_NSS_RX_DL_MU_320,
    B_UHR_PHY_CAP_ELR_TX,
    B_UHR_PHY_CAP_ELR_RX,
    B_UHR_PHY_CAP_PART_BW_DL_MUMIMO,
    B_UHR_PHY_CAP_PART_BW_UL_MUMIMO,
    B_UHR_PHY_CAP_MCS15,
    B_UHR_PHY_CAP_2XLDPC_TX,
    B_UHR_PHY_CAP_2XLDPC_RX,
    B_UHR_PHY_CAP_UEQM_TX_MAX_NSS,
    B_UHR_PHY_CAP_UEQM_RX_MAX_NSS,
    B_UHR_PHY_CAP_CO_BF_JOINT_SOUNDING,
    B_UHR_PHY_CAP_IM_TX,
    B_UHR_PHY_CAP_IM_RX,
    B_UHR_PHY_CAP_CO_SR_MODE_1,
    B_UHR_PHY_CAP_CO_SR_MODE_2,
    B_UHR_PHY_CAP_DRU_DBW_20_IN_PBW_20,
    B_UHR_PHY_CAP_DRU_DBW_40_IN_PBW_40,
    B_UHR_PHY_CAP_DRU_DBW_80_IN_PBW_80,
    B_UHR_PHY_CAP_DRU_DBW_80_IN_PBW_160,
    B_UHR_PHY_CAP_DRU_DBW_80_IN_PBW_320,
    B_UHR_PHY_CAP_DRU_DBW_20_IN_PBW_GE80,
    B_UHR_PHY_CAP_DRU_DBW_40_IN_PBW_GE80,
    B_UHR_PHY_CAP_DRU_DBW_60_IN_PBW_GE80,
    B_UHR_PHY_CAP_DRU_RRU_HYBRID_MODE,
    B_SMD_INFO_CAPA_DL_DATA_FWD,
    B_SMD_INFO_CAPA_MAX_NUM_PREP,
    B_SMD_INFO_CAPA_TYPE,
    B_SMD_INFO_CAPA_PTK_PER_AP_MLD,
    FIELD_COUNT
};
static int hf[FIELD_COUNT];
static int ett_uhr, ett_parameters;
static expert_field ei_short, ei_raw;
static int layout;
static const enum_val_t layouts[] = {
    {"d1_5", "D1.5 public reference", 0},
    {"pre_d1_5", "Pre D1.5 public Linux reference 410d70acf9ca", 1},
    {NULL, NULL, 0}};
static const value_string modes[] = {
    {0, "DPS"}, {1, "NPCA"},  {2, "DUO"},   {3, "DSO"},    {4, "P-EDCA"}, {5, "ELR RX"}, {6, "AOM"},
    {7, "LLI"}, {8, "Co-BF"}, {9, "Co-SR"}, {10, "EMLSR"}, {11, "DBE"},   {0, NULL}};
static const value_string actions[] = {{0, "Link Reconfiguration Request"},
                                       {1, "Link Reconfiguration Response"},
                                       {2, "Link Reconfiguration Notify"},
                                       {0, NULL}};
typedef struct {
    int field;
    uint32_t mask, old_mask;
    unsigned byte;
} uhr_bit_t;
static const uhr_bit_t op_bits[] = {{B_UHR_OPER_PARAMS_DPS_ENA, 0x00000001U, 0x00000001U, 0},
                                    {B_UHR_OPER_PARAMS_NPCA_ENA, 0x00000002U, 0x00000002U, 0},
                                    {B_UHR_OPER_PARAMS_PEDCA_ENA, 0x00000004U, 0x00000004U, 0},
                                    {B_UHR_OPER_PARAMS_DBE_ENA, 0x00000008U, 0x00000008U, 0},
                                    {B_UHR_OPER_PARAMS_DBE_BW, 0x00000070U, 0x00000070U, 0},
                                    {B_UHR_OPER_PARAMS_ELR_RX, 0x00000080U, 0x00000000U, 0},
                                    {B_UHR_OPER_PARAMS_DUO_PRES, 0x00000100U, 0x00000080U, 0},
                                    {B_UHR_OPER_PARAMS_DPS_PRES, 0x00000200U, 0x00000100U, 0},
                                    {B_UHR_OPER_PARAMS_NPCA_PRES, 0x00000400U, 0x00000200U, 0},
                                    {B_UHR_OPER_PARAMS_PEDCA_PRES, 0x00000800U, 0x00000400U, 0},
                                    {B_UHR_OPER_PARAMS_DBE_PRES, 0x00001000U, 0x00000800U, 0}};
static const uhr_bit_t dps_bits[] = {
    {B_UHR_DPS_PADDING_DELAY, 0x0000003fU, 0x0000003fU, 0},
    {B_UHR_DPS_TRANSITION_DELAY, 0x00003f00U, 0x00003f00U, 0},
    {B_UHR_DPS_ICF_REQUIRED, 0x00010000U, 0x00010000U, 0},
    {B_UHR_DPS_PARAMETERIZED_FLAG, 0x00020000U, 0x00020000U, 0},
    {B_UHR_DPS_LC_MODE_BW, 0x001c0000U, 0x001c0000U, 0},
    {B_UHR_DPS_LC_MODE_NSS, 0x01e00000U, 0x01e00000U, 0},
    {B_UHR_DPS_LC_MODE_MCS, 0x1e000000U, 0x1e000000U, 0},
    {B_UHR_DPS_MOBILE_AP_DPS_STATIC_HCM, 0x20000000U, 0x20000000U, 0}};
static const uhr_bit_t npca_bits[] = {
    {B_UHR_NPCA_PARAMS_PRIMARY_CHAN, 0x000000ffU, 0x00000000U, 0},
    {B_UHR_NPCA_PARAMS_MIN_DUR_THRESH, 0x00000f00U, 0x000000f0U, 0},
    {B_UHR_NPCA_PARAMS_SWITCH_DELAY, 0x0003f000U, 0x00003f00U, 0},
    {B_UHR_NPCA_PARAMS_SWITCH_BACK_DELAY, 0x00fc0000U, 0x000fc000U, 0},
    {B_UHR_NPCA_PARAMS_INIT_QSRC, 0x03000000U, 0x00300000U, 0},
    {B_UHR_NPCA_PARAMS_MOPLEN, 0x04000000U, 0x00400000U, 0},
    {B_UHR_NPCA_PARAMS_DIS_SUBCH_BMAP_PRES, 0x08000000U, 0x00800000U, 0}};
static const uhr_bit_t pedca_bits[] = {{B_UHR_P_EDCA_ECWMIN, 0x00000007U, 0x0000000fU, 0},
                                       {B_UHR_P_EDCA_ECWMAX, 0x00000038U, 0x000000f0U, 0},
                                       {B_UHR_P_EDCA_AIFSN, 0x000001c0U, 0x0000000fU, 0},
                                       {B_UHR_P_EDCA_CW_DS, 0x00000600U, 0x00000030U, 0},
                                       {B_UHR_P_EDCA_PSRC_THRESHOLD, 0x00003800U, 0x000001c0U, 0},
                                       {B_UHR_P_EDCA_QSRC_THRESHOLD, 0x0000c000U, 0x00000600U, 0}};
static const uhr_bit_t dbe_bits[] = {
    {B_UHR_DBE_OPER_BANDWIDTH, 0x00000007U, 0x00000007U, 0},
    {B_UHR_DBE_OPER_DIS_SUBCHANNEL_BITMAP_PRES, 0x00000008U, 0x00000008U, 0}};
static const uhr_bit_t dbe_cap_bits[] = {
    {B_UHR_MAC_CAP_DBE_MAX_BW, 0x00000007U, 0x00000007U, 0},
    {B_UHR_MAC_CAP_DBE_EHT_MCS_MAP_160_PRES, 0x00000008U, 0x00000008U, 0},
    {B_UHR_MAC_CAP_DBE_EHT_MCS_MAP_320_PRES, 0x00000010U, 0x00000010U, 0}};
static const uhr_bit_t dbe_bw_bits[] = {
    {B_UHR_MAC_CAP_DBE_CAP_NUM_SND_DIMS, 0x00000007U, 0x00000000U, 0},
    {B_UHR_MAC_CAP_DBE_CAP_NON_OFDMA_UL_MUMIMO, 0x00000008U, 0x00000000U, 0},
    {B_UHR_MAC_CAP_DBE_CAP_MU_BEAMFORMER, 0x00000010U, 0x00000000U, 0},
    {B_UHR_MAC_CAP_DBE_CAP_BEAMFORMEE_SS, 0x000000e0U, 0x00000000U, 0}};
static const uhr_bit_t mac_bits[] = {
    {B_UHR_MAC_CAP0_DPS_SUPP, 0x00000001U, 0x00000001U, 0},
    {B_UHR_MAC_CAP0_DPS_ASSIST_SUPP, 0x00000002U, 0x00000002U, 0},
    {B_UHR_MAC_CAP0_DPS_AP_STATIC_HCM_SUPP, 0x00000004U, 0x00000004U, 0},
    {B_UHR_MAC_CAP0_NPCA_SUPP, 0x00000010U, 0x00000010U, 0},
    {B_UHR_MAC_CAP0_ENH_BSR_SUPP, 0x00000020U, 0x00000020U, 0},
    {B_UHR_MAC_CAP0_ADD_MAP_TID_SUPP, 0x00000040U, 0x00000040U, 0},
    {B_UHR_MAC_CAP0_EOTSP_SUPP, 0x00000080U, 0x00000080U, 0},
    {B_UHR_MAC_CAP1_DSO_SUPP, 0x00000001U, 0x00000001U, 1},
    {B_UHR_MAC_CAP1_PEDCA_SUPP, 0x00000002U, 0x00000002U, 1},
    {B_UHR_MAC_CAP1_DBE_SUPP, 0x00000004U, 0x00000004U, 1},
    {B_UHR_MAC_CAP1_UL_LLI_SUPP, 0x00000008U, 0x00000008U, 1},
    {B_UHR_MAC_CAP1_P2P_LLI_SUPP, 0x00000010U, 0x00000010U, 1},
    {B_UHR_MAC_CAP1_PUO_SUPP, 0x00000020U, 0x00000020U, 1},
    {B_UHR_MAC_CAP1_AP_PUO_SUPP, 0x00000040U, 0x00000040U, 1},
    {B_UHR_MAC_CAP1_DUO_SUPP, 0x00000080U, 0x00000080U, 1},
    {B_UHR_MAC_CAP2_OMC_UL_MU_DIS_RX_SUPP, 0x00000001U, 0x00000001U, 2},
    {B_UHR_MAC_CAP2_AOM_SUPP, 0x00000002U, 0x00000002U, 2},
    {B_UHR_MAC_CAP2_IFCS_LOC_SUPP, 0x00000004U, 0x00000004U, 2},
    {B_UHR_MAC_CAP2_UHR_TRS_SUPP, 0x00000008U, 0x00000008U, 2},
    {B_UHR_MAC_CAP2_TXSPG_SUPP, 0x00000010U, 0x00000010U, 2},
    {B_UHR_MAC_CAP2_TXOP_RET_IN_TXSPG, 0x00000020U, 0x00000020U, 2},
    {B_UHR_MAC_CAP2_UHR_OM_PU_TO_LOW, 0x000000c0U, 0x000000c0U, 2},
    {B_UHR_MAC_CAP3_UHR_OM_PU_TO_HIGH, 0x00000003U, 0x00000003U, 3},
    {B_UHR_MAC_CAP3_PARAM_UPD_ADV_NOTIF_INTV, 0x0000007cU, 0x0000001cU, 3},
    {B_UHR_MAC_CAP3_UPD_IND_TIM_INTV_LOW, 0x00000080U, 0x000000e0U, 3},
    {B_UHR_MAC_CAP4_UPD_IND_TIM_INTV_HIGH, 0x0000000fU, 0x00000003U, 4},
    {B_UHR_MAC_CAP4_BOUNDED_ESS, 0x00000010U, 0x00000004U, 4},
    {B_UHR_MAC_CAP4_BTM_ASSURANCE, 0x00000020U, 0x00000008U, 4},
    {B_UHR_MAC_CAP4_CO_BF_SUPP, 0x00000040U, 0x00000010U, 4},
    {B_UHR_MAC_CAP4_CO_SR_SUPP, 0x00000080U, 0x00000000U, 4},
    {B_UHR_MAC_CAP5_MAPC_ENH_MSRMT_SUPP, 0x00000001U, 0x00000000U, 5}};
static const uhr_bit_t phy_bits[] = {
    {B_UHR_PHY_CAP_MAX_NSS_RX_SND_NDP_LE80, 0x00000001U, 0x00000001U, 0},
    {B_UHR_PHY_CAP_MAX_NSS_RX_DL_MU_LE80, 0x00000002U, 0x00000002U, 0},
    {B_UHR_PHY_CAP_MAX_NSS_RX_SND_NDP_160, 0x00000004U, 0x00000004U, 0},
    {B_UHR_PHY_CAP_MAX_NSS_RX_DL_MU_160, 0x00000008U, 0x00000008U, 0},
    {B_UHR_PHY_CAP_MAX_NSS_RX_SND_NDP_320, 0x00000010U, 0x00000010U, 0},
    {B_UHR_PHY_CAP_MAX_NSS_RX_DL_MU_320, 0x00000020U, 0x00000020U, 0},
    {B_UHR_PHY_CAP_ELR_TX, 0x00000040U, 0x00000040U, 0},
    {B_UHR_PHY_CAP_ELR_RX, 0x00000080U, 0x00000080U, 0},
    {B_UHR_PHY_CAP_PART_BW_DL_MUMIMO, 0x00000100U, 0x00000100U, 0},
    {B_UHR_PHY_CAP_PART_BW_UL_MUMIMO, 0x00000200U, 0x00000200U, 0},
    {B_UHR_PHY_CAP_MCS15, 0x00000400U, 0x00000400U, 0},
    {B_UHR_PHY_CAP_2XLDPC_TX, 0x00000800U, 0x00000800U, 0},
    {B_UHR_PHY_CAP_2XLDPC_RX, 0x00001000U, 0x00001000U, 0},
    {B_UHR_PHY_CAP_UEQM_TX_MAX_NSS, 0x00006000U, 0x00006000U, 0},
    {B_UHR_PHY_CAP_UEQM_RX_MAX_NSS, 0x00018000U, 0x00018000U, 0},
    {B_UHR_PHY_CAP_CO_BF_JOINT_SOUNDING, 0x00040000U, 0x00040000U, 0},
    {B_UHR_PHY_CAP_IM_TX, 0x00080000U, 0x00080000U, 0},
    {B_UHR_PHY_CAP_IM_RX, 0x00100000U, 0x00100000U, 0},
    {B_UHR_PHY_CAP_CO_SR_MODE_1, 0x00200000U, 0x00200000U, 0},
    {B_UHR_PHY_CAP_CO_SR_MODE_2, 0x00400000U, 0x00400000U, 0},
    {B_UHR_PHY_CAP_DRU_DBW_20_IN_PBW_20, 0x00800000U, 0x00800000U, 0},
    {B_UHR_PHY_CAP_DRU_DBW_40_IN_PBW_40, 0x01000000U, 0x01000000U, 0},
    {B_UHR_PHY_CAP_DRU_DBW_80_IN_PBW_80, 0x02000000U, 0x02000000U, 0},
    {B_UHR_PHY_CAP_DRU_DBW_80_IN_PBW_160, 0x04000000U, 0x04000000U, 0},
    {B_UHR_PHY_CAP_DRU_DBW_80_IN_PBW_320, 0x08000000U, 0x08000000U, 0},
    {B_UHR_PHY_CAP_DRU_DBW_20_IN_PBW_GE80, 0x10000000U, 0x10000000U, 0},
    {B_UHR_PHY_CAP_DRU_DBW_40_IN_PBW_GE80, 0x20000000U, 0x20000000U, 0},
    {B_UHR_PHY_CAP_DRU_DBW_60_IN_PBW_GE80, 0x40000000U, 0x40000000U, 0},
    {B_UHR_PHY_CAP_DRU_RRU_HYBRID_MODE, 0x80000000U, 0x80000000U, 0}};
static const uhr_bit_t smd_bits[] = {{B_SMD_INFO_CAPA_DL_DATA_FWD, 0x00000001U, 0x00000001U, 0},
                                     {B_SMD_INFO_CAPA_MAX_NUM_PREP, 0x0000000eU, 0x0000000eU, 0},
                                     {B_SMD_INFO_CAPA_TYPE, 0x00000010U, 0x00000010U, 0},
                                     {B_SMD_INFO_CAPA_PTK_PER_AP_MLD, 0x00000020U, 0x00000020U, 0}};
static int
uhr_end(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int len)
{
    int available = MAX(0, tvb_captured_length_remaining(tvb, offset));
    if (available < len)
        expert_add_info_format(pinfo, tree, &ei_short,
                               "UHR capture truncated: declared %d bytes, captured %d", len,
                               available);
    return offset + MIN(len, available);
}

static bool
need(packet_info *pinfo, proto_tree *tree, int at, int end, int n, const char *name)
{
    if (n <= end - at)
        return true;
    expert_add_info_format(pinfo, tree, &ei_short,
                           "%s needs %d bytes, %d remain in selected reference layout", name, n,
                           MAX(0, end - at));
    return false;
}

static void
raw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int at, int end, const char *why)
{
    if (at < end)
        proto_tree_add_item(tree, hf[TAIL], tvb, at, end - at, ENC_NA);
    if (why)
        expert_add_info_format(pinfo, tree, &ei_raw, "%s", why);
}

static void
selected_layout(tvbuff_t *tvb, proto_tree *tree, int at)
{
    proto_item *item = proto_tree_add_string(tree, hf[LAYOUT], tvb, at, 0,
                                             layout ? "Pre D1.5 public reference 410d70acf9ca"
                                                    : "D1.5 public reference");
    proto_item_set_generated(item);
}

static void
bit(tvbuff_t *tvb, proto_tree *tree, int at, int n, uint32_t value, const uhr_bit_t *b)
{
    uint32_t mask = layout ? b->old_mask : b->mask;
    unsigned shift = 0;
    if (!mask)
        return;
    while (!((mask >> shift) & 1U))
        shift++;
    if (proto_registrar_get_ftype(hf[b->field]) == FT_BOOLEAN)
        proto_tree_add_boolean(tree, hf[b->field], tvb, at, n, !!(value & mask));
    else
        proto_tree_add_uint(tree, hf[b->field], tvb, at, n, (value & mask) >> shift);
}

static void
bits(tvbuff_t *tvb, proto_tree *tree, int at, int n, uint32_t value, const uhr_bit_t *b,
     unsigned count)
{
    for (unsigned i = 0; i < count; i++)
        bit(tvb, tree, at, n, value, &b[i]);
}

void
dissect_uhr_operation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int at, int len)
{
    int end = uhr_end(tvb, pinfo, tree, at, len);
    unsigned shift = layout ? 0 : 1;
    uint16_t control;
    uint32_t params;
    proto_tree *sub =
        proto_tree_add_subtree(tree, tvb, at, end - at, ett_uhr, NULL, "UHR Operation");
    selected_layout(tvb, sub, at);
    if (!need(pinfo, sub, at, end, 2, "UHR Operation Control"))
        goto remaining;
    control = tvb_get_letohs(tvb, at);
    proto_tree_add_item(sub, hf[OP_CONTROL], tvb, at, 2, ENC_LITTLE_ENDIAN);
    bits(tvb, sub, at, 2, control, op_bits, array_length(op_bits));
    at += 2;
    if (layout) {
        if (!need(pinfo, sub, at, end, 4, "Pre D1.5 Basic UHR MCS/NSS Set"))
            goto remaining;
        proto_tree_add_item(sub, hf[BASIC_MCS], tvb, at, 4, ENC_NA);
        at += 4;
    }
    if (control & (layout ? 0xf000 : 0xe000)) {
        raw(tvb, pinfo, sub, at, end, "Unassigned control bits set; optional offsets not assumed");
        return;
    }
    if (control & (0x0080U << shift)) {
        if (layout) {
            raw(tvb, pinfo, sub, at, end, "Pre D1.5 DUO size unknown; later offsets not assumed");
            return;
        }
        if (!need(pinfo, sub, at, end, 1, "DUO Parameters"))
            goto remaining;
        /* D1.5 public Linux NPCA/DBE walkers skip one DUO octet. */
        proto_tree_add_item(sub, hf[DUO], tvb, at++, 1, ENC_NA);
    }
    if (control & (0x0100U << shift)) {
        if (!need(pinfo, sub, at, end, 4, "DPS Parameters"))
            goto remaining;
        proto_tree *dps = proto_tree_add_subtree(sub, tvb, at, 4, ett_parameters, NULL,
                                                 "DPS Operation Parameters");
        params = tvb_get_letohl(tvb, at);
        proto_tree_add_item(dps, hf[DPS_CONTROL], tvb, at, 4, ENC_LITTLE_ENDIAN);
        bits(tvb, dps, at, 4, params, dps_bits, array_length(dps_bits));
        at += 4;
    }
    if (control & (0x0200U << shift)) {
        if (!need(pinfo, sub, at, end, 4, "NPCA Parameters"))
            goto remaining;
        proto_tree *npca = proto_tree_add_subtree(sub, tvb, at, 4, ett_parameters, NULL,
                                                  "NPCA Operation Parameters");
        params = tvb_get_letohl(tvb, at);
        proto_tree_add_item(npca, hf[NPCA_CONTROL], tvb, at, 4, ENC_LITTLE_ENDIAN);
        bits(tvb, npca, at, 4, params, npca_bits, array_length(npca_bits));
        if (layout)
            proto_tree_add_uint(npca, hf[NPCA_OFFSET], tvb, at, 4, params & 0x0f);
        at += 4;
        if (params & (layout ? 0x00800000U : 0x08000000U)) {
            if (!need(pinfo, sub, at, end, 2, "NPCA Disabled Subchannel Bitmap"))
                goto remaining;
            proto_tree_add_item(npca, hf[NPCA_BITMAP], tvb, at, 2, ENC_LITTLE_ENDIAN);
            at += 2;
            proto_item_set_len(proto_tree_get_parent(npca), 6);
        }
    }
    if (control & (0x0400U << shift)) {
        int n = layout ? 3 : 2;
        if (!need(pinfo, sub, at, end, n, "P-EDCA Parameters"))
            goto remaining;
        proto_tree *pedca = proto_tree_add_subtree(sub, tvb, at, n, ett_parameters, NULL,
                                                   "P-EDCA Operation Parameters");
        proto_tree_add_item(pedca, hf[PEDCA_CONTROL], tvb, at, n, ENC_NA);
        for (unsigned i = 0; i < array_length(pedca_bits); i++) {
            bool ecw = i < 2; /* The older layout has ECW in a separate octet. */
            int pos = at + (layout && !ecw ? 1 : 0), size = layout && ecw ? 1 : 2;
            params = size == 1 ? tvb_get_uint8(tvb, pos) : tvb_get_letohs(tvb, pos);
            bit(tvb, pedca, pos, size, params, &pedca_bits[i]);
        }
        at += n;
    }
    if (control & (0x0800U << shift)) {
        if (!need(pinfo, sub, at, end, 1, "DBE Parameters"))
            goto remaining;
        proto_tree *dbe = proto_tree_add_subtree(sub, tvb, at, 1, ett_parameters, NULL,
                                                 "DBE Operation Parameters");
        params = tvb_get_uint8(tvb, at);
        proto_tree_add_item(dbe, hf[DBE_CONTROL], tvb, at, 1, ENC_NA);
        bits(tvb, dbe, at, 1, params, dbe_bits, array_length(dbe_bits));
        at++;
        if (params & 8) {
            if (!need(pinfo, sub, at, end, 2, "DBE Disabled Subchannel Bitmap"))
                goto remaining;
            proto_tree_add_item(dbe, hf[DBE_BITMAP], tvb, at, 2, ENC_LITTLE_ENDIAN);
            at += 2;
            proto_item_set_len(proto_tree_get_parent(dbe), 3);
        }
    }
remaining:
    raw(tvb, pinfo, sub, at, end, at < end ? "Remaining UHR Operation bytes retained raw" : NULL);
}

void
dissect_uhr_capabilities(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int at, int len,
                         bool from_ap)
{
    int end = uhr_end(tvb, pinfo, tree, at, len), start = at;
    uint8_t mac[6];
    proto_tree *sub =
        proto_tree_add_subtree(tree, tvb, at, end - at, ett_uhr, NULL, "UHR Capabilities");
    selected_layout(tvb, sub, at);
    if (!need(pinfo, sub, at, end, 11, "UHR MAC and PHY Capabilities"))
        goto remaining;
    tvb_memcpy(tvb, mac, at, sizeof(mac));
    proto_item *item = proto_tree_add_item(sub, hf[MAC], tvb, at, 6, ENC_NA);
    proto_tree *mt = proto_item_add_subtree(item, ett_parameters);
    for (unsigned i = 0; i < array_length(mac_bits); i++)
        bit(tvb, mt, at + mac_bits[i].byte, 1, mac[mac_bits[i].byte], &mac_bits[i]);
    proto_tree_add_uint(mt, hf[OM_TIMEOUT], tvb, at + 2, 2,
                        ((mac[2] & 0xc0) >> 6) | ((mac[3] & 3) << 2));
    proto_tree_add_uint(mt, hf[TIM_INTERVAL], tvb, at + 3, 2,
                        layout ? ((mac[3] & 0xe0) >> 5) | ((mac[4] & 3) << 3)
                               : ((mac[3] & 0x80) >> 7) | ((mac[4] & 15) << 1));
    at += 6;
    item = proto_tree_add_item(sub, hf[PHY], tvb, at, 5, ENC_NA);
    proto_tree *pt = proto_item_add_subtree(item, ett_parameters);
    bits(tvb, pt, at, 4, tvb_get_letohl(tvb, at), phy_bits, array_length(phy_bits));
    proto_tree_add_item(pt, hf[PHY_RESERVED], tvb, at + 4, 1, ENC_NA);
    at += 5;
    if (from_ap && (mac[1] & 4)) {
        int n = layout ? 1 : 3;
        if (!need(pinfo, sub, at, end, n, "DBE Capability Parameters"))
            goto remaining;
        uint8_t cap = tvb_get_uint8(tvb, at);
        proto_tree *dbe = proto_tree_add_subtree(sub, tvb, at, n, ett_parameters, NULL,
                                                 "DBE Capability Parameters");
        proto_tree_add_item(dbe, hf[DBE_CAP], tvb, at, 1, ENC_NA);
        bits(tvb, dbe, at, 1, cap, dbe_cap_bits, array_length(dbe_cap_bits));
        if (!layout) {
            proto_tree_add_item(dbe, hf[DBE_SWITCH], tvb, at + 1, 1, ENC_NA);
            proto_tree_add_item(dbe, hf[DBE_INTERVAL], tvb, at + 2, 1, ENC_NA);
        }
        at += n;
        for (unsigned i = 0; i < 2; i++) {
            if (!(cap & (8U << i)))
                continue;
            n = layout ? 3 : 4;
            if (!need(pinfo, sub, at, end, n, "DBE Per Bandwidth Capability"))
                goto remaining;
            proto_tree_add_item(dbe, hf[i ? DBE_MCS320 : DBE_MCS160], tvb, at, 3, ENC_NA);
            if (!layout) {
                proto_tree_add_item(dbe, hf[DBE_BWCAP], tvb, at + 3, 1, ENC_NA);
                bits(tvb, dbe, at + 3, 1, tvb_get_uint8(tvb, at + 3), dbe_bw_bits,
                     array_length(dbe_bw_bits));
            }
            at += n;
            proto_item_set_len(proto_tree_get_parent(dbe), at - (start + 11));
        }
    }
remaining:
    raw(tvb, pinfo, sub, at, end, at < end ? "Remaining UHR Capability bytes retained raw" : NULL);
}

void
dissect_uhr_smd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int at, int len)
{
    int end = uhr_end(tvb, pinfo, tree, at, len);
    proto_tree *sub =
        proto_tree_add_subtree(tree, tvb, at, end - at, ett_uhr, NULL, "SMD Information");
    if (need(pinfo, sub, at, end, 9, "SMD Information")) {
        proto_tree_add_item(sub, hf[SMD_ID], tvb, at, 6, ENC_NA);
        proto_tree_add_item(sub, hf[SMD_CAP], tvb, at + 6, 1, ENC_NA);
        bits(tvb, sub, at + 6, 1, tvb_get_uint8(tvb, at + 6), smd_bits, array_length(smd_bits));
        proto_tree_add_item(sub, hf[SMD_TIMEOUT], tvb, at + 7, 2, ENC_LITTLE_ENDIAN);
        at += 9;
    }
    raw(tvb, pinfo, sub, at, end, at < end ? "Remaining SMD bytes retained raw" : NULL);
}

void
dissect_uhr_mode_change(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int at, int len)
{
    int end = uhr_end(tvb, pinfo, tree, at, len);
    proto_tree *sub =
        proto_tree_add_subtree(tree, tvb, at, end - at, ett_uhr, NULL, "UHR Mode Change");
    while (at < end) {
        if (!need(pinfo, sub, at, end, 2, "UHR Mode Change Control"))
            break;
        uint16_t control = tvb_get_letohs(tvb, at);
        int n = (control >> 8) & 15;
        if (!need(pinfo, sub, at, end, n + 2, "UHR Mode Change Tuple"))
            break;
        proto_tree *tuple = proto_tree_add_subtree_format(
            sub, tvb, at, n + 2, ett_parameters, NULL, "%s Mode Change",
            val_to_str_const(control & 63, modes, "Unknown"));
        for (unsigned i = MODE_CONTROL; i <= MODE_SPECIFIC; i++)
            proto_tree_add_item(tuple, hf[i], tvb, at, 2, ENC_LITTLE_ENDIAN);
        at += 2;
        if (n) {
            proto_tree_add_item(tuple, hf[MODE_DATA], tvb, at, n, ENC_NA);
            expert_add_info(pinfo, tuple, &ei_raw);
        }
        at += n;
    }
    raw(tvb, pinfo, sub, at, end, NULL);
}

unsigned
dissect_uhr_action(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int at)
{
    int start = at,
        end = uhr_end(tvb, pinfo, tree, at, MAX(0, tvb_reported_length_remaining(tvb, at)));
    proto_tree *sub =
        proto_tree_add_subtree(tree, tvb, at, end - at, ett_uhr, NULL, "Protected UHR Action");
    at++; /* Category displayed by the normal action dispatcher. */
    if (!need(pinfo, sub, at, end, 1, "Protected UHR Action Code"))
        goto remaining;
    uint8_t action = tvb_get_uint8(tvb, at);
    proto_tree_add_item(sub, hf[ACTION], tvb, at++, 1, ENC_NA);
    if (action > 2)
        goto remaining;
    if (!need(pinfo, sub, at, end, 2, "UHR Dialog Token and Type"))
        goto remaining;
    proto_tree_add_item(sub, hf[ACTION_TOKEN], tvb, at++, 1, ENC_NA);
    uint8_t type = tvb_get_uint8(tvb, at);
    proto_item *item = proto_tree_add_item(sub, hf[ACTION_TYPE], tvb, at++, 1, ENC_NA);
    const char *name = "Unknown";
    if (action <= 1 && type <= 1)
        name = type ? "Seamless Transition Execution" : "Seamless Transition Preparation";
    else if (action == 0 && type == 3)
        name = "Operating Mode Parameter Request";
    else if (action == 2 && type == 2)
        name = "Downlink Drained";
    else if (action == 2 && type == 3)
        name = "Operating Mode Parameter Response";
    proto_item_append_text(item, " (%s)", name);
    if (action == 1) {
        if (!need(pinfo, sub, at, end, 1, "UHR Response Count"))
            goto remaining;
        proto_tree_add_item(sub, hf[ACTION_COUNT], tvb, at++, 1, ENC_NA);
    }
remaining:
    raw(tvb, pinfo, sub, at, end, at < end ? "UHR action variable body retained raw" : NULL);
    return end - start;
}

void
register_uhr_fields(int proto_wlan, module_t *module, expert_module_t *expert)
{
    for (unsigned i = 0; i < FIELD_COUNT; i++)
        hf[i] = -1;
    static hf_register_info fields[] = {
        {&hf[LAYOUT],
         {"Selected UHR reference layout", "wlan.uhr.layout", FT_STRING, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[OP_CONTROL],
         {"UHR Operation Control", "wlan.uhr.operation.control", FT_UINT16, BASE_HEX, NULL, 0, NULL,
          HFILL}},
        {&hf[BASIC_MCS],
         {"Basic UHR MCS/NSS Set before D1.5", "wlan.uhr.operation.basic_mcs_nss", FT_BYTES,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[TAIL],
         {"Undecoded UHR data", "wlan.uhr.undecoded", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[DUO],
         {"DUO Operation Parameters raw", "wlan.uhr.operation.duo", FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[DPS_CONTROL],
         {"DPS Operation Parameters", "wlan.uhr.dps.control", FT_UINT32, BASE_HEX, NULL, 0, NULL,
          HFILL}},
        {&hf[NPCA_CONTROL],
         {"NPCA Operation Parameters", "wlan.uhr.npca.control", FT_UINT32, BASE_HEX, NULL, 0, NULL,
          HFILL}},
        {&hf[NPCA_OFFSET],
         {"NPCA Primary Channel Offset before D1.5", "wlan.uhr.npca.primary_channel_offset",
          FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[NPCA_BITMAP],
         {"NPCA Disabled Subchannel Bitmap", "wlan.uhr.npca.disabled_subchannel_bitmap", FT_UINT16,
          BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf[PEDCA_CONTROL],
         {"P-EDCA Operation Parameters", "wlan.uhr.pedca.control", FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[DBE_CONTROL],
         {"DBE Operation Parameters", "wlan.uhr.dbe.control", FT_UINT8, BASE_HEX, NULL, 0, NULL,
          HFILL}},
        {&hf[DBE_BITMAP],
         {"DBE Disabled Subchannel Bitmap", "wlan.uhr.dbe.disabled_subchannel_bitmap", FT_UINT16,
          BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf[MAC],
         {"UHR MAC Capabilities Information", "wlan.uhr.capabilities.mac", FT_BYTES, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        {&hf[PHY],
         {"UHR PHY Capabilities Information", "wlan.uhr.capabilities.phy", FT_BYTES, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        {&hf[PHY_RESERVED],
         {"UHR PHY Reserved Octet", "wlan.uhr.capabilities.phy.reserved", FT_UINT8, BASE_HEX, NULL,
          0, NULL, HFILL}},
        {&hf[OM_TIMEOUT],
         {"OM Parameter Update Timeout code", "wlan.uhr.capabilities.mac.om_update_timeout_code",
          FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[TIM_INTERVAL],
         {"Update Indication in TIM Interval code",
          "wlan.uhr.capabilities.mac.update_indication_tim_interval_code", FT_UINT32, BASE_DEC,
          NULL, 0, NULL, HFILL}},
        {&hf[DBE_CAP],
         {"DBE Capability Parameters", "wlan.uhr.capabilities.dbe.control", FT_UINT8, BASE_HEX,
          NULL, 0, NULL, HFILL}},
        {&hf[DBE_SWITCH],
         {"DBE Maximum Switch Time Period code", "wlan.uhr.capabilities.dbe.max_switch_time_period",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[DBE_INTERVAL],
         {"DBE Mode Change Interval code", "wlan.uhr.capabilities.dbe.mode_change_interval",
          FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[DBE_MCS160],
         {"DBE EHT MCS/NSS Set for 160 MHz", "wlan.uhr.capabilities.dbe.eht_mcs_nss_160", FT_BYTES,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[DBE_MCS320],
         {"DBE EHT MCS/NSS Set for 320 MHz", "wlan.uhr.capabilities.dbe.eht_mcs_nss_320", FT_BYTES,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[DBE_BWCAP],
         {"DBE Per Bandwidth Capabilities", "wlan.uhr.capabilities.dbe.bandwidth_capabilities",
          FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL}},
        {&hf[SMD_ID], {"SMD ID", "wlan.uhr.smd.id", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[SMD_CAP],
         {"SMD Capabilities", "wlan.uhr.smd.capabilities", FT_UINT8, BASE_HEX, NULL, 0, NULL,
          HFILL}},
        {&hf[SMD_TIMEOUT],
         {"SMD Timeout code", "wlan.uhr.smd.timeout", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[MODE_CONTROL],
         {"Mode Change Control", "wlan.uhr.mode_change.control", FT_UINT16, BASE_HEX, NULL, 0, NULL,
          HFILL}},
        {&hf[MODE_ID],
         {"Mode ID", "wlan.uhr.mode_change.mode_id", FT_UINT16, BASE_DEC, VALS(modes), 0x003f, NULL,
          HFILL}},
        {&hf[MODE_ENABLE],
         {"Mode Enabled", "wlan.uhr.mode_change.enabled", FT_BOOLEAN, 16, NULL, 0x0040, NULL,
          HFILL}},
        {&hf[MODE_UPDATE],
         {"Mode Update", "wlan.uhr.mode_change.update", FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL}},
        {&hf[MODE_LENGTH],
         {"Mode Data Length", "wlan.uhr.mode_change.length", FT_UINT16, BASE_DEC, NULL, 0x0f00,
          NULL, HFILL}},
        {&hf[MODE_SPECIFIC],
         {"Mode Specific Control", "wlan.uhr.mode_change.specific", FT_UINT16, BASE_HEX, NULL,
          0xf000, NULL, HFILL}},
        {&hf[MODE_DATA],
         {"Mode Specific Data raw", "wlan.uhr.mode_change.data", FT_BYTES, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[ACTION],
         {"Protected UHR Action", "wlan.uhr.action", FT_UINT8, BASE_DEC, VALS(actions), 0, NULL,
          HFILL}},
        {&hf[ACTION_TOKEN],
         {"Dialog Token", "wlan.uhr.action.dialog_token", FT_UINT8, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[ACTION_TYPE],
         {"Link Reconfiguration Type", "wlan.uhr.action.type", FT_UINT8, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[ACTION_COUNT],
         {"Response Count", "wlan.uhr.action.count", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_OPER_PARAMS_DPS_ENA],
         {"DPS Enabled", "wlan.uhr.operation.dps_ena", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_OPER_PARAMS_NPCA_ENA],
         {"NPCA Enabled", "wlan.uhr.operation.npca_ena", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_OPER_PARAMS_PEDCA_ENA],
         {"PEDCA Enabled", "wlan.uhr.operation.pedca_ena", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_OPER_PARAMS_DBE_ENA],
         {"DBE Enabled", "wlan.uhr.operation.dbe_ena", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_OPER_PARAMS_DBE_BW],
         {"DBE BW code", "wlan.uhr.operation.dbe_bw", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_OPER_PARAMS_ELR_RX],
         {"ELR RX", "wlan.uhr.operation.elr_rx", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_OPER_PARAMS_DUO_PRES],
         {"DUO Present", "wlan.uhr.operation.duo_pres", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_OPER_PARAMS_DPS_PRES],
         {"DPS Present", "wlan.uhr.operation.dps_pres", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_OPER_PARAMS_NPCA_PRES],
         {"NPCA Present", "wlan.uhr.operation.npca_pres", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_OPER_PARAMS_PEDCA_PRES],
         {"PEDCA Present", "wlan.uhr.operation.pedca_pres", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_OPER_PARAMS_DBE_PRES],
         {"DBE Present", "wlan.uhr.operation.dbe_pres", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_DPS_PADDING_DELAY],
         {"Padding Delay code", "wlan.uhr.dps.padding_delay", FT_UINT32, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_DPS_TRANSITION_DELAY],
         {"Transition Delay code", "wlan.uhr.dps.transition_delay", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_DPS_ICF_REQUIRED],
         {"ICF Required", "wlan.uhr.dps.icf_required", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_DPS_PARAMETERIZED_FLAG],
         {"Parameterized Flag", "wlan.uhr.dps.parameterized_flag", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_DPS_LC_MODE_BW],
         {"LC Mode BW code", "wlan.uhr.dps.lc_mode_bw", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_DPS_LC_MODE_NSS],
         {"LC Mode NSS code", "wlan.uhr.dps.lc_mode_nss", FT_UINT32, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_DPS_LC_MODE_MCS],
         {"LC Mode MCS code", "wlan.uhr.dps.lc_mode_mcs", FT_UINT32, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_DPS_MOBILE_AP_DPS_STATIC_HCM],
         {"Mobile AP DPS Static HCM", "wlan.uhr.dps.mobile_ap_dps_static_hcm", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_NPCA_PARAMS_PRIMARY_CHAN],
         {"Primary Channel code", "wlan.uhr.npca.primary_chan", FT_UINT32, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_NPCA_PARAMS_MIN_DUR_THRESH],
         {"Minimum Duration Threshold code", "wlan.uhr.npca.min_dur_thresh", FT_UINT32, BASE_DEC,
          NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_NPCA_PARAMS_SWITCH_DELAY],
         {"Switch Delay code", "wlan.uhr.npca.switch_delay", FT_UINT32, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_NPCA_PARAMS_SWITCH_BACK_DELAY],
         {"Switch Back Delay code", "wlan.uhr.npca.switch_back_delay", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_NPCA_PARAMS_INIT_QSRC],
         {"Initial QSRC code", "wlan.uhr.npca.init_qsrc", FT_UINT32, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_NPCA_PARAMS_MOPLEN],
         {"MOPLEN", "wlan.uhr.npca.moplen", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_NPCA_PARAMS_DIS_SUBCH_BMAP_PRES],
         {"Disabled Subchannel Bitmap Present", "wlan.uhr.npca.dis_subch_bmap_pres", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_P_EDCA_ECWMIN],
         {"ECWmin code", "wlan.uhr.pedca.ecwmin", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_P_EDCA_ECWMAX],
         {"ECWmax code", "wlan.uhr.pedca.ecwmax", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_P_EDCA_AIFSN],
         {"AIFSN code", "wlan.uhr.pedca.aifsn", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_P_EDCA_CW_DS],
         {"CW DS code", "wlan.uhr.pedca.cw_ds", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_P_EDCA_PSRC_THRESHOLD],
         {"PSRC Threshold code", "wlan.uhr.pedca.psrc_threshold", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_P_EDCA_QSRC_THRESHOLD],
         {"QSRC Threshold code", "wlan.uhr.pedca.qsrc_threshold", FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_DBE_OPER_BANDWIDTH],
         {"Bandwidth code", "wlan.uhr.dbe.bandwidth", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_DBE_OPER_DIS_SUBCHANNEL_BITMAP_PRES],
         {"Disabled Subchannel Bitmap Present", "wlan.uhr.dbe.dis_subchannel_bitmap_pres",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP_DBE_MAX_BW],
         {"Maximum BW code", "wlan.uhr.capabilities.dbe.max_bw", FT_UINT32, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_MAC_CAP_DBE_EHT_MCS_MAP_160_PRES],
         {"EHT MCS MAP 160 Present", "wlan.uhr.capabilities.dbe.eht_mcs_map_160_pres", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP_DBE_EHT_MCS_MAP_320_PRES],
         {"EHT MCS MAP 320 Present", "wlan.uhr.capabilities.dbe.eht_mcs_map_320_pres", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP_DBE_CAP_NUM_SND_DIMS],
         {"Capability Number Sounding Dimensions code",
          "wlan.uhr.capabilities.dbe.cap_num_snd_dims", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP_DBE_CAP_NON_OFDMA_UL_MUMIMO],
         {"Capability NON OFDMA UL MUMIMO", "wlan.uhr.capabilities.dbe.cap_non_ofdma_ul_mumimo",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP_DBE_CAP_MU_BEAMFORMER],
         {"Capability MU Beamformer", "wlan.uhr.capabilities.dbe.cap_mu_beamformer", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP_DBE_CAP_BEAMFORMEE_SS],
         {"Capability Beamformee SS code", "wlan.uhr.capabilities.dbe.cap_beamformee_ss", FT_UINT32,
          BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP0_DPS_SUPP],
         {"DPS Supported", "wlan.uhr.capabilities.mac.dps_supp", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP0_DPS_ASSIST_SUPP],
         {"DPS Assist Supported", "wlan.uhr.capabilities.mac.dps_assist_supp", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP0_DPS_AP_STATIC_HCM_SUPP],
         {"DPS AP Static HCM Supported", "wlan.uhr.capabilities.mac.dps_ap_static_hcm_supp",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP0_NPCA_SUPP],
         {"NPCA Supported", "wlan.uhr.capabilities.mac.npca_supp", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP0_ENH_BSR_SUPP],
         {"Enhanced BSR Supported", "wlan.uhr.capabilities.mac.enh_bsr_supp", FT_BOOLEAN, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP0_ADD_MAP_TID_SUPP],
         {"Additional MAP TID Supported", "wlan.uhr.capabilities.mac.add_map_tid_supp", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP0_EOTSP_SUPP],
         {"EOTSP Supported", "wlan.uhr.capabilities.mac.eotsp_supp", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP1_DSO_SUPP],
         {"DSO Supported", "wlan.uhr.capabilities.mac.dso_supp", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP1_PEDCA_SUPP],
         {"PEDCA Supported", "wlan.uhr.capabilities.mac.pedca_supp", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP1_DBE_SUPP],
         {"DBE Supported", "wlan.uhr.capabilities.mac.dbe_supp", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP1_UL_LLI_SUPP],
         {"UL LLI Supported", "wlan.uhr.capabilities.mac.ul_lli_supp", FT_BOOLEAN, BASE_NONE, NULL,
          0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP1_P2P_LLI_SUPP],
         {"P2P LLI Supported", "wlan.uhr.capabilities.mac.p2p_lli_supp", FT_BOOLEAN, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP1_PUO_SUPP],
         {"PUO Supported", "wlan.uhr.capabilities.mac.puo_supp", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP1_AP_PUO_SUPP],
         {"AP PUO Supported", "wlan.uhr.capabilities.mac.ap_puo_supp", FT_BOOLEAN, BASE_NONE, NULL,
          0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP1_DUO_SUPP],
         {"DUO Supported", "wlan.uhr.capabilities.mac.duo_supp", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP2_OMC_UL_MU_DIS_RX_SUPP],
         {"OMC UL MU Disabled RX Supported", "wlan.uhr.capabilities.mac.omc_ul_mu_dis_rx_supp",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP2_AOM_SUPP],
         {"AOM Supported", "wlan.uhr.capabilities.mac.aom_supp", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP2_IFCS_LOC_SUPP],
         {"IFCS LOC Supported", "wlan.uhr.capabilities.mac.ifcs_loc_supp", FT_BOOLEAN, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP2_UHR_TRS_SUPP],
         {"UHR TRS Supported", "wlan.uhr.capabilities.mac.uhr_trs_supp", FT_BOOLEAN, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP2_TXSPG_SUPP],
         {"TXSPG Supported", "wlan.uhr.capabilities.mac.txspg_supp", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP2_TXOP_RET_IN_TXSPG],
         {"TXOP Return in TXSPG", "wlan.uhr.capabilities.mac.txop_ret_in_txspg", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP2_UHR_OM_PU_TO_LOW],
         {"UHR OM PU Timeout Low code", "wlan.uhr.capabilities.mac.uhr_om_pu_to_low", FT_UINT32,
          BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP3_UHR_OM_PU_TO_HIGH],
         {"UHR OM PU Timeout High code", "wlan.uhr.capabilities.mac.uhr_om_pu_to_high", FT_UINT32,
          BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP3_PARAM_UPD_ADV_NOTIF_INTV],
         {"Parameter Update Advance Notification Interval code",
          "wlan.uhr.capabilities.mac.param_upd_adv_notif_intv", FT_UINT32, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_MAC_CAP3_UPD_IND_TIM_INTV_LOW],
         {"Update Indication TIM Interval Low", "wlan.uhr.capabilities.mac.upd_ind_tim_intv_low",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP4_UPD_IND_TIM_INTV_HIGH],
         {"Update Indication TIM Interval High code",
          "wlan.uhr.capabilities.mac.upd_ind_tim_intv_high", FT_UINT32, BASE_DEC, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_MAC_CAP4_BOUNDED_ESS],
         {"Bounded ESS", "wlan.uhr.capabilities.mac.bounded_ess", FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP4_BTM_ASSURANCE],
         {"BTM Assurance", "wlan.uhr.capabilities.mac.btm_assurance", FT_BOOLEAN, BASE_NONE, NULL,
          0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP4_CO_BF_SUPP],
         {"Coordinated BF Supported", "wlan.uhr.capabilities.mac.co_bf_supp", FT_BOOLEAN, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP4_CO_SR_SUPP],
         {"Coordinated SR Supported", "wlan.uhr.capabilities.mac.co_sr_supp", FT_BOOLEAN, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_MAC_CAP5_MAPC_ENH_MSRMT_SUPP],
         {"MAPC Enhanced Measurement Supported", "wlan.uhr.capabilities.mac.mapc_enh_msrmt_supp",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_MAX_NSS_RX_SND_NDP_LE80],
         {"Maximum NSS RX Sounding NDP <=80", "wlan.uhr.capabilities.phy.max_nss_rx_snd_ndp_le80",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_MAX_NSS_RX_DL_MU_LE80],
         {"Maximum NSS RX DL MU <=80", "wlan.uhr.capabilities.phy.max_nss_rx_dl_mu_le80",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_MAX_NSS_RX_SND_NDP_160],
         {"Maximum NSS RX Sounding NDP 160", "wlan.uhr.capabilities.phy.max_nss_rx_snd_ndp_160",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_MAX_NSS_RX_DL_MU_160],
         {"Maximum NSS RX DL MU 160", "wlan.uhr.capabilities.phy.max_nss_rx_dl_mu_160", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_MAX_NSS_RX_SND_NDP_320],
         {"Maximum NSS RX Sounding NDP 320", "wlan.uhr.capabilities.phy.max_nss_rx_snd_ndp_320",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_MAX_NSS_RX_DL_MU_320],
         {"Maximum NSS RX DL MU 320", "wlan.uhr.capabilities.phy.max_nss_rx_dl_mu_320", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_ELR_TX],
         {"ELR TX", "wlan.uhr.capabilities.phy.elr_tx", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_PHY_CAP_ELR_RX],
         {"ELR RX", "wlan.uhr.capabilities.phy.elr_rx", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_PHY_CAP_PART_BW_DL_MUMIMO],
         {"Partial BW DL MUMIMO", "wlan.uhr.capabilities.phy.part_bw_dl_mumimo", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_PART_BW_UL_MUMIMO],
         {"Partial BW UL MUMIMO", "wlan.uhr.capabilities.phy.part_bw_ul_mumimo", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_MCS15],
         {"MCS15", "wlan.uhr.capabilities.phy.mcs15", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_2XLDPC_TX],
         {"2XLDPC TX", "wlan.uhr.capabilities.phy.2xldpc_tx", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_PHY_CAP_2XLDPC_RX],
         {"2XLDPC RX", "wlan.uhr.capabilities.phy.2xldpc_rx", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_UHR_PHY_CAP_UEQM_TX_MAX_NSS],
         {"UEQM TX Maximum NSS code", "wlan.uhr.capabilities.phy.ueqm_tx_max_nss", FT_UINT32,
          BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_UEQM_RX_MAX_NSS],
         {"UEQM RX Maximum NSS code", "wlan.uhr.capabilities.phy.ueqm_rx_max_nss", FT_UINT32,
          BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_CO_BF_JOINT_SOUNDING],
         {"Coordinated BF Joint Sounding", "wlan.uhr.capabilities.phy.co_bf_joint_sounding",
          FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_IM_TX],
         {"IM TX", "wlan.uhr.capabilities.phy.im_tx", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_IM_RX],
         {"IM RX", "wlan.uhr.capabilities.phy.im_rx", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_CO_SR_MODE_1],
         {"Coordinated SR Mode 1", "wlan.uhr.capabilities.phy.co_sr_mode_1", FT_BOOLEAN, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_CO_SR_MODE_2],
         {"Coordinated SR Mode 2", "wlan.uhr.capabilities.phy.co_sr_mode_2", FT_BOOLEAN, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_DRU_DBW_20_IN_PBW_20],
         {"DRU DBW 20 in PBW 20", "wlan.uhr.capabilities.phy.dru_dbw_20_in_pbw_20", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_DRU_DBW_40_IN_PBW_40],
         {"DRU DBW 40 in PBW 40", "wlan.uhr.capabilities.phy.dru_dbw_40_in_pbw_40", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_DRU_DBW_80_IN_PBW_80],
         {"DRU DBW 80 in PBW 80", "wlan.uhr.capabilities.phy.dru_dbw_80_in_pbw_80", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_DRU_DBW_80_IN_PBW_160],
         {"DRU DBW 80 in PBW 160", "wlan.uhr.capabilities.phy.dru_dbw_80_in_pbw_160", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_DRU_DBW_80_IN_PBW_320],
         {"DRU DBW 80 in PBW 320", "wlan.uhr.capabilities.phy.dru_dbw_80_in_pbw_320", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_DRU_DBW_20_IN_PBW_GE80],
         {"DRU DBW 20 in PBW >=80", "wlan.uhr.capabilities.phy.dru_dbw_20_in_pbw_ge80", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_DRU_DBW_40_IN_PBW_GE80],
         {"DRU DBW 40 in PBW >=80", "wlan.uhr.capabilities.phy.dru_dbw_40_in_pbw_ge80", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_DRU_DBW_60_IN_PBW_GE80],
         {"DRU DBW 60 in PBW >=80", "wlan.uhr.capabilities.phy.dru_dbw_60_in_pbw_ge80", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_UHR_PHY_CAP_DRU_RRU_HYBRID_MODE],
         {"DRU RRU Hybrid Mode", "wlan.uhr.capabilities.phy.dru_rru_hybrid_mode", FT_BOOLEAN,
          BASE_NONE, NULL, 0, NULL, HFILL}},
        {&hf[B_SMD_INFO_CAPA_DL_DATA_FWD],
         {"DL Data Forwarding", "wlan.uhr.smd.dl_data_fwd", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
        {&hf[B_SMD_INFO_CAPA_MAX_NUM_PREP],
         {"Maximum Number Preparations code", "wlan.uhr.smd.max_num_prep", FT_UINT32, BASE_DEC,
          NULL, 0, NULL, HFILL}},
        {&hf[B_SMD_INFO_CAPA_TYPE],
         {"Type code", "wlan.uhr.smd.type", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        {&hf[B_SMD_INFO_CAPA_PTK_PER_AP_MLD],
         {"PTK per AP MLD", "wlan.uhr.smd.ptk_per_ap_mld", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL,
          HFILL}},
    };
    static int *ett[] = {&ett_uhr, &ett_parameters};
    static ei_register_info ei[] = {{&ei_short,
                                     {"wlan.uhr.truncated", PI_MALFORMED, PI_WARN,
                                      "UHR truncated for selected reference layout", EXPFILL}},
                                    {&ei_raw,
                                     {"wlan.uhr.undecoded_data", PI_UNDECODED, PI_NOTE,
                                      "UHR data retained without interpretation", EXPFILL}}};
    proto_register_field_array(proto_wlan, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_register_field_array(expert, ei, array_length(ei));
    prefs_register_enum_preference(
        module, "uhr_layout", "UHR reference layout",
        "Select the public reference matching the firmware. This does not detect the draft. "
        "D1.5 removed Basic UHR MCS/NSS and changed Operation, NPCA, P-EDCA and DBE packing.",
        &layout, layouts, false);
}
