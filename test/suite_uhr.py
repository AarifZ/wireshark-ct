# Copyright 2026 Mohammad Aarif
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic UHR vectors from public reference layouts; no private captures."""
import random
import struct
import subprocess

import pytest


def ie(extension, body):
    return bytes((255, len(body) + 1, extension)) + body


def management(ies, subtype=0x80):
    ap = bytes.fromhex('020000000001')
    sta = bytes.fromhex('020000000002')
    header = struct.pack('<HH', subtype, 0) + sta + ap + ap + b'\0\0'
    if subtype in (0x80, 0x50):
        fixed = struct.pack('<QHH', 0, 100, 1)
    elif subtype in (0x10, 0x30):
        fixed = struct.pack('<HHH', 1, 0, 0xc001)
    elif subtype == 0:
        fixed = struct.pack('<HH', 1, 10)
    else:
        fixed = b''
    return header + fixed + b'\x00\x07UHRTest\x01\x01\x82' + ies


@pytest.fixture
def decode(cmd_tshark, tmp_path, test_env):
    def run(ies, fields, layout='d1_5', subtype=0x80, frames=None):
        packets = frames if frames is not None else [management(ies, subtype)]
        path = tmp_path / 'uhr.pcap'
        with path.open('wb') as out:
            out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105))
            for i, packet in enumerate(packets):
                out.write(struct.pack('<IIII', i + 1, 0, len(packet), len(packet)))
                out.write(packet)
        args = [cmd_tshark, '-n', '-r', str(path), '-o', 'wlan.uhr_layout:' + layout,
                '-Tfields', '-E', 'separator=|']
        for field in fields:
            args.extend(('-e', field))
        result = subprocess.run(args, capture_output=True, text=True, env=test_env,
                                check=True, timeout=30)
        assert 'Dissector bug' not in result.stderr
        # TShark versions can render Boolean fields as True/False or 1/0.
        def normalize(cell):
            return ','.join({'True': '1', 'False': '0'}.get(v, v)
                            for v in cell.split(','))
        return [[normalize(cell) for cell in line.split('|')]
                for line in result.stdout.splitlines()]
    return run


@pytest.mark.parametrize('control,enabled', [(0, '0'), (2, '1'), (0x80, '0')])
def test_control_only_operation(decode, control, enabled):
    row = decode(ie(151, struct.pack('<H', control)), [
        'wlan.uhr.operation.npca_ena', 'wlan.uhr.truncated', '_ws.expert.message'])[0]
    assert row[0] == enabled
    assert not row[1]
    assert 'code not implemented' not in row[2]


def test_explicit_legacy_selection(decode):
    body = bytes.fromhex('020011223344')
    row = decode(ie(151, body), ['wlan.uhr.operation.basic_mcs_nss',
        'wlan.uhr.truncated'], layout='pre_d1_5')[0]
    assert row[0].replace(':', '') == '11223344'
    assert not row[1]
    assert decode(ie(151, b'\0\0'), ['wlan.uhr.truncated'], layout='pre_d1_5')[0][0]
    assert not decode(ie(151, body), ['wlan.uhr.operation.basic_mcs_nss'])[0][0]


@pytest.mark.parametrize('layout', ['d1_5', 'pre_d1_5'])
def test_npca_parameters_and_bitmap(decode, layout):
    if layout == 'd1_5':
        control = 0x0402
        params = 44 | (5 << 8) | (7 << 12) | (9 << 18) | (2 << 24) | (1 << 27)
        basic, primary, expected = b'', 'primary_chan', '44'
    else:
        control = 0x0202
        params = 3 | (5 << 4) | (7 << 8) | (9 << 14) | (2 << 20) | (1 << 23)
        basic, primary, expected = b'\0' * 4, 'primary_channel_offset', '3'
    row = decode(ie(151, struct.pack('<H', control) + basic + struct.pack('<IH', params, 0xa5)), [
        'wlan.uhr.npca.' + primary, 'wlan.uhr.npca.min_dur_thresh',
        'wlan.uhr.npca.switch_delay', 'wlan.uhr.npca.switch_back_delay',
        'wlan.uhr.npca.init_qsrc', 'wlan.uhr.npca.disabled_subchannel_bitmap',
        'wlan.uhr.truncated'], layout=layout)[0]
    assert row[:5] == [expected, '5', '7', '9', '2']
    assert int(row[5], 16) == 0xa5 and not row[6]


def test_presence_independent_of_enable(decode):
    row = decode(ie(151, struct.pack('<HI', 0x0400, 53)), [
        'wlan.uhr.operation.npca_ena', 'wlan.uhr.operation.npca_pres',
        'wlan.uhr.npca.primary_chan'])[0]
    assert row == ['0', '1', '53']


@pytest.mark.parametrize('layout', ['d1_5', 'pre_d1_5'])
def test_pedca_layouts(decode, layout):
    if layout == 'd1_5':
        body = struct.pack('<HH', 0x0804, 2 | (4 << 3) | (3 << 6) | (1 << 9) | (2 << 11) | (1 << 14))
    else:
        body = struct.pack('<H', 0x0404) + b'\0' * 4 + b'\x42' + struct.pack('<H', 3 | (1 << 4) | (2 << 6) | (1 << 9))
    row = decode(ie(151, body), ['wlan.uhr.pedca.' + s for s in
        ['ecwmin', 'ecwmax', 'aifsn', 'cw_ds', 'psrc_threshold', 'qsrc_threshold']] +
        ['wlan.uhr.truncated'], layout=layout)[0]
    assert row == ['2', '4', '3', '1', '2', '1', '']


def test_combined_optional_alignment(decode):
    body = struct.pack('<H', 0x1f0f) + b'\xa0' + struct.pack('<I', 3 | (4 << 8))
    body += struct.pack('<IH', 53 | (1 << 27), 4) + struct.pack('<H', 2 | (3 << 3))
    body += struct.pack('<BH', 0x0a, 0x20)
    row = decode(ie(151, body), ['wlan.uhr.dps.padding_delay', 'wlan.uhr.dps.transition_delay',
        'wlan.uhr.npca.primary_chan', 'wlan.uhr.pedca.ecwmin', 'wlan.uhr.dbe.bandwidth',
        'wlan.uhr.dbe.disabled_subchannel_bitmap', 'wlan.uhr.truncated'])[0]
    assert row[:5] == ['3', '4', '53', '2', '2']
    assert int(row[5], 16) == 0x20 and not row[6]


def test_legacy_duo_stops_optional_offsets(decode):
    row = decode(ie(151, struct.pack('<H', 0x0282) + b'\0' * 10), [
        'wlan.uhr.undecoded', 'wlan.uhr.npca.primary_channel_offset',
        'wlan.uhr.undecoded_data'], layout='pre_d1_5')[0]
    assert row[0] and not row[1] and row[2]


@pytest.mark.parametrize('subtype', [0x80, 0x50, 0x10, 0x30, 0x00, 0x40])
def test_capabilities_management_subtypes(decode, subtype):
    row = decode(ie(152, bytes.fromhex('110000000000') + struct.pack('<IB', 0x18c0, 0)), [
        'wlan.uhr.capabilities.mac.npca_supp', 'wlan.uhr.capabilities.mac.dps_supp',
        'wlan.uhr.capabilities.phy.elr_rx', 'wlan.uhr.truncated'], subtype=subtype)[0]
    assert row == ['1', '1', '1', '']


@pytest.mark.parametrize('layout', ['d1_5', 'pre_d1_5'])
def test_dbe_capability_maps(decode, layout):
    body = bytes.fromhex('000400000000') + b'\0' * 5
    body += bytes.fromhex('1b0709112233e544556610' if layout == 'd1_5' else '1b112233445566')
    row = decode(ie(152, body), ['wlan.uhr.capabilities.dbe.eht_mcs_nss_160',
        'wlan.uhr.capabilities.dbe.eht_mcs_nss_320', 'wlan.uhr.truncated'], layout=layout)[0]
    assert row[0].replace(':', '') == '112233'
    assert row[1].replace(':', '') == '445566' and not row[2]


def test_non_ap_dbe_support_has_no_ap_tail(decode):
    row = decode(ie(152, bytes.fromhex('000400000000') + b'\0' * 5), [
        'wlan.uhr.capabilities.mac.dbe_supp', 'wlan.uhr.truncated',
        'wlan.uhr.capabilities.dbe.control'], subtype=0)[0]
    assert row == ['1', '', '']


@pytest.mark.parametrize('layout,byte4,expected', [
    ('d1_5', 0x10, '1'), ('d1_5', 4, '0'),
    ('pre_d1_5', 4, '1'), ('pre_d1_5', 0x10, '0')])
def test_draft_specific_mac_masks(decode, layout, byte4, expected):
    assert decode(ie(152, bytes((0, 0, 0, 0, byte4, 0)) + b'\0' * 5), [
        'wlan.uhr.capabilities.mac.bounded_ess'], layout=layout)[0] == [expected]


@pytest.mark.parametrize('extension,body', [
    (151, b''), (151, b'\x02'), (151, struct.pack('<H', 0x0200) + b'\0' * 3),
    (151, struct.pack('<HI', 0x0400, 1 << 27) + b'\0'),
    (151, struct.pack('<H', 0x0800) + b'\0'),
    (151, struct.pack('<HB', 0x1000, 8) + b'\0'), (152, b'\0' * 10),
    (152, bytes.fromhex('000400000000') + b'\0' * 7),
    (154, b'\0' * 8), (157, b'\x01'), (157, struct.pack('<H', 0x0f01) + b'\0' * 3)])
def test_short_elements(decode, extension, body):
    assert decode(ie(extension, body), ['wlan.uhr.truncated'])[0][0]


def test_element_boundary_and_repeated_elements(decode):
    body = ie(151, struct.pack('<H', 0x0402)) + ie(152, b'\x10' + b'\0' * 10)
    row = decode(body, ['wlan.uhr.truncated', 'wlan.uhr.capabilities.mac.npca_supp'])[0]
    assert row[0] and row[1] == '1'
    row = decode(ie(151, b'\0\0') + ie(151, b'\2\0'), ['wlan.uhr.operation.npca_ena'])[0]
    assert row == ['0,1']


def test_smd_information(decode):
    row = decode(ie(154, bytes.fromhex('020000000003') + struct.pack('<BH', 0x37, 1234)), [
        'wlan.uhr.smd.id', 'wlan.uhr.smd.dl_data_fwd', 'wlan.uhr.smd.max_num_prep',
        'wlan.uhr.smd.type', 'wlan.uhr.smd.ptk_per_ap_mld', 'wlan.uhr.smd.timeout',
        'wlan.uhr.truncated'])[0]
    assert row[0].replace(':', '') == '020000000003'
    assert row[1:] == ['1', '3', '1', '1', '1234', '']


def test_mode_change_tuples(decode):
    body = struct.pack('<H', 0xa241) + b'\x12\x34' + struct.pack('<H', 0x008b)
    row = decode(ie(157, body), ['wlan.uhr.mode_change.' + s for s in
        ['mode_id', 'enabled', 'update', 'length', 'data']] + ['wlan.uhr.truncated'])[0]
    assert row[:4] == ['1,11', '1,0', '0,1', '2,0']
    assert row[4].replace(':', '') == '1234' and not row[5]


@pytest.mark.parametrize('action,type_code', [(0, 0), (0, 3), (1, 1), (2, 2), (2, 3)])
def test_action_headers(decode, action, type_code):
    header = b'\xd0\0' + management(b'')[2:24]
    body = bytes((43, action, 7, type_code)) + (b'\2' if action == 1 else b'')
    row = decode(b'', ['wlan.uhr.action', 'wlan.uhr.action.dialog_token',
        'wlan.uhr.action.type', 'wlan.uhr.action.count', 'wlan.uhr.truncated'],
        frames=[header + body + b'\xaa\xbb'])[0]
    assert row[:3] == [str(action), '7', str(type_code)]
    assert row[3] == ('2' if action == 1 else '') and not row[4]


@pytest.mark.parametrize('body', [b'\x2b', b'\x2b\0', b'\x2b\1\7\1'])
def test_short_action_headers(decode, body):
    header = b'\xd0\0' + management(b'')[2:24]
    assert decode(b'', ['wlan.uhr.truncated'], frames=[header + body])[0][0]


def test_reserved_control_preserves_tail(decode):
    row = decode(ie(151, struct.pack('<H', 0x2402) + b'\xaa' * 6), [
        'wlan.uhr.undecoded', 'wlan.uhr.npca.primary_chan', 'wlan.uhr.undecoded_data'])[0]
    assert row[0] and not row[1] and row[2]


@pytest.mark.parametrize('layout', ['d1_5', 'pre_d1_5'])
def test_deterministic_mutations(decode, layout):
    rng = random.Random(80211)
    frames = [management(ie(ext, bytes(rng.randrange(256) for _ in range(rng.randrange(40)))))
              for ext in [151, 152, 154, 157] for _ in range(64)]
    rows = decode(b'', ['frame.number', '_ws.expert.message'], layout=layout, frames=frames)
    assert len(rows) == 256
    assert all('Dissector bug' not in row[1] for row in rows)
