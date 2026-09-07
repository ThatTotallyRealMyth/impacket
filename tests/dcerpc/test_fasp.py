# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest

import pytest

from impacket.dcerpc.v5 import fasp
from impacket.dcerpc.v5.ndr import NDRUNION, NDRUniConformantVaryingArray
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from tests.dcerpc import DCERPCTests


class FASPNDRTests(unittest.TestCase):
    def test_v1_enums_are_32_bits(self):
        values = (
            (fasp.FW_PROFILE_TYPE, fasp.FW_PROFILE_TYPE.FW_PROFILE_TYPE_CURRENT),
            (fasp.FW_RULE_STATUS, fasp.FW_RULE_STATUS.FW_RULE_STATUS_OK),
            (fasp.FW_RULE_CATEGORY, fasp.FW_RULE_CATEGORY.FW_RULE_CATEGORY_FIREWALL),
        )

        for enum_type, value in values:
            for is_ndr64 in (False, True):
                enum = enum_type(isNDR64=is_ndr64)
                enum['Data'] = value
                self.assertEqual(len(enum.getData()), 4)

    def test_open_policy_store_round_trip(self):
        for is_ndr64 in (False, True):
            request = fasp.FWOpenPolicyStore(isNDR64=is_ndr64)
            request['BinaryVersion'] = fasp.FW_CURRENT_BINARY_VERSION
            request['StoreType'] = fasp.FW_STORE_TYPE.FW_STORE_TYPE_LOCAL
            request['AccessRight'] = fasp.FW_POLICY_ACCESS_RIGHT.FW_POLICY_ACCESS_RIGHT_READ
            request['dwFlags'] = fasp.FW_POLICY_STORE_FLAGS.FW_POLICY_STORE_FLAGS_NONE

            encoded = request.getData()
            decoded = fasp.FWOpenPolicyStore(encoded, isNDR64=is_ndr64)

            self.assertEqual(decoded.getData(), encoded)
            self.assertEqual(decoded['BinaryVersion'], fasp.FW_CURRENT_BINARY_VERSION)
            self.assertEqual(decoded['StoreType'], fasp.FW_STORE_TYPE.FW_STORE_TYPE_LOCAL)

    def test_get_config_uses_an_in_out_conformant_varying_buffer(self):
        for call_type in (
            fasp.FWGetGlobalConfig,
            fasp.FWGetGlobalConfigResponse,
            fasp.FWGetConfig,
            fasp.FWGetConfigResponse,
            fasp.FWGetGlobalConfig2_10,
            fasp.FWGetGlobalConfig2_10Response,
            fasp.FWGetConfig2_10,
            fasp.FWGetConfig2_10Response,
        ):
            fields = dict(call_type.structure)
            self.assertIs(fields['pBuffer'], fasp.PBYTE_ARRAY_CV)
            self.assertTrue(issubclass(fasp.BYTE_ARRAY_CV, NDRUniConformantVaryingArray))

    def test_enum_union_discriminants_use_the_ndr_enum_width(self):
        for union_type in (
            fasp.FW_AUTH_SUITE2_10_UNION,
            fasp.FW_AUTH_SUITE_UNION,
            fasp.FW_CRYPTO_SET_UNION,
            fasp.FW_AUTH_INFO_UNION,
        ):
            self.assertEqual(union_type.commonHdr, NDRUNION.commonHdr)
            self.assertEqual(union_type.commonHdr64, NDRUNION.commonHdr64)

    def test_enumeration_results_are_linked_lists(self):
        linked_results = (
            (fasp.FWEnumFirewallRulesResponse, 'ppRules', fasp.PPFW_RULE2_0),
            (fasp.FWEnumConnectionSecurityRulesResponse, 'ppRules', fasp.PPFW_CS_RULE2_0),
            (fasp.FWEnumAuthenticationSetsResponse, 'ppAuth', fasp.PPFW_AUTH_SET2_10),
            (fasp.FWEnumCryptoSetsResponse, 'ppCryptoSets', fasp.PPFW_CRYPTO_SET),
            (fasp.FWEnumMainModeRulesResponse, 'ppMMRules', fasp.PPFW_MM_RULE),
            (fasp.FWEnumFirewallRules2_33Response, 'ppRules', fasp.PPFW_RULE),
        )

        for response_type, field_name, pointer_type in linked_results:
            self.assertIs(dict(response_type.structure)[field_name], pointer_type)

        self.assertIs(dict(fasp.FW_RULE2_0.structure)['pNext'], fasp.PFW_RULE2_0)
        self.assertIs(dict(fasp.FW_CS_RULE.structure)['pNext'], fasp.PFW_CS_RULE)
        self.assertIs(dict(fasp.FW_AUTH_SET.structure)['pNext'], fasp.PFW_AUTH_SET)
        self.assertIs(dict(fasp.FW_CRYPTO_SET.structure)['pNext'], fasp.PFW_CRYPTO_SET)
        self.assertIs(dict(fasp.FW_MM_RULE.structure)['pNext'], fasp.PFW_MM_RULE)

        request = fasp.FWAddFirewallRule()
        rule = request.fields['pRule'].fields['Data']
        self.assertEqual(rule.fields['pNext']['ReferentID'], 0)

        encoded_pointer = b'\x01\x00\x00\x00'
        decoded_pointer = fasp.PFW_RULE2_0(encoded_pointer)
        self.assertIsInstance(decoded_pointer.fields['Data'], fasp.FW_RULE2_0)

    def test_size_is_results_are_arrays_of_pointers(self):
        self.assertIs(fasp.FW_NETWORK_ARRAY.item, fasp.PFW_NETWORK)
        self.assertIs(fasp.FW_ADAPTER_ARRAY.item, fasp.PFW_ADAPTER)
        self.assertIs(fasp.FW_PRODUCT_ARRAY.item, fasp.PFW_PRODUCT)
        self.assertIs(fasp.FW_PHASE1_SA_DETAILS_ARRAY.item, fasp.PFW_PHASE1_SA_DETAILS)
        self.assertIs(fasp.FW_PHASE2_SA_DETAILS_ARRAY.item, fasp.PFW_PHASE2_SA_DETAILS)

    def test_current_opnums_match_ms_fasp(self):
        self.assertNotIn(90, fasp.OPNUMS)
        self.assertIs(fasp.OPNUMS[91][0], fasp.FWAddFirewallRule2_33)
        self.assertIs(fasp.OPNUMS[92][0], fasp.FWSetFirewallRule2_33)
        self.assertIs(fasp.OPNUMS[93][0], fasp.FWEnumFirewallRules2_33)
        self.assertIs(fasp.OPNUMS[94][0], fasp.FWQueryFirewallRules2_33)

    def test_all_registered_calls_can_be_constructed(self):
        for request_type, response_type in fasp.OPNUMS.values():
            for is_ndr64 in (False, True):
                request_type(isNDR64=is_ndr64)
                response_type(isNDR64=is_ndr64)


class FASPTests(DCERPCTests):
    iface_uuid = fasp.MSRPC_UUID_FASP
    protocol = 'ncacn_ip_tcp'
    string_binding_formatting = DCERPCTests.STRING_BINDING_MAPPER
    authn = True
    authn_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY

    def test_FWOpenPolicyStore(self):
        dce, _ = self.connect()
        request = fasp.FWOpenPolicyStore()
        request['BinaryVersion'] = fasp.FW_BINARY_VERSION_2_0
        request['StoreType'] = fasp.FW_STORE_TYPE.FW_STORE_TYPE_LOCAL
        request['AccessRight'] = fasp.FW_POLICY_ACCESS_RIGHT.FW_POLICY_ACCESS_RIGHT_READ
        request['dwFlags'] = fasp.FW_POLICY_STORE_FLAGS.FW_POLICY_STORE_FLAGS_NONE
        response = dce.request(request)
        response.dump()

    def test_hFWOpenPolicyStore(self):
        dce, _ = self.connect()
        response = fasp.hFWOpenPolicyStore(dce)
        response.dump()

    def test_FWClosePolicyStore(self):
        dce, _ = self.connect()
        response = fasp.hFWOpenPolicyStore(dce)
        request = fasp.FWClosePolicyStore()
        request['phPolicyStore'] = response['phPolicyStore']
        response = dce.request(request)
        response.dump()

    def test_hFWClosePolicyStore(self):
        dce, _ = self.connect()
        response = fasp.hFWOpenPolicyStore(dce)
        response = fasp.hFWClosePolicyStore(dce, response['phPolicyStore'])
        response.dump()


@pytest.mark.remote
class FASPTestsTCPTransport(FASPTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR


@pytest.mark.remote
class FASPTestsTCPTransport64(FASPTests, unittest.TestCase):
    transfer_syntax = DCERPCTests.TRANSFER_SYNTAX_NDR64


if __name__ == '__main__':
    unittest.main(verbosity=1)
