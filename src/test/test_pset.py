import json
import unittest
from util import *

class PSETTests(unittest.TestCase):

    def test_serialization(self):
        """Testing serialization and deserialization"""

        with open(root_dir + 'src/data/pset.json', 'r') as f:
            d = json.load(f)
            valids = d['valid']
            invalids = d['invalid']

        for invalid in invalids:
            self.assertEqual(WALLY_EINVAL, wally_psbt_from_base64(utf8(invalid['pset']), pointer(wally_psbt())))

        for valid in valids:
            psbt_out = pointer(wally_psbt())
            self.assertEqual(WALLY_OK, wally_psbt_from_base64(utf8(valid['pset']), psbt_out))
            ret, b64 = wally_psbt_to_base64(psbt_out, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(valid['pset'], b64)
            ret, length = wally_psbt_get_length(psbt_out, 0)
            self.assertEqual(WALLY_OK, ret)
            self.assertEqual(length, valid['len'])
            
    def test_build_pset(self):
        # can create version 0 or 2
        psbt = pointer(wally_psbt())
        self.assertEqual(wally_psbt_elements_init_alloc(2, 0, 0, 0, psbt), WALLY_OK)
        ret, base64 = wally_psbt_to_base64(psbt, 0)        
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual("cHNldP8B+wQCAAAAAQIEAgAAAAEEAQABBQEAAA==", base64)
        
        tx_input = pointer(wally_tx_input())
        
        txhash, txhash_len = make_cbuffer("e7f25add4560021c77c4944f92739025fddbf99816d79c06d219268ca9f4b7e7")
        issuance_amount, issuance_amount_len = make_cbuffer("010000000000000201")
        inflation_keys, inflation_keys_len = make_cbuffer("010000000000040302")
        issuance_rangeproof, issuance_rangeproof_len = make_cbuffer("0102030405060708")
        inflation_rangeproof, inflation_rangeproof_len = make_cbuffer("0a0b0c0d0e0f1011")
        nonce, nonce_len = make_cbuffer("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        entropy, entropy_len = make_cbuffer("02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021")
        
        ret = wally_tx_elements_input_init_alloc(txhash, txhash_len, 5, 6, b'\x59', 1, None, nonce, nonce_len, entropy, entropy_len, 
                                                 issuance_amount, issuance_amount_len, inflation_keys, inflation_keys_len, issuance_rangeproof, issuance_rangeproof_len,
                                                 inflation_rangeproof, inflation_rangeproof_len, None,
                                                 tx_input)
        
        wally_psbt_add_input_at(psbt, 0, 0, tx_input)
        ret, base64 = wally_psbt_to_base64(psbt, 0)        
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual("cHNldP8B+wQCAAAAAQIEAgAAAAEEAQEBBQEAAAEOIOfyWt1FYAIcd8SUT5JzkCX92/mYFtecBtIZJoyp9LfnAQ8EBQAAAAEQBAYAAAAH/ARwc2V0AAgBAgAAAAAAAAf8BHBzZXQCCAECAwQFBgcIB/wEcHNldAMICgsMDQ4PEBEH/ARwc2V0CggCAwQAAAAAAAf8BHBzZXQMIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gB/wEcHNldA0gAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEA", base64)
                
        txhash, txhash_len = make_cbuffer("e7f25add4560021c77c4944f92739025fddbf99816d79c06d219268ca9f4b7e7")
        issuance_amount, issuance_amount_len = make_cbuffer("080102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        ret = wally_tx_elements_input_init_alloc(txhash, txhash_len, 3, 6, b'\x59', 1, None, None, 0, None, 0, issuance_amount, issuance_amount_len, None, 0, None, 0, None, 0, None,
                                                 tx_input)
        
        wally_psbt_add_input_at(psbt, 1, 0, tx_input)
        ret, base64 = wally_psbt_to_base64(psbt, 0)        
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual("cHNldP8B+wQCAAAAAQIEAgAAAAEEAQIBBQEAAAEOIOfyWt1FYAIcd8SUT5JzkCX92/mYFtecBtIZJoyp9LfnAQ8EBQAAAAEQBAYAAAAH/ARwc2V0AAgBAgAAAAAAAAf8BHBzZXQCCAECAwQFBgcIB/wEcHNldAMICgsMDQ4PEBEH/ARwc2V0CggCAwQAAAAAAAf8BHBzZXQMIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gB/wEcHNldA0gAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEAAQ4g5/Ja3UVgAhx3xJRPknOQJf3b+ZgW15wG0hkmjKn0t+cBDwQDAAAAARAEBgAAAAf8BHBzZXQBIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gAA==", base64)
        
        pegin_witness = pointer(wally_tx_witness_stack())
        
        pegin_amount, pegin_amount_len = make_cbuffer("0102030400000000")
        asset, asset_len = make_cbuffer("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d")
        genesis_hash, genesis_hash_len = make_cbuffer("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        claim_script, claim_script_len = make_cbuffer("010203")
        pegin_tx, pegin_tx_len = make_cbuffer("01000000016b246ed31e77fde10c1212ddb53b9c08451ed57bd644093e80539cd0a4571bc6000000006a4730440220021470f8381c569bbe7598bb23dacbb45ecabb0b2f5f4d5fa3d396a22e031c3102204abd31b957eca3d4d8b8de07865133059607e766de0e683fe59dab711731efb60121025907864f0894a6871562733e093978058c0cbfee924a47fd8b03410d68976b00ffffffff018afd09030000000017a914a59681709ece70a26670723a51f8735719d032928700000000")
        txout_proof, txout_proof_len = make_cbuffer("0102030405060708")
        
        ret = wally_tx_witness_stack_init_alloc(6, pegin_witness)
        self.assertEqual(ret, WALLY_OK)
        ret = wally_tx_witness_stack_add(pegin_witness, pegin_amount, pegin_amount_len)        
        ret = wally_tx_witness_stack_add(pegin_witness, asset, asset_len)
        ret = wally_tx_witness_stack_add(pegin_witness, genesis_hash, genesis_hash_len)
        ret = wally_tx_witness_stack_add(pegin_witness, claim_script, claim_script_len)
        ret = wally_tx_witness_stack_add(pegin_witness, pegin_tx, pegin_tx_len)
        ret = wally_tx_witness_stack_add(pegin_witness, txout_proof, txout_proof_len)
        
        pegin_pset = pointer(wally_psbt())
        tx_input = pointer(wally_tx_input())
        
        self.assertEqual(wally_psbt_elements_init_alloc(2, 0, 0, 0, pegin_pset), WALLY_OK)
        ret = wally_tx_elements_input_init_alloc(txhash, txhash_len, 5, 6, b'\x59', 1, None, None, 0, None, 0, 
                                                 None, 0, None, 0, None, 0,
                                                 None, 0, pegin_witness,
                                                 tx_input)
        
        self.assertEqual(ret, WALLY_OK)
                
        ret = wally_psbt_add_input_at(pegin_pset, 0, 0, tx_input)
        
        self.assertEqual(ret, WALLY_OK)
        
        ret, b64 = wally_psbt_to_base64(pegin_pset, 0)
        
        # ret, amount = wally_psbt_input_get_pegin_amount(psbt, 2)
        self.assertEqual(ret, WALLY_OK)
        # self.assertEqual(amount, 67305985)
        
        

if __name__ == '__main__':
    _, val = wally_is_elements_build()
    if val != 0:
        unittest.main()
