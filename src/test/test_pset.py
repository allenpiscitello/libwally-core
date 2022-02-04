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
        

if __name__ == '__main__':
    _, val = wally_is_elements_build()
    if val != 0:
        unittest.main()
