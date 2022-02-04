"""Tests for PSBT wrappers"""
import unittest
from wallycore import *

SAMPLE = "cHNidP8BAFICAAAAAZ38ZijCbFiZ/hvT3DOGZb/VXXraEPYiCXPfLTht7BJ2AQAAAAD/////AfA9zR0AAAAAFgAUezoAv9wU0neVwrdJAdCdpu8TNXkAAAAATwEENYfPAto/0AiAAAAAlwSLGtBEWx7IJ1UXcnyHtOTrwYogP/oPlMAVZr046QADUbdDiH7h1A3DKmBDck8tZFmztaTXPa7I+64EcvO8Q+IM2QxqT64AAIAAAACATwEENYfPAto/0AiAAAABuQRSQnE5zXjCz/JES+NTzVhgXj5RMoXlKLQH+uP2FzUD0wpel8itvFV9rCrZp+OcFyLrrGnmaLbyZnzB1nHIPKsM2QxqT64AAIABAACAAAEBKwBlzR0AAAAAIgAgLFSGEmxJeAeagU4TcV1l82RZ5NbMre0mbQUIZFuvpjIBBUdSIQKdoSzbWyNWkrkVNq/v5ckcOrlHPY5DtTODarRWKZyIcSEDNys0I07Xz5wf6l0F1EFVeSe+lUKxYusC4ass6AIkwAtSriIGAp2hLNtbI1aSuRU2r+/lyRw6uUc9jkO1M4NqtFYpnIhxENkMak+uAACAAAAAgAAAAAAiBgM3KzQjTtfPnB/qXQXUQVV5J76VQrFi6wLhqyzoAiTACxDZDGpPrgAAgAEAAIAAAAAAACICA57/H1R6HV+S36K6evaslxpL0DukpzSwMVaiVritOh75EO3kXMUAAACAAAAAgAEAAIAA"
SAMPLE_2 = "cHNidP8B+wQCAAAAAQIEewAAAAEEAQEBBQEBAAEOIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gAQ8EAQAAAAABAwgBAgMEBQYHCAEEAhEiAA=="

class PSBTTests(unittest.TestCase):

    def _try_invalid(self, fn, psbt, *args):
        with self.assertRaises(ValueError):
            fn(None, 0, *args) # Null PSBT
        with self.assertRaises(ValueError):
            fn(psbt, 1, *args) # Invalid index

    def _try_set(self, fn, psbt, valid_value, null_value=None):
        fn(psbt, 0, valid_value) # Set
        fn(psbt, 0, null_value) # Un-set
        self._try_invalid(fn, psbt, valid_value)
        
    def _try_get_set_i(self, setfn, clearfn, getfn, psbt, valid_value):
        self._try_invalid(setfn, psbt, valid_value)
        setfn(psbt, 0, valid_value) # Set
        self._try_invalid(getfn, psbt)
        ret = getfn(psbt, 0) # Get
        self.assertEqual(valid_value, ret)
        if clearfn:
            clearfn(psbt, 0)

    def _try_get_set_b(self, setfn, getfn, lenfn, psbt, valid_value, null_value=None):
        self._try_set(setfn, psbt, valid_value, null_value)
        setfn(psbt, 0, valid_value) # Set
        self._try_invalid(lenfn, psbt)
        self._try_invalid(getfn, psbt)
        ret = getfn(psbt, 0) # Get
        self.assertEqual(valid_value, ret)

    def _try_get_set_m(self, setfn, sizefn, lenfn, getfn, findfn, psbt, valid_value, valid_item):
        self._try_set(setfn, psbt, valid_value, None)
        self._try_invalid(sizefn, psbt)
        self.assertEqual(sizefn(psbt, 0), 0)
        setfn(psbt, 0, valid_value) # Set
        self.assertEqual(sizefn(psbt, 0), 1) # 1 item in the map
        self._try_invalid(lenfn, psbt, 0)
        with self.assertRaises(ValueError):
            lenfn(psbt, 0, 1) # Invalid subindex
        map_val = getfn(psbt, 0, 0)
        self.assertTrue(len(map_val) > 0)
        self.assertEqual(lenfn(psbt, 0, 0), len(map_val))
        self._try_invalid(findfn, psbt, map_val)
        self.assertEqual(findfn(psbt, 0, valid_item), 1)


    def test_psbt(self):
        psbt = psbt_from_base64(SAMPLE)
        psbt2 = psbt_from_base64(SAMPLE_2)

        # Roundtrip to/from bytes
        psbt_bytes = psbt_to_bytes(psbt, 0)
        psbt_tmp = psbt_from_bytes(psbt_bytes)
        self.assertEqual(hex_from_bytes(psbt_bytes),
                         hex_from_bytes(psbt_to_bytes(psbt_tmp, 0)))

        self.assertIsNotNone(psbt_get_global_tx(psbt))

        for fn, ret in [(psbt_get_version, 0),
                        (psbt_get_num_inputs, 1),
                        (psbt_get_num_outputs, 1)]:
            self.assertEqual(fn(psbt), ret)
            with self.assertRaises(ValueError):
                fn(None) # Null PSBT

        # Conversion to base64 should round trip
        self.assertEqual(psbt_to_base64(psbt, 0), SAMPLE)

        # Combining with ourselves shouldn't change the PSBT
        psbt_combine(psbt, psbt)
        self.assertEqual(psbt_to_base64(psbt, 0), SAMPLE)

        # Test setters
        dummy_tx = psbt_get_global_tx(psbt)
        self.assertIsNotNone(dummy_tx)

        dummy_txout = tx_output_init(1234567, bytearray(b'\x00' * 33))

        dummy_witness = tx_witness_stack_init(5)
        self.assertIsNotNone(dummy_witness)

        dummy_bytes = bytearray(b'\x00' * 32)
        dummy_pubkey = bytearray(b'\x02'* EC_PUBLIC_KEY_LEN)
        dummy_fingerprint = bytearray(b'\x00' * BIP32_KEY_FINGERPRINT_LEN)
        dummy_path = [1234, 1234, 1234]
        dummy_sig = bytearray(b'\x00' * 72)
        if is_elements_build():
            dummy_nonce = bytearray(b'\x00' * WALLY_TX_ASSET_CT_NONCE_LEN)
            dummy_bf = bytearray(b'\x00' * BLINDING_FACTOR_LEN)
            dummy_commitment = bytearray(b'\x00' * ASSET_COMMITMENT_LEN)
            dummy_asset = bytearray(b'\x00' * ASSET_TAG_LEN)

        dummy_keypaths = map_init(0)
        self.assertIsNotNone(dummy_keypaths)
        map_add_keypath_item(dummy_keypaths, dummy_pubkey, dummy_fingerprint, dummy_path)
        self.assertEqual(map_find(dummy_keypaths, dummy_pubkey), 1)

        dummy_signatures = map_init(0)
        self.assertIsNotNone(dummy_signatures)
        map_add(dummy_signatures, dummy_pubkey, dummy_sig)
        self.assertEqual(map_find(dummy_signatures, dummy_pubkey), 1)

        dummy_unknowns = map_init(1)
        self.assertIsNotNone(dummy_unknowns)
        map_add(dummy_unknowns, dummy_pubkey, dummy_fingerprint)
        self.assertEqual(map_find(dummy_unknowns, dummy_pubkey), 1)

        with self.assertRaises(ValueError):  # Cannot set TX Version on V0 PSBT.
            psbt_set_tx_version(psbt, 3)
            
        psbt_set_tx_version(psbt2, 3)
        self.assertEqual(psbt_get_tx_version(psbt2), 3)
        
        with self.assertRaises(ValueError): #Cannot set TX Version on NULL PSBT.
            psbt_set_tx_version(None, 3)
        
        with self.assertRaises(ValueError):  # Cannot set Fallback Locktime on V0 PSBT.
            psbt_set_fallback_locktime(psbt, 3)
        
        psbt_set_fallback_locktime(psbt2, 3)
        self.assertEqual(psbt_get_fallback_locktime(psbt2), 3)
        
        with self.assertRaises(ValueError): #Cannot set Fallback Locktime on NULL PSBT.
            psbt_set_fallback_locktime(None, 3)
            
        psbt_clear_fallback_locktime(psbt2)
        
        with self.assertRaises(ValueError): #Cannot clear Fallback Locktime Version on NULL PSBT.
            psbt_clear_fallback_locktime(None)
        
        self.assertEqual(psbt_to_base64(psbt2, 0), "cHNidP8B+wQCAAAAAQIEAwAAAAEEAQEBBQEBAAEOIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gAQ8EAQAAAAABAwgBAgMEBQYHCAEEAhEiAA==")
        
        psbt_set_tx_modifiable_flags(psbt2, 1)
        
        self.assertEqual(psbt_get_tx_modifiable_flags(psbt2), 1)
        
        with self.assertRaises(ValueError): #Cannot get TX Modifiable Flags on NULL PSBT.
            psbt_get_tx_modifiable_flags(None)
    
        with self.assertRaises(ValueError): #Cannot set TX Modifiable Flags on NULL PSBT.
            psbt_set_tx_modifiable_flags(None, 3)
            
        with self.assertRaises(ValueError): #Cannot set TX Modifiable Flags on V0 PSBT.
            psbt_set_tx_modifiable_flags(psbt, 1)
        
        psbt_set_scalar(psbt2, dummy_bytes)
        self.assertEqual(psbt_get_scalar_len(psbt2), 32)
        self.assertEqual(psbt_get_scalar(psbt2), dummy_bytes)
        
        
        with self.assertRaises(ValueError): #Cannot set scalar on NULL PSBT.   
            psbt_set_scalar(None, dummy_bytes)
            
        with self.assertRaises(ValueError): #Cannot get scalar len on NULL PSBT.   
            psbt_get_scalar_len(None)
            
        with self.assertRaises(ValueError): #Cannot get scalar on NULL PSBT.   
            psbt_get_scalar(None)
            
            
        with self.assertRaises(ValueError): #Cannot set scalar on V0 PSBT.   
            psbt_set_scalar(psbt, dummy_bytes)
            
        #
        # Inputs
        #
        self._try_set(psbt_set_input_utxo, psbt, dummy_tx)
        self._try_invalid(psbt_get_input_utxo, psbt)
        self._try_set(psbt_set_input_witness_utxo, psbt, dummy_txout)
        self._try_invalid(psbt_get_input_witness_utxo, psbt)
        self._try_get_set_b(psbt_set_input_redeem_script,
                            psbt_get_input_redeem_script,
                            psbt_get_input_redeem_script_len, psbt, dummy_bytes)
        self._try_get_set_b(psbt_set_input_witness_script,
                            psbt_get_input_witness_script,
                            psbt_get_input_witness_script_len, psbt, dummy_bytes)
        self._try_get_set_b(psbt_set_input_final_scriptsig,
                            psbt_get_input_final_scriptsig,
                            psbt_get_input_final_scriptsig_len, psbt, dummy_bytes)
        self._try_set(psbt_set_input_final_witness, psbt, dummy_witness)
        self._try_invalid(psbt_get_input_final_witness, psbt)
        self._try_get_set_m(psbt_set_input_keypaths,
                            psbt_get_input_keypaths_size,
                            psbt_get_input_keypath_len,
                            psbt_get_input_keypath,
                            psbt_find_input_keypath,
                            psbt, dummy_keypaths, dummy_pubkey)
        self._try_get_set_m(psbt_set_input_signatures,
                            psbt_get_input_signatures_size,
                            psbt_get_input_signature_len,
                            psbt_get_input_signature,
                            psbt_find_input_signature,
                            psbt, dummy_signatures, dummy_pubkey)
        self._try_get_set_m(psbt_set_input_unknowns,
                            psbt_get_input_unknowns_size,
                            psbt_get_input_unknown_len,
                            psbt_get_input_unknown,
                            psbt_find_input_unknown,
                            psbt, dummy_unknowns, dummy_pubkey)
        self._try_set(psbt_set_input_sighash, psbt, 0xff, 0x0)
        self.assertEqual(psbt_get_input_sighash(psbt, 0), 0)
        self._try_invalid(psbt_get_input_sighash, psbt)
        
        with self.assertRaises(ValueError): #Cannot set txhash on V0 PSBT.
            psbt_set_input_previous_txid(psbt, 0, dummy_bytes)
        
        self._try_get_set_b(psbt_set_input_previous_txid, 
                            psbt_get_input_previous_txid,
                            psbt_get_input_previous_txid_len, psbt2, dummy_bytes)
        
        
        with self.assertRaises(ValueError): #Cannot set output index on V0 PSBT.
            psbt_set_input_output_index(psbt, 0, 1234)
            
        self._try_get_set_i(psbt_set_input_output_index,
                            None,
                            psbt_get_input_output_index,
                            psbt2, 1234)
        
        
        with self.assertRaises(ValueError): #Cannot set sequence on V0 PSBT.
            psbt_set_input_sequence(psbt, 0, 1234)
            
        self._try_get_set_i(psbt_set_input_sequence,
                            psbt_clear_input_sequence,
                            psbt_get_input_sequence,
                            psbt2, 1234)
        
        with self.assertRaises(ValueError): #Cannot set required locktime on V0 PSBT.
            psbt_set_input_required_locktime(psbt, 0, 1234)
            
        self._try_get_set_i(psbt_set_input_required_locktime,
                            psbt_clear_input_required_locktime,
                            psbt_get_input_required_locktime,
                            psbt2, 1234)

        if is_elements_build():
            self._try_get_set_i(psbt_set_input_issuance_amount,
                                psbt_clear_input_issuance_amount,
                                psbt_get_input_issuance_amount,
                                psbt2, 100)
            
            self._try_get_set_b(psbt_set_input_issuance_amount_commitment,
                                psbt_get_input_issuance_amount_commitment,
                                psbt_get_input_issuance_amount_commitment_len, psbt2, dummy_bytes)
            
            self._try_get_set_b(psbt_set_input_issuance_amount_rangeproof,
                                psbt_get_input_issuance_amount_rangeproof,
                                psbt_get_input_issuance_amount_rangeproof_len, psbt2, dummy_bytes)
            
            self._try_get_set_b(psbt_set_input_issuance_amount_blind_proof,
                                psbt_get_input_issuance_amount_blind_proof,
                                psbt_get_input_issuance_amount_blind_proof_len, psbt2, dummy_bytes)
            
            self._try_get_set_b(psbt_set_input_blinding_nonce,
                                psbt_get_input_blinding_nonce,
                                psbt_get_input_blinding_nonce_len, psbt2, dummy_nonce)
            
            self._try_get_set_b(psbt_set_input_entropy,
                                psbt_get_input_entropy,
                                psbt_get_input_entropy_len, psbt2, dummy_bytes)
            
            self._try_get_set_i(psbt_set_input_inflation_keys,
                                psbt_clear_input_inflation_keys,
                                psbt_get_input_inflation_keys,
                                psbt2, 100)
            
            self._try_get_set_b(psbt_set_input_inflation_keys_commitment,
                                psbt_get_input_inflation_keys_commitment,
                                psbt_get_input_inflation_keys_commitment_len, psbt2, dummy_bytes)
            
            self._try_get_set_b(psbt_set_input_inflation_keys_rangeproof,
                                psbt_get_input_inflation_keys_rangeproof,
                                psbt_get_input_inflation_keys_rangeproof_len, psbt2, dummy_bytes)
            
            self._try_get_set_b(psbt_set_input_inflation_keys_blind_proof,
                                psbt_get_input_inflation_keys_blind_proof,
                                psbt_get_input_inflation_keys_blind_proof_len, psbt2, dummy_bytes)
            
            self._try_get_set_b(psbt_set_input_txoutproof,
                                psbt_get_input_txoutproof,
                                psbt_get_input_txoutproof_len, psbt, dummy_bytes)
            
            self._try_set(psbt_set_input_pegin_tx, psbt, dummy_tx)
            self._try_invalid(psbt_get_input_pegin_tx, psbt)
            self._try_get_set_b(psbt_set_input_txoutproof,
                                psbt_get_input_txoutproof,
                                psbt_get_input_txoutproof_len, psbt, dummy_bytes)
            self._try_get_set_b(psbt_set_input_genesis_blockhash,
                                psbt_get_input_genesis_blockhash,
                                psbt_get_input_genesis_blockhash_len, psbt, dummy_bytes)
            self._try_get_set_b(psbt_set_input_claim_script,
                                psbt_get_input_claim_script,
                                psbt_get_input_claim_script_len, psbt, dummy_bytes)

        #
        # Outputs
        #
        self._try_get_set_b(psbt_set_output_redeem_script,
                            psbt_get_output_redeem_script,
                            psbt_get_output_redeem_script_len, psbt, dummy_bytes)
        self._try_get_set_b(psbt_set_output_witness_script,
                            psbt_get_output_witness_script,
                            psbt_get_output_witness_script_len, psbt, dummy_bytes)
        self._try_get_set_m(psbt_set_output_keypaths,
                            psbt_get_output_keypaths_size,
                            psbt_get_output_keypath_len,
                            psbt_get_output_keypath,
                            psbt_find_output_keypath,
                            psbt, dummy_keypaths, dummy_pubkey)
        self._try_get_set_m(psbt_set_output_unknowns,
                            psbt_get_output_unknowns_size,
                            psbt_get_output_unknown_len,
                            psbt_get_output_unknown,
                            psbt_find_output_unknown,
                            psbt, dummy_unknowns, dummy_pubkey)
        
        with self.assertRaises(ValueError): #Cannot set script on V0 PSBT.
            psbt_set_output_script(psbt, 0, dummy_bytes)
            
        self._try_get_set_b(psbt_set_output_script,
                    psbt_get_output_script,
                    psbt_get_output_script_len, psbt2, dummy_bytes)
        
        with self.assertRaises(ValueError): #Cannot set amount on V0 PSBT.
            psbt_set_output_amount(psbt, 0, 1234)
        
        self._try_get_set_i(psbt_set_output_amount,
                    None,
                    psbt_get_output_amount, psbt2, 1234)
        
        
        if is_elements_build():
            self._try_get_set_b(psbt_set_output_blinding_pubkey,
                                psbt_get_output_blinding_pubkey,
                                psbt_get_output_blinding_pubkey_len, psbt, dummy_pubkey)
            self._try_get_set_b(psbt_set_output_value_commitment,
                                psbt_get_output_value_commitment,
                                psbt_get_output_value_commitment_len, psbt, dummy_commitment)
            self._try_get_set_b(psbt_set_output_asset_commitment,
                                psbt_get_output_asset_commitment,
                                psbt_get_output_asset_commitment_len, psbt, dummy_commitment)
            self._try_get_set_b(psbt_set_output_nonce,
                                psbt_get_output_nonce,
                                psbt_get_output_nonce_len, psbt, dummy_nonce)
            self._try_get_set_b(psbt_set_output_rangeproof,
                                psbt_get_output_rangeproof,
                                psbt_get_output_rangeproof_len, psbt, dummy_bytes)
            self._try_get_set_b(psbt_set_output_surjectionproof,
                                psbt_get_output_surjectionproof,
                                psbt_get_output_surjectionproof_len, psbt, dummy_bytes)
            


if __name__ == '__main__':
    unittest.main()
