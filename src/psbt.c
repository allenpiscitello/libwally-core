#include "internal.h"

#include <include/wally_elements.h>
#include <include/wally_script.h>
#include <include/wally_psbt.h>

#include <limits.h>
#include <stdbool.h>
#include "transaction_shared.h"
#include "psbt_int.h"
#include "script_int.h"
#include "script.h"
#include "pullpush.h"

/* TODO:
 * - When setting utxo in an input via the psbt (in the SWIG
 *   case), check the txid matches the input (see is_matching_txid() call
 *   in the signing code).
 * - When signing, validate the existing signatures and refuse to sign if
 *   any are incorrect. This prevents others pretending to sign and then
 *   gaining our signature without having provided theirs.
 * - Signing of multisig inputs is not implemented.
 * - Change detection is not implemented, something like:
 *   wally_psbt_is_related_output(psbt, index, ext_key, written) could
 *   identify whether the given output pays to and address from ext_key.
 */

/* Constants for key types in serialized PSBTs */
#define PSBT_SEPARATOR 0x00

#define PSBT_GLOBAL_UNSIGNED_TX 0x00
#define PSBT_GLOBAL_TX_VERSION 0x02
#define PSBT_GLOBAL_FALLBACK_LOCKTIME 0x03
#define PSBT_GLOBAL_INPUT_COUNT 0x04
#define PSBT_GLOBAL_OUTPUT_COUNT 0x05
#define PSBT_GLOBAL_TX_MODIFIABLE 0x06
#define PSBT_GLOBAL_VERSION 0xFB

#define PSBT_IN_NON_WITNESS_UTXO 0x00
#define PSBT_IN_WITNESS_UTXO 0x01
#define PSBT_IN_PARTIAL_SIG 0x02
#define PSBT_IN_SIGHASH_TYPE 0x03
#define PSBT_IN_REDEEM_SCRIPT 0x04
#define PSBT_IN_WITNESS_SCRIPT 0x05
#define PSBT_IN_BIP32_DERIVATION 0x06
#define PSBT_IN_FINAL_SCRIPTSIG 0x07
#define PSBT_IN_FINAL_SCRIPTWITNESS 0x08
#define PSBT_IN_POR_COMMITMENT 0x09
#define PSBT_IN_RIPEMD160 0x0a
#define PSBT_IN_SHA256 0x0b
#define PSBT_IN_HASH160 0x0c
#define PSBT_IN_HASH256 0x0d
#define PSBT_IN_PREVIOUS_TXID 0x0e
#define PSBT_IN_OUTPUT_INDEX 0x0f
#define PSBT_IN_SEQUENCE 0x10
#define PSBT_IN_REQUIRED_TIME_LOCKTIME 0x11
#define PSBT_IN_REQUIRED_HEIGHT_LOCKTIME 0x012

#define PSBT_LOCKTIME_MIN_TIMESTAMP 500000000

#define PSBT_OUT_REDEEM_SCRIPT 0x00
#define PSBT_OUT_WITNESS_SCRIPT 0x01
#define PSBT_OUT_BIP32_DERIVATION 0x02
#define PSBT_OUT_AMOUNT 0x03
#define PSBT_OUT_SCRIPT 0x04

#ifdef BUILD_ELEMENTS
#define PSBT_ELEMENTS_GLOBAL_SCALAR 0x00
#define PSBT_ELEMENTS_GLOBAL_TX_MODIFIABLE 0x01

#define PSBT_ELEMENTS_IN_ISSUANCE_VALUE 0x00
#define PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT 0x01
#define PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF 0x02
#define PSBT_ELEMENTS_IN_ISSUANCE_KEYS_RANGEPROOF 0x03
#define PSBT_ELEMENTS_IN_PEG_IN_TX 0x04
#define PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF 0x05
#define PSBT_ELEMENTS_IN_PEG_IN_GENESIS 0x06
#define PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT 0x07
#define PSBT_ELEMENTS_IN_PEG_IN_VALUE 0x08
#define PSBT_ELEMENTS_IN_PEG_IN_WITNESS 0x09
#define PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS 0x0a
#define PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT 0x0b
#define PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE 0x0c
#define PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY 0x0d
#define PSBT_ELEMENTS_IN_UTXO_RANGEPROOF 0x0e
#define PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF 0x0f
#define PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF 0x10

#define PSBT_ELEMENTS_OUT_VALUE_COMMITMENT 0x01
#define PSBT_ELEMENTS_OUT_ASSET 0x02
#define PSBT_ELEMENTS_OUT_ASSET_COMMITMENT 0x03
#define PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF 0x04
#define PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF 0x05
#define PSBT_ELEMENTS_OUT_BLINDING_PUBKEY 0x06
#define PSBT_ELEMENTS_OUT_ECDH_PUBKEY 0x07
#define PSBT_ELEMENTS_OUT_BLINDER_INDEX 0x08
#define PSBT_ELEMENTS_OUT_BLIND_VALUE_PROOF 0x09
#define PSBT_ELEMENTS_OUT_BLIND_ASSET_PROOF 0x0a

#endif /* BUILD ELEMENTS */

static const uint8_t PSBT_MAGIC[5] = {'p', 's', 'b', 't', 0xff};
static const uint8_t PSET_MAGIC[5] = {'p', 's', 'e', 't', 0xff};

#ifdef BUILD_ELEMENTS
static const uint8_t PSET_KEY_PREFIX[4] = {'p', 's', 'e', 't'};

static bool is_elements_prefix(const unsigned char *key, size_t key_len) {
    return key_len == sizeof(PSET_KEY_PREFIX) &&
           memcmp(key, PSET_KEY_PREFIX, key_len) == 0;
}
#endif /* BUILD_ELEMENTS */

static int tx_clone_alloc(const struct wally_tx *src, struct wally_tx **dst) {
    return wally_tx_clone_alloc(src, 0, dst);
}

static bool is_matching_txid(const struct wally_tx *tx,
                             const unsigned char *txid, size_t txid_len)
{
    unsigned char src_txid[WALLY_TXHASH_LEN];
    bool ret;

    if (!tx || !txid || txid_len != WALLY_TXHASH_LEN)
        return false;

    if (wally_tx_get_txid(tx, src_txid, sizeof(src_txid)) != WALLY_OK)
        return false;

    ret = memcmp(src_txid, txid, txid_len) == 0;
    wally_clear(src_txid, sizeof(src_txid));
    return ret;
}

static int array_grow(void **src, size_t num_items, size_t *allocation_len,
                      size_t item_size)
{
    if (num_items == *allocation_len) {
        /* Array is full, allocate more space */
        const size_t n = (*allocation_len == 0 ? 1 : *allocation_len) * 2;
        void *p = realloc_array(*src, *allocation_len, n, item_size);
        if (!p)
            return WALLY_ENOMEM;
        /* Free and replace the old array with the new enlarged copy */
        clear_and_free(*src, num_items * item_size);
        *src = p;
        *allocation_len = n;
    }
    return WALLY_OK;
}

int wally_map_init(size_t allocation_len, struct wally_map *output)
{
    if (!output)
        return WALLY_EINVAL;

    wally_clear(output, sizeof(*output));
    if (allocation_len) {
        output->items = wally_calloc(allocation_len * sizeof(*output->items));
        if (!output->items)
            return WALLY_ENOMEM;
    }
    output->items_allocation_len = allocation_len;
    return WALLY_OK;
}

int wally_map_init_alloc(size_t allocation_len, struct wally_map **output)
{
    struct wally_map *result;
    int ret;

    TX_CHECK_OUTPUT;
    TX_OUTPUT_ALLOC(struct wally_map);

    ret = wally_map_init(allocation_len, result);
    if (ret != WALLY_OK) {
        wally_free(result);
        *output = NULL;
    }
    return ret;
}

int wally_map_clear(struct wally_map *map_in)
{
    size_t i;

    if (!map_in)
        return WALLY_EINVAL;
    for (i = 0; i < map_in->num_items; ++i) {
        clear_and_free(map_in->items[i].key, map_in->items[i].key_len);
        clear_and_free(map_in->items[i].value, map_in->items[i].value_len);
    }
    clear_and_free(map_in->items, map_in->num_items * sizeof(*map_in->items));
    wally_clear(map_in, sizeof(*map_in));
    return WALLY_OK;
}

int wally_map_free(struct wally_map *map_in)
{
    if (map_in) {
        wally_map_clear(map_in);
        wally_free(map_in);
    }
    return WALLY_OK;
}

int wally_map_find(const struct wally_map *map_in,
                   const unsigned char *key, size_t key_len,
                   size_t *written)
{
    size_t i;

    if (written)
        *written = 0;

    if (!map_in || !key || BYTES_INVALID(key, key_len) || !written)
        return WALLY_EINVAL;

    for (i = 0; i < map_in->num_items; ++i) {
        const struct wally_map_item *item = &map_in->items[i];

        if (key_len == item->key_len && memcmp(key, item->key, key_len) == 0) {
            *written = i + 1; /* Found */
            break;
        }
    }
    return WALLY_OK;
}

/* Note: If take_value is true and this errors, the caller must
 * free `value`. By design this only happens with calls internal
 * to this source file. */
static int map_add(struct wally_map *map_in,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *value, size_t value_len,
                   bool take_value,
                   int (*check_fn)(const unsigned char *key, size_t key_len),
                   bool ignore_dups)
{
    size_t is_found;
    int ret;

    if (!map_in || !key || BYTES_INVALID(key, key_len) ||
        (check_fn && check_fn(key, key_len) != WALLY_OK) ||
        BYTES_INVALID(value, value_len))
        return WALLY_EINVAL;

    if ((ret = wally_map_find(map_in, key, key_len, &is_found)) != WALLY_OK)
        return ret;

    if (is_found) {
        if (ignore_dups && take_value)
            clear_and_free((unsigned char *)value, value_len);
        return ignore_dups ? WALLY_OK : WALLY_EINVAL;
    }

    ret = array_grow((void *)&map_in->items, map_in->num_items,
                     &map_in->items_allocation_len, sizeof(struct wally_map_item));
    if (ret == WALLY_OK) {
        struct wally_map_item *new_item = map_in->items + map_in->num_items;

        if (!clone_bytes(&new_item->key, key, key_len))
            return WALLY_ENOMEM;
        if (value) {
            if (take_value)
                new_item->value = (unsigned char *)value;
            else if (!clone_bytes(&new_item->value, value, value_len)) {
                clear_and_free(new_item->key, key_len);
                new_item->key = NULL;
                return WALLY_ENOMEM;
            }
        }
        new_item->key_len = key_len;
        new_item->value_len = value_len;
        map_in->num_items++;
    }
    return ret;
}

int wally_map_add(struct wally_map *map_in,
                  const unsigned char *key, size_t key_len,
                  const unsigned char *value, size_t value_len)
{
    return map_add(map_in, key, key_len, value, value_len, false, NULL, true);
}

int wally_map_add_keypath_item(struct wally_map *map_in,
                               const unsigned char *pub_key, size_t pub_key_len,
                               const unsigned char *fingerprint, size_t fingerprint_len,
                               const uint32_t *path, size_t path_len)
{
    unsigned char *value;
    size_t value_len, i;
    int ret;

    if (!map_in ||
        (wally_ec_public_key_verify(pub_key, pub_key_len) != WALLY_OK) ||
        !fingerprint || fingerprint_len != BIP32_KEY_FINGERPRINT_LEN ||
        BYTES_INVALID(path, path_len))
        return WALLY_EINVAL;

    value_len = fingerprint_len + path_len * sizeof(uint32_t);
    if (!(value = wally_malloc(value_len)))
        return WALLY_ENOMEM;

    memcpy(value, fingerprint, fingerprint_len);
    for (i = 0; i < path_len; ++i) {
        leint32_t tmp = cpu_to_le32(path[i]);
        memcpy(value + fingerprint_len + i * sizeof(uint32_t),
               &tmp, sizeof(tmp));
    }

    ret = map_add(map_in, pub_key, pub_key_len, value, value_len, true, NULL, true);
    if (ret != WALLY_OK)
        clear_and_free(value, value_len);
    return ret;
}

static int map_item_compare(const void *lhs, const void *rhs)
{
    const struct wally_map_item *l = lhs, *r = rhs;
    const size_t min_len = l->key_len < r->key_len ? l->key_len : r->key_len;
    int cmp;

    cmp = memcmp(l->key, r->key, min_len);
    if (cmp == 0) {
        /* Equal up to the min length, longest key is greater. If we have
         * duplicate keys somehow, the resulting order is undefined */
        cmp = l->key_len < r->key_len ? -1 : 1;
    }
    return cmp;
}

int wally_map_sort(struct wally_map *map_in, uint32_t flags)
{
    if (!map_in || flags)
        return WALLY_EINVAL;

    qsort(map_in->items, map_in->num_items, sizeof(struct wally_map_item), map_item_compare);
    return WALLY_OK;
}

static int map_extend(struct wally_map *dst, const struct wally_map *src,
                      int (*check_fn)(const unsigned char *key, size_t key_len))
{
    int ret = WALLY_OK;
    size_t i;

    if (src) {
        for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
            ret = map_add(dst, src->items[i].key, src->items[i].key_len,
                          src->items[i].value, src->items[i].value_len,
                          false, check_fn, true);
    }
    return ret;
}

static int map_assign(const struct wally_map *src, struct wally_map *dst,
                      int (*check_fn)(const unsigned char *key, size_t key_len))
{
    struct wally_map result;
    size_t i;
    int ret = WALLY_OK;

    if (!src)
        ret = wally_map_init(0, &result);
    else {
        ret = wally_map_init(src->items_allocation_len, &result);
        for (i = 0; ret == WALLY_OK && i < src->num_items; ++i)
            ret = map_add(&result, src->items[i].key, src->items[i].key_len,
                          src->items[i].value, src->items[i].value_len,
                          false, check_fn, true);
    }

    if (ret != WALLY_OK)
        wally_map_clear(&result);
    else {
        wally_map_clear(dst);
        memcpy(dst, &result, sizeof(result));
    }
    return ret;
}

/* Set a struct member on a parent struct */
#define SET_STRUCT(PARENT, NAME, STRUCT_TYPE, CLONE_FN, FREE_FN) \
    int PARENT ## _set_ ## NAME(struct PARENT *parent, const struct STRUCT_TYPE *p) { \
        int ret = WALLY_OK; \
        struct STRUCT_TYPE *new_p = NULL; \
        if (!parent) return WALLY_EINVAL; \
        if (p && (ret = CLONE_FN(p, &new_p)) != WALLY_OK) return ret; \
        FREE_FN(parent->NAME); \
        parent->NAME = new_p; \
        return ret; \
    }

/* Set a variable length bytes member on a parent struct */
#define SET_BYTES(PARENT, NAME) \
    int PARENT ## _set_ ## NAME(struct PARENT *parent, const unsigned char *bytes, size_t len) { \
        if (!parent) return WALLY_EINVAL; \
        return replace_bytes(bytes, len, \
                             &parent->NAME, &parent->NAME ## _len); \
    }

/* Set a fixed length bytes member on a parent struct */
#define SET_BYTES_N(PARENT, NAME, SIZE) \
    int PARENT ## _set_ ## NAME(struct PARENT *parent, const unsigned char *bytes, size_t len) { \
        if (!parent || BYTES_INVALID_N(bytes, len, SIZE)) return WALLY_EINVAL; \
        return replace_bytes(bytes, len, \
                             &parent->NAME, &parent->NAME ## _len); \
    }

/* Set/find in and add a vap value member on a parent struct */
#define SET_MAP(PARENT, NAME, CHECK_FN) \
    int PARENT ## _set_ ## NAME ## s(struct PARENT *parent, const struct wally_map *map_in) { \
        if (!parent) return WALLY_EINVAL; \
        return map_assign(map_in, &parent->NAME ## s, CHECK_FN); \
    } \
    int PARENT ## _find_ ## NAME(struct PARENT *parent, \
                                 const unsigned char *key, size_t key_len, \
                                 size_t *written) { \
        if (written) *written = 0; \
        if (!parent) return WALLY_EINVAL; \
        return wally_map_find(&parent->NAME ## s, key, key_len, written); \
    } \
    int PARENT ## _add_ ## NAME(struct PARENT *parent, \
                                const unsigned char *key, size_t key_len, \
                                const unsigned char *value, size_t value_len) { \
        if (!parent) return WALLY_EINVAL; \
        return wally_map_add(&parent->NAME ## s, key, key_len, value, value_len); \
    }

/* Add a keypath to parent structs keyoaths member */
#define ADD_KEYPATH(PARENT) \
    int PARENT ## _add_keypath_item(struct PARENT *parent, \
                                    const unsigned char *pub_key, size_t pub_key_len, \
                                    const unsigned char *fingerprint, size_t fingerprint_len, \
                                    const uint32_t *child_path, size_t child_path_len) { \
        if (!parent) return WALLY_EINVAL; \
        return wally_map_add_keypath_item(&parent->keypaths, pub_key, pub_key_len, \
                                          fingerprint, fingerprint_len, \
                                          child_path, child_path_len); \
    }

int wally_psbt_input_is_finalized(const struct wally_psbt_input *input,
                                  size_t *written)
{
    if (written)
        *written = 0;
    if (!input || !written)
        return WALLY_EINVAL;
    *written = input->final_scriptsig || input->final_witness ? 1 : 0;
    return WALLY_OK;
}

SET_STRUCT(wally_psbt_input, utxo, wally_tx,
           tx_clone_alloc, wally_tx_free)
SET_STRUCT(wally_psbt_input, witness_utxo, wally_tx_output,
           wally_tx_output_clone_alloc, wally_tx_output_free)
SET_BYTES(wally_psbt_input, redeem_script)
SET_BYTES(wally_psbt_input, witness_script)
SET_BYTES(wally_psbt_input, final_scriptsig)
SET_STRUCT(wally_psbt_input, final_witness, wally_tx_witness_stack,
           wally_tx_witness_stack_clone_alloc, wally_tx_witness_stack_free)
SET_MAP(wally_psbt_input, keypath, wally_ec_public_key_verify)
ADD_KEYPATH(wally_psbt_input)
SET_MAP(wally_psbt_input, signature, wally_ec_public_key_verify)
SET_MAP(wally_psbt_input, unknown, NULL)

int wally_psbt_input_set_sighash(struct wally_psbt_input *input, uint32_t sighash)
{
    if (!input)
        return WALLY_EINVAL;
    input->sighash = sighash;
    return WALLY_OK;
}

int wally_psbt_input_set_previous_txid(struct wally_psbt_input *input, const unsigned char *bytes, size_t len)
{
    if (!input || BYTES_INVALID_N(bytes, len, WALLY_TXHASH_LEN) || input->psbt_version == 0) return WALLY_EINVAL;
    return replace_bytes(bytes, len,
                         &input->previous_txid, &input->previous_txid_len);
}

int wally_psbt_input_set_output_index(struct wally_psbt_input *input, uint32_t output_index)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->output_index = output_index;
    return WALLY_OK;
}

int wally_psbt_input_set_sequence(struct wally_psbt_input *input, uint32_t sequence)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->sequence = sequence;
    input->has_sequence = 1u;
    return WALLY_OK;
}

int wally_psbt_input_clear_sequence(struct wally_psbt_input *input)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->sequence = 0;
    input->has_sequence = 0u;
    return WALLY_OK;
}

int wally_psbt_input_set_required_locktime(struct wally_psbt_input *input, uint32_t required_locktime)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->required_locktime = required_locktime;
    input->has_required_locktime = 1u;
    return WALLY_OK;
}

int wally_psbt_input_clear_required_locktime(struct wally_psbt_input *input)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->required_locktime = 0;
    input->has_required_locktime = 0u;
    return WALLY_OK;
}

#ifdef BUILD_ELEMENTS
int wally_psbt_input_set_issuance_amount(struct wally_psbt_input *input, uint64_t issuance_amount)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->issuance_amount = issuance_amount;
    input->has_issuance_amount = 1u;
    return WALLY_OK;
}

int wally_psbt_input_clear_issuance_amount(struct wally_psbt_input *input)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->issuance_amount = 0;
    input->has_issuance_amount = 0u;
    return WALLY_OK;
}

SET_BYTES(wally_psbt_input, issuance_amount_commitment)
SET_BYTES(wally_psbt_input, issuance_amount_rangeproof)
SET_BYTES(wally_psbt_input, issuance_amount_blind_proof)
SET_BYTES(wally_psbt_input, blinding_nonce)
SET_BYTES(wally_psbt_input, entropy)
int wally_psbt_input_set_inflation_keys(struct wally_psbt_input *input, uint64_t inflation_keys)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->inflation_keys = inflation_keys;
    input->has_inflation_keys = 1u;
    return WALLY_OK;
}

int wally_psbt_input_clear_inflation_keys(struct wally_psbt_input *input)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->inflation_keys = 0;
    input->has_inflation_keys = 0u;
    return WALLY_OK;
}

SET_BYTES(wally_psbt_input, inflation_keys_commitment)
SET_BYTES(wally_psbt_input, inflation_keys_rangeproof)
SET_BYTES(wally_psbt_input, inflation_keys_blind_proof)
SET_STRUCT(wally_psbt_input, pegin_tx, wally_tx,
           tx_clone_alloc, wally_tx_free)
SET_BYTES(wally_psbt_input, txoutproof)
SET_BYTES_N(wally_psbt_input, genesis_blockhash, SHA256_LEN)
SET_BYTES(wally_psbt_input, claim_script)

int wally_psbt_input_set_pegin_amount(struct wally_psbt_input *input, uint64_t pegin_amount)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->pegin_amount = pegin_amount;
    input->has_pegin_amount = 1u;
    return WALLY_OK;
}

int wally_psbt_input_clear_pegin_amount(struct wally_psbt_input *input)
{
    if (!input || input->psbt_version == 0)
        return WALLY_EINVAL;
    input->pegin_amount = 0;
    input->has_pegin_amount = 0u;
    return WALLY_OK;
}
SET_STRUCT(wally_psbt_input, pegin_witness, wally_tx_witness_stack,
           wally_tx_witness_stack_clone_alloc, wally_tx_witness_stack_free)
SET_BYTES(wally_psbt_input, utxo_rangeproof)
#endif /* BUILD_ELEMENTS */

static int psbt_input_free(struct wally_psbt_input *input, bool free_parent)
{
    if (input) {
        wally_tx_free(input->utxo);
        wally_tx_output_free(input->witness_utxo);
        clear_and_free(input->redeem_script, input->redeem_script_len);
        clear_and_free(input->witness_script, input->witness_script_len);
        clear_and_free(input->final_scriptsig, input->final_scriptsig_len);
        wally_tx_witness_stack_free(input->final_witness);
        wally_map_clear(&input->keypaths);
        wally_map_clear(&input->signatures);
        wally_map_clear(&input->unknowns);
        clear_and_free(input->previous_txid, input->previous_txid_len);

#ifdef BUILD_ELEMENTS
        clear_and_free(input->issuance_amount_commitment, input->issuance_amount_commitment_len);
        clear_and_free(input->issuance_amount_rangeproof, input->issuance_amount_rangeproof_len);
        clear_and_free(input->issuance_amount_blind_proof, input->issuance_amount_blind_proof_len);
        clear_and_free(input->blinding_nonce, input->blinding_nonce_len);
        clear_and_free(input->entropy, input->entropy_len);
        clear_and_free(input->inflation_keys_commitment, input->inflation_keys_commitment_len);
        clear_and_free(input->inflation_keys_rangeproof, input->inflation_keys_rangeproof_len);
        clear_and_free(input->inflation_keys_blind_proof, input->inflation_keys_blind_proof_len);
        wally_tx_free(input->pegin_tx);
        clear_and_free(input->txoutproof, input->txoutproof_len);
        clear_and_free(input->genesis_blockhash, input->genesis_blockhash_len);
        clear_and_free(input->claim_script, input->claim_script_len);
        wally_tx_witness_stack_free(input->pegin_witness);
        clear_and_free(input->utxo_rangeproof, input->utxo_rangeproof_len);
#endif /* BUILD_ELEMENTS */

        wally_clear(input, sizeof(*input));
        if (free_parent)
            wally_free(input);
    }
    return WALLY_OK;
}

SET_BYTES(wally_psbt_output, redeem_script)
SET_BYTES(wally_psbt_output, witness_script)
SET_MAP(wally_psbt_output, keypath, wally_ec_public_key_verify)
ADD_KEYPATH(wally_psbt_output)
SET_MAP(wally_psbt_output, unknown, NULL)

int wally_psbt_output_set_amount(struct wally_psbt_output *output, uint64_t amount)
{
    if (!output || output->psbt_version == 0)
        return WALLY_EINVAL;
    output->amount = amount;
    output->has_amount = 1u;
    return WALLY_OK;
}

int wally_psbt_output_set_script(struct wally_psbt_output *output, const unsigned char *bytes, size_t len)
{
    if (!output || output->psbt_version == 0)
        return WALLY_EINVAL;
    return replace_bytes(bytes, len,
                         &output->script, &output->script_len);
}

#ifdef BUILD_ELEMENTS
int wally_psbt_output_set_blinding_pubkey(struct wally_psbt_output *output,
                                          const unsigned char *pub_key,
                                          size_t pub_key_len)
{
    int ret;
    if (!output || BYTES_INVALID(pub_key, pub_key_len))
        return WALLY_EINVAL;
    if (pub_key &&
        (ret = wally_ec_public_key_verify(pub_key, pub_key_len)) != WALLY_OK)
        return ret;
    return replace_bytes(pub_key, pub_key_len,
                         &output->blinding_pubkey, &output->blinding_pubkey_len);
}

SET_BYTES_N(wally_psbt_output, value_commitment, ASSET_COMMITMENT_LEN)
SET_BYTES_N(wally_psbt_output, asset_commitment, ASSET_COMMITMENT_LEN)
SET_BYTES_N(wally_psbt_output, nonce, WALLY_TX_ASSET_CT_NONCE_LEN)
SET_BYTES(wally_psbt_output, rangeproof)
SET_BYTES(wally_psbt_output, surjectionproof)
#endif/* BUILD_ELEMENTS */

static int psbt_output_free(struct wally_psbt_output *output, bool free_parent)
{
    if (output) {
        clear_and_free(output->redeem_script, output->redeem_script_len);
        clear_and_free(output->witness_script, output->witness_script_len);
        wally_map_clear(&output->keypaths);
        wally_map_clear(&output->unknowns);
        clear_and_free(output->script, output->script_len);

#ifdef BUILD_ELEMENTS
        clear_and_free(output->blinding_pubkey, output->blinding_pubkey_len);
        clear_and_free(output->value_commitment, output->value_commitment_len);
        clear_and_free(output->asset_commitment, output->asset_commitment_len);
        clear_and_free(output->nonce, output->nonce_len);
        clear_and_free(output->rangeproof, output->rangeproof_len);
        clear_and_free(output->surjectionproof, output->surjectionproof_len);
#endif /* BUILD_ELEMENTS */

        wally_clear(output, sizeof(*output));
        if (free_parent)
            wally_free(output);
    }
    return WALLY_OK;
}

int wally_psbt_init_alloc(uint32_t version, size_t inputs_allocation_len,
                          size_t outputs_allocation_len,
                          size_t global_unknowns_allocation_len,
                          struct wally_psbt **output)
{
    struct wally_psbt *result;
    int ret;

    TX_CHECK_OUTPUT;
    if (version != 0 && version != 2)
        return WALLY_EINVAL; /* Only versions 0 and 2 are specified/supported */
    TX_OUTPUT_ALLOC(struct wally_psbt);

    if (inputs_allocation_len)
        result->inputs = wally_calloc(inputs_allocation_len * sizeof(struct wally_psbt_input));
    if (outputs_allocation_len)
        result->outputs = wally_calloc(outputs_allocation_len * sizeof(struct wally_psbt_output));

    ret = wally_map_init(global_unknowns_allocation_len, &result->unknowns);

    if (ret != WALLY_OK ||
        (inputs_allocation_len && !result->inputs) || (outputs_allocation_len && !result->outputs)) {
        wally_psbt_free(result);
        return ret != WALLY_OK ? ret : WALLY_ENOMEM;
    }

    result->version = version;
    result->tx_version = 2;
    result->has_tx_version = 1u;
    memcpy(result->magic, PSBT_MAGIC, sizeof(PSBT_MAGIC));
    result->inputs_allocation_len = inputs_allocation_len;
    result->outputs_allocation_len = outputs_allocation_len;
    result->tx = NULL;
    return WALLY_OK;
}

#ifdef BUILD_ELEMENTS
int wally_psbt_elements_init_alloc(
    uint32_t version,
    size_t inputs_allocation_len,
    size_t outputs_allocation_len,
    size_t global_unknowns_allocation_len,
    struct wally_psbt **output)
{
    int ret = wally_psbt_init_alloc(version, inputs_allocation_len,
                                    outputs_allocation_len,
                                    global_unknowns_allocation_len, output);
    if (ret == WALLY_OK)
        memcpy((*output)->magic, PSET_MAGIC, sizeof(PSET_MAGIC));

    return ret;
}
#endif /* BUILD_ELEMENTS */

int wally_psbt_free(struct wally_psbt *psbt)
{
    size_t i;
    if (psbt) {
        wally_tx_free(psbt->tx);
        for (i = 0; i < psbt->num_inputs; ++i)
            psbt_input_free(&psbt->inputs[i], false);

        wally_free(psbt->inputs);
        for (i = 0; i < psbt->num_outputs; ++i)
            psbt_output_free(&psbt->outputs[i], false);

        wally_free(psbt->outputs);
        wally_map_clear(&psbt->unknowns);

#ifdef BUILD_ELEMENTS
        clear_and_free(psbt->scalar, psbt->scalar_len);
#endif /* BUILD ELEMENTS */
        clear_and_free(psbt, sizeof(*psbt));
    }
    return WALLY_OK;
}

int wally_psbt_get_global_tx_alloc(const struct wally_psbt *psbt, struct wally_tx **output)
{
    TX_CHECK_OUTPUT;
    if (!psbt)
        return WALLY_EINVAL;
    if (!psbt->tx)
        return WALLY_OK; /* Return a NULL tx if not present */
    return tx_clone_alloc(psbt->tx, output);
}

#define PSBT_GET(name) \
    int wally_psbt_get_ ## name(const struct wally_psbt *psbt, size_t *written) { \
        if (written) \
            *written = 0; \
        if (!psbt || !written) \
            return WALLY_EINVAL; \
        *written = psbt->name; \
        return WALLY_OK; \
    }

PSBT_GET(version)
PSBT_GET(num_inputs)
PSBT_GET(num_outputs)
PSBT_GET(tx_version)
PSBT_GET(fallback_locktime)
PSBT_GET(tx_modifiable_flags)

int wally_psbt_set_tx_version(struct wally_psbt *psbt, uint32_t tx_version) {
    if(!psbt || psbt->version == 0) return WALLY_EINVAL;
    psbt->tx_version = tx_version;
    psbt->has_tx_version = 1u;
    return WALLY_OK;
}

int wally_psbt_set_fallback_locktime(struct wally_psbt *psbt, uint32_t locktime) {
    if(!psbt || psbt->version == 0) return WALLY_EINVAL;
    psbt->fallback_locktime = locktime;
    psbt->has_fallback_locktime = 1u;
    return WALLY_OK;
}

int wally_psbt_clear_fallback_locktime(struct wally_psbt *psbt) {
    if(!psbt || psbt->version == 0) return WALLY_EINVAL;
    psbt->fallback_locktime = 0;
    psbt->has_fallback_locktime = 0u;
    return WALLY_OK;
}

int wally_psbt_set_tx_modifiable_flags(struct wally_psbt *psbt, uint8_t tx_modifiable_flags) {
    if(!psbt || psbt->version == 0) return WALLY_EINVAL;
    psbt->tx_modifiable_flags = tx_modifiable_flags;
    return WALLY_OK;
}

int wally_psbt_is_finalized(const struct wally_psbt *psbt,
                            size_t *written)
{
    size_t i;

    if (written)
        *written = 0;
    if (!psbt || !written)
        return WALLY_EINVAL;

    for (i = 0; i < psbt->num_inputs; ++i) {
        if (!psbt->inputs[i].final_scriptsig && !psbt->inputs[i].final_witness)
            return WALLY_OK; /* Non fully finalized */
    }
    /* We are finalized if we have inputs since they are all finalized */
    *written = psbt->num_inputs > 0 ?  1 : 0;
    return WALLY_OK;
}

static int psbt_set_global_tx(struct wally_psbt *psbt, struct wally_tx *tx, bool do_clone)
{
    struct wally_tx *new_tx = NULL;
    struct wally_psbt_input *new_inputs = NULL;
    struct wally_psbt_output *new_outputs = NULL;
    size_t i;
    int ret;

    if (!psbt || psbt->tx || psbt->num_inputs || psbt->num_outputs || !tx)
        return WALLY_EINVAL; /* PSBT must be completely empty */

    for (i = 0; i < tx->num_inputs; ++i)
        if (tx->inputs[i].script || tx->inputs[i].witness)
            return WALLY_EINVAL; /* tx mustn't have scriptSigs or witnesses */

    if (do_clone && (ret = tx_clone_alloc(tx, &new_tx)) != WALLY_OK)
        return ret;

    if (psbt->inputs_allocation_len < tx->num_inputs)
        new_inputs = wally_calloc(tx->num_inputs * sizeof(struct wally_psbt_input));

    if (psbt->outputs_allocation_len < tx->num_outputs)
        new_outputs = wally_calloc(tx->num_outputs * sizeof(struct wally_psbt_output));

    if ((psbt->inputs_allocation_len < tx->num_inputs && !new_inputs) ||
        (psbt->outputs_allocation_len < tx->num_outputs && !new_outputs)) {
        wally_free(new_inputs);
        wally_free(new_outputs);
        wally_tx_free(new_tx);
        return WALLY_ENOMEM;
    }

    if (new_inputs) {
        wally_free(psbt->inputs);
        psbt->inputs = new_inputs;
        psbt->inputs_allocation_len = tx->num_inputs;
    }
    if (new_outputs) {
        wally_free(psbt->outputs);
        psbt->outputs = new_outputs;
        psbt->outputs_allocation_len = tx->num_outputs;
    }
    psbt->num_inputs = tx->num_inputs;
    psbt->num_outputs = tx->num_outputs;
    psbt->tx = do_clone ? new_tx : tx;
    return WALLY_OK;
}

int wally_psbt_set_global_tx(struct wally_psbt *psbt, const struct wally_tx *tx)
{
    return psbt_set_global_tx(psbt, (struct wally_tx *)tx, true);
}

#ifdef BUILD_ELEMENTS

int wally_psbt_get_scalar(const struct wally_psbt *psbt, unsigned char *bytes_out, size_t len, size_t *written) {
    if (written) *written = 0;
    if (!psbt || !written) return WALLY_EINVAL;
    *written = 32;
    if (32 <= len)
        memcpy(bytes_out, psbt->scalar, 32);
    return WALLY_OK;
}

int wally_psbt_get_scalar_len(const struct wally_psbt *psbt, size_t *written) {
    if (written) *written = 0;
    if (!psbt || !written) return WALLY_EINVAL;
    *written = psbt->scalar_len;
    return WALLY_OK;
}

PSBT_GET(elements_tx_modifiable_flags)

int wally_psbt_set_elements_tx_modifiable_flags(struct wally_psbt *psbt, uint8_t elements_tx_modifiable_flags) {
    if(!psbt || psbt->version == 0) return WALLY_EINVAL;
    psbt->elements_tx_modifiable_flags = elements_tx_modifiable_flags;
    return WALLY_OK;
}

int wally_psbt_set_scalar(struct wally_psbt *psbt, unsigned char *scalar, size_t scalar_len) {
    if(!psbt || psbt->version == 0) return WALLY_EINVAL;
    return replace_bytes(scalar, scalar_len, &psbt->scalar, &psbt->scalar_len);
}

#endif /* BUILD_ELEMENTS */

int wally_psbt_add_input_at(struct wally_psbt *psbt,
                            uint32_t index, uint32_t flags,
                            const struct wally_tx_input *input)
{
    struct wally_tx_input tmp;
    int ret = WALLY_OK;

    if (!psbt || ((psbt->version == 0) && (!psbt->tx || psbt->tx->num_inputs != psbt->num_inputs)) ||
        (flags & ~WALLY_PSBT_FLAG_NON_FINAL) ||
        index > psbt->num_inputs || !input)
        return WALLY_EINVAL;

    memcpy(&tmp, input, sizeof(tmp));
    if (flags & WALLY_PSBT_FLAG_NON_FINAL) {
        /* Clear scriptSig and witness before adding */
        tmp.script = NULL;
        tmp.script_len = 0;
        tmp.witness = NULL;
    }

    if (psbt->tx) {
        ret = wally_tx_add_input_at(psbt->tx, index, &tmp);
        wally_clear(&tmp, sizeof(tmp));
    }

    if (ret == WALLY_OK) {
        if (psbt->num_inputs >= psbt->inputs_allocation_len) {
            ret = array_grow((void *)&psbt->inputs, psbt->num_inputs,
                             &psbt->inputs_allocation_len,
                             sizeof(struct wally_psbt_input));
            if (ret != WALLY_OK)
                goto cleanup;
        }

        memmove(psbt->inputs + index + 1, psbt->inputs + index,
                (psbt->num_inputs - index) * sizeof(struct wally_psbt_input));
        wally_clear(psbt->inputs + index, sizeof(struct wally_psbt_input));

        if (psbt->version >= 2) {
            if((ret = replace_bytes(input->txhash, WALLY_TXHASH_LEN, &psbt->inputs[index].previous_txid, &psbt->inputs[index].previous_txid_len)) != WALLY_OK)
                goto cleanup;

            psbt->inputs[index].previous_txid_len = WALLY_TXHASH_LEN;
            psbt->inputs[index].output_index = input->index;
            psbt->inputs[index].psbt_version = psbt->version;
            psbt->inputs[index].sequence = input->sequence;
            psbt->inputs[index].has_sequence = 1u;
#ifdef BUILD_ELEMENTS
            if (input->issuance_amount) {
                if (input->issuance_amount_len == WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN && input->issuance_amount[0] == 0x01) {
                    if ((ret = wally_tx_confidential_value_to_satoshi(input->issuance_amount, input->issuance_amount_len, &psbt->inputs[index].issuance_amount)) != WALLY_OK)
                        goto cleanup;
                    psbt->inputs[index].has_issuance_amount = 1u;
                }
                else if(input->issuance_amount_len == WALLY_TX_ASSET_CT_VALUE_LEN && (input->issuance_amount[0] == 0x8 || input->issuance_amount[0] == 0x09)) {
                    if ((ret = replace_bytes(input->issuance_amount + 1, WALLY_TX_ASSET_CT_VALUE_LEN - 1,
                                             &psbt->inputs[index].issuance_amount_commitment, &psbt->inputs[index].issuance_amount_commitment_len)) != WALLY_OK)
                        goto cleanup;
                }
            }
            if ((ret = replace_bytes(input->issuance_amount_rangeproof, input->issuance_amount_rangeproof_len, &psbt->inputs[index].issuance_amount_rangeproof, &psbt->inputs[index].issuance_amount_rangeproof_len)) != WALLY_OK)
                goto cleanup;
            if ((ret = replace_bytes(input->inflation_keys_rangeproof, input->inflation_keys_rangeproof_len, &psbt->inputs[index].inflation_keys_rangeproof, &psbt->inputs[index].inflation_keys_rangeproof_len)) != WALLY_OK)
                goto cleanup;
            if (input->inflation_keys) {
                if (input->inflation_keys_len == WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN && input->inflation_keys[0] == 0x01) {
                    wally_tx_confidential_value_to_satoshi(input->inflation_keys, input->inflation_keys_len, &psbt->inputs[index].inflation_keys);
                    psbt->inputs[index].has_inflation_keys = 1u;
                }
                else if(input->inflation_keys_len == WALLY_TX_ASSET_CT_VALUE_LEN && (input->inflation_keys[0] == 0x8 || input->inflation_keys[0] == 0x09)) {
                    if ((ret = replace_bytes(input->inflation_keys + 1, WALLY_TX_ASSET_CT_VALUE_LEN - 1, &psbt->inputs[index].inflation_keys_commitment, &psbt->inputs[index].inflation_keys_commitment_len)) != WALLY_OK)
                        goto cleanup;
                }
            }
            if (input->features & WALLY_TX_IS_ISSUANCE) {
                if ((ret = replace_bytes(input->blinding_nonce, SHA256_LEN, &psbt->inputs[index].blinding_nonce, &psbt->inputs[index].blinding_nonce_len)) != WALLY_OK)
                    goto cleanup;
                if ((ret = replace_bytes(input->entropy, SHA256_LEN, &psbt->inputs[index].entropy, &psbt->inputs[index].entropy_len)) != WALLY_OK)
                    goto cleanup;
            }
            if (input->features & WALLY_TX_IS_PEGIN) {
                const unsigned char *cursor = psbt->inputs[index].pegin_witness->items[0].witness;
                size_t max = sizeof(psbt->inputs[index].pegin_amount);
                if ((ret = wally_tx_witness_stack_clone_alloc(input->pegin_witness, &psbt->inputs[index].pegin_witness)) != WALLY_OK)
                    goto cleanup;

                if (psbt->inputs[index].pegin_witness->num_items != 6) {
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }
                if (psbt->inputs[index].pegin_witness->items[0].witness_len != 8) {
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }
                psbt->inputs[index].pegin_amount = pull_le64(&cursor, &max);

                if (psbt->inputs[index].pegin_witness->items[2].witness_len != WALLY_TXHASH_LEN) {
                    ret = WALLY_EINVAL;
                    goto cleanup;
                }
                if ((ret = replace_bytes(psbt->inputs[index].pegin_witness->items[2].witness, psbt->inputs[index].pegin_witness->items[2].witness_len,
                                         &psbt->inputs[index].genesis_blockhash, &psbt->inputs[index].genesis_blockhash_len)) != WALLY_OK)
                    goto cleanup;
                if ((ret = replace_bytes(psbt->inputs[index].pegin_witness->items[3].witness, psbt->inputs[index].pegin_witness->items[3].witness_len,
                                         &psbt->inputs[index].claim_script, &psbt->inputs[index].claim_script_len)) != WALLY_OK)
                    goto cleanup;
                if ((ret = wally_tx_from_bytes(psbt->inputs[index].pegin_witness->items[4].witness, psbt->inputs[index].pegin_witness->items[4].witness_len, 0, &psbt->inputs[index].pegin_tx)) != WALLY_OK)
                    goto cleanup;
                if ((ret = replace_bytes(psbt->inputs[index].pegin_witness->items[5].witness, psbt->inputs[index].pegin_witness->items[5].witness_len,
                                         &psbt->inputs[index].txoutproof, &psbt->inputs[index].txoutproof_len)) != WALLY_OK)
                    goto cleanup;
            }
#endif /* BUILD_ELEMENTS */
        }
        psbt->num_inputs += 1;
    }
cleanup:
    if (ret != WALLY_OK)
        wally_psbt_remove_input(psbt, index);
    return ret;
}

int wally_psbt_remove_input(struct wally_psbt *psbt, uint32_t index)
{
    int ret = WALLY_OK;

    if (!psbt || (psbt->version == 0 && (!psbt->tx || psbt->tx->num_inputs != psbt->num_inputs)))
        ret = WALLY_EINVAL;
    else if (psbt->tx)
        ret = wally_tx_remove_input(psbt->tx, index);
    if (ret == WALLY_OK) {
        psbt_input_free(&psbt->inputs[index], false);
        memmove(psbt->inputs + index, psbt->inputs + index + 1,
                (psbt->num_inputs - index - 1) * sizeof(struct wally_psbt_input));
        psbt->num_inputs -= 1;
    }
    return ret;
}

int wally_psbt_add_output_at(struct wally_psbt *psbt,
                             uint32_t index, uint32_t flags,
                             const struct wally_tx_output *output)
{
    int ret = WALLY_OK;

    if (!psbt || (psbt->version == 0 && (!psbt->tx || psbt->tx->num_outputs != psbt->num_outputs)) ||
        flags || index > psbt->num_outputs || !output)
        return WALLY_EINVAL;

    if (psbt->tx)
        ret = wally_tx_add_output_at(psbt->tx, index, output);

    if (ret == WALLY_OK) {
        if (psbt->num_outputs >= psbt->outputs_allocation_len) {
            ret = array_grow((void *)&psbt->outputs, psbt->num_outputs,
                             &psbt->outputs_allocation_len,
                             sizeof(struct wally_psbt_output));
            if (ret != WALLY_OK) {
                wally_tx_remove_output(psbt->tx, index);
                return ret;
            }
        }

        memmove(psbt->outputs + index + 1, psbt->outputs + index,
                (psbt->num_outputs - index) * sizeof(struct wally_psbt_output));
        wally_clear(psbt->outputs + index, sizeof(struct wally_psbt_output));

        psbt->outputs[index].psbt_version = psbt->version;
        if (psbt->version >= 2) {
            if ((ret = replace_bytes(output->script, output->script_len, &psbt->outputs[index].script, &psbt->outputs[index].script_len)) != WALLY_OK) {
                wally_psbt_remove_output(psbt, index);
                return ret;
            }
            psbt->outputs[index].amount = output->satoshi;
            psbt->outputs[index].has_amount = 1u;
        }
        psbt->num_outputs += 1;
    }
    return ret;
}

int wally_psbt_remove_output(struct wally_psbt *psbt, uint32_t index)
{
    int ret = WALLY_OK;

    if (!psbt || (psbt->version == 0 && (!psbt->tx || psbt->tx->num_outputs != psbt->num_outputs)))
        ret = WALLY_EINVAL;
    else if (psbt->tx)
        ret = wally_tx_remove_output(psbt->tx, index);
    if (ret == WALLY_OK) {
        psbt_output_free(&psbt->outputs[index], false);
        memmove(psbt->outputs + index, psbt->outputs + index + 1,
                (psbt->num_outputs - index - 1) * sizeof(struct wally_psbt_output));
        psbt->num_outputs -= 1;
    }
    return ret;
}


/* Stricter version of pull_subfield_end which insists there's nothing left. */
static void subfield_nomore_end(const unsigned char **cursor, size_t *max,
                                const unsigned char *subcursor,
                                const size_t submax)
{
    if (submax) {
        pull_failed(cursor, max);
    } else {
        pull_subfield_end(cursor, max, subcursor, submax);
    }
}

/* The remainder of the key is a public key, the value is a signature */
static int pull_map(const unsigned char **cursor, size_t *max,
                    const unsigned char *key, size_t key_len,
                    struct wally_map *map_in,
                    int (*check_fn)(const unsigned char *key, size_t key_len))
{
    const unsigned char *val;
    size_t val_len;

    pull_subfield_end(cursor, max, key, key_len);

    val_len = pull_varlength(cursor, max);
    val = pull_skip(cursor, max, val_len);

    return map_add(map_in, key, key_len, val, val_len, false, check_fn, false);
}

/* Rewind cursor to prekey, and append unknown key/value to unknowns */
static int pull_unknown_key_value(const unsigned char **cursor, size_t *max,
                                  const unsigned char *pre_key,
                                  struct wally_map *unknowns)
{
    const unsigned char *key, *val;
    size_t key_len, val_len;

    /* If we've already failed, it's invalid */
    if (!*cursor)
        return WALLY_EINVAL;

    /* We have to unwind a bit, to get entire key again. */
    *max += (*cursor - pre_key);
    *cursor = pre_key;

    key_len = pull_varlength(cursor, max);
    key = pull_skip(cursor, max, key_len);
    val_len = pull_varlength(cursor, max);
    val = pull_skip(cursor, max, val_len);

    return map_add(unknowns, key, key_len, val, val_len, false, NULL, false);
}

#ifdef BUILD_ELEMENTS
static size_t push_elements_bytes_size(const struct wally_tx_output *out)
{
    size_t size = 0;
    size += out->asset_len == 0 ? 1 : out->asset_len;
    size += out->value_len == 0 ? 1 : out->value_len;
    size += out->nonce_len == 0 ? 1 : out->nonce_len;
    size += out->script_len == 0 ? 1 : out->script_len + 1;
    return size;
}

static void push_elements_bytes(unsigned char **cursor, size_t *max,
                                unsigned char *value, size_t val_len)
{
    unsigned char empty = 0;
    push_bytes(cursor, max, value ? value : &empty, value ? val_len : sizeof(empty));
}

static int pull_elements_confidential(const unsigned char **cursor, size_t *max,
                                      const unsigned char **value, size_t *val_len,
                                      size_t prefixA, size_t prefixB,
                                      size_t prefixed_size, size_t explicit_size)
{
    /* First byte is always the 'version' which tells you what the value is */
    const uint8_t type = peek_u8(cursor, max);
    size_t size;

    if (type == 0) {
        /* Empty, Pop off the type */
        pull_u8(cursor, max);
        *value = NULL;
        *val_len = 0;
        return WALLY_OK;
    }

    if (type == 1)
        size = explicit_size;
    else if (type == prefixA || type == prefixB)
        size = prefixed_size;
    else
        return WALLY_EINVAL;

    *value = pull_skip(cursor, max, size);
    if (!*cursor)
        return WALLY_EINVAL;
    *val_len = size;
    return WALLY_OK;
}

/* Either returns a 33-byte commitment to a confidential value, or
 * a 64-bit explicit value. */
static int pull_confidential_value(const unsigned char **cursor, size_t *max,
                                   const unsigned char **value, size_t *val_len)

{
    return pull_elements_confidential(cursor, max, value, val_len,
                                      WALLY_TX_ASSET_CT_VALUE_PREFIX_A, WALLY_TX_ASSET_CT_VALUE_PREFIX_B,
                                      WALLY_TX_ASSET_CT_VALUE_LEN, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN);
}

static int pull_confidential_asset(const unsigned char **cursor, size_t *max,
                                   const unsigned char **asset, size_t *asset_len)

{
    return pull_elements_confidential(cursor, max, asset, asset_len,
                                      WALLY_TX_ASSET_CT_ASSET_PREFIX_A, WALLY_TX_ASSET_CT_ASSET_PREFIX_B,
                                      WALLY_TX_ASSET_CT_ASSET_LEN, WALLY_TX_ASSET_CT_ASSET_LEN);
}

static int pull_nonce(const unsigned char **cursor, size_t *max,
                      const unsigned char **nonce, size_t *nonce_len)

{
    return pull_elements_confidential(cursor, max, nonce, nonce_len,
                                      WALLY_TX_ASSET_CT_NONCE_PREFIX_A, WALLY_TX_ASSET_CT_NONCE_PREFIX_B,
                                      WALLY_TX_ASSET_CT_NONCE_LEN, WALLY_TX_ASSET_CT_NONCE_LEN);
}

#endif /* BUILD_ELEMENTS */

static void fetch_varlength_ptr(const unsigned char **dst, size_t *len,
                                const unsigned char **cursor, size_t *max)
{
    *len = pull_varlength(cursor, max);
    *dst = pull_skip(cursor, max, *len);
}

/* Pull and set a variable length byte buffer */
#define PSBT_PULL_B(typ, name) \
    if (result->name) \
        return WALLY_EINVAL; /* Duplicate value */ \
    subfield_nomore_end(cursor, max, key, key_len); \
    fetch_varlength_ptr(&vl_p, &vl_len, cursor, max); \
    if (!vl_len) \
        result->name = wally_malloc(1); /* TODO: handle empty values more elegantly */ \
    else if ((ret = wally_psbt_ ## typ ## _set_ ## name(result, vl_p, vl_len)) != WALLY_OK) \
        return ret

static int pull_psbt_input(const unsigned char **cursor, size_t *max,
                           uint32_t flags, struct wally_psbt_input *result)
{
    int ret;
    size_t key_len, vl_len;
    const unsigned char *pre_key, *vl_p;
    bool found_output_index = false;

    /* Read key value pairs */
    pre_key = *cursor;
    while ((key_len = pull_varlength(cursor, max)) != 0) {
        const unsigned char *key, *val;
        size_t val_max;

        /* Start parsing key */
        pull_subfield_start(cursor, max, key_len, &key, &key_len);

        /* Process based on type */
        switch (pull_varint(&key, &key_len)) {
        case PSBT_IN_NON_WITNESS_UTXO: {
            if (result->utxo)
                return WALLY_EINVAL;     /* We already have a non witness utxo */

            subfield_nomore_end(cursor, max, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(cursor, max, pull_varint(cursor, max),
                                &val, &val_max);
            if ((ret = wally_tx_from_bytes(val, val_max, flags,
                                           &result->utxo)) != WALLY_OK)
                return ret;

            pull_subfield_end(cursor, max, val, val_max);
            break;
        }
        case PSBT_IN_WITNESS_UTXO: {
            uint64_t amount, script_len;
            const unsigned char *script;

            if (result->witness_utxo)
                return WALLY_EINVAL; /* Duplicate value */

            subfield_nomore_end(cursor, max, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(cursor, max, pull_varint(cursor, max),
                                &val, &val_max);
#ifdef BUILD_ELEMENTS
            if (flags & WALLY_TX_FLAG_USE_ELEMENTS) {
                const unsigned char *asset, *value, *nonce;
                size_t asset_len, value_len, nonce_len;
                if ((ret = pull_confidential_asset(&val, &val_max, &asset, &asset_len)) != WALLY_OK)
                    return ret;
                if ((ret = pull_confidential_value(&val, &val_max, &value, &value_len)) != WALLY_OK)
                    return ret;
                if ((ret = pull_nonce(&val, &val_max, &nonce, &nonce_len)) != WALLY_OK)
                    return ret;

                script_len = pull_varint(&val, &val_max);
                script = pull_skip(&val, &val_max, script_len);
                if (!script || !script_len)
                    return WALLY_EINVAL;

                ret = wally_tx_elements_output_init_alloc(script, script_len,
                                                          asset, asset_len,
                                                          value, value_len,
                                                          nonce, nonce_len,
                                                          NULL, 0, NULL, 0,
                                                          &result->witness_utxo);
                if (ret != WALLY_OK)
                    return ret;

                subfield_nomore_end(cursor, max, val, val_max);
                break;
            }
#endif /* BUILD_ELEMENTS */

            amount = pull_le64(&val, &val_max);
            script_len = pull_varint(&val, &val_max);
            script = pull_skip(&val, &val_max, script_len);
            if (!script || !script_len)
                return WALLY_EINVAL;
            ret = wally_tx_output_init_alloc(amount, script, script_len,
                                             &result->witness_utxo);
            if (ret != WALLY_OK)
                return ret;

            subfield_nomore_end(cursor, max, val, val_max);
            break;
        }
        case PSBT_IN_PARTIAL_SIG: {
            ret = pull_map(cursor, max, key, key_len, &result->signatures,
                           wally_ec_public_key_verify);
            if (ret != WALLY_OK)
                return ret;
            break;
        }
        case PSBT_IN_SIGHASH_TYPE: {
            if (result->sighash != 0)
                return WALLY_EINVAL; /* Duplicate value */

            subfield_nomore_end(cursor, max, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(cursor, max,
                                pull_varint(cursor, max),
                                &val, &val_max);
            result->sighash = pull_le32(&val, &val_max);
            subfield_nomore_end(cursor, max, val, val_max);
            break;
        }
        case PSBT_IN_REDEEM_SCRIPT:
            PSBT_PULL_B(input, redeem_script);
            break;
        case PSBT_IN_WITNESS_SCRIPT:
            PSBT_PULL_B(input, witness_script);
            break;
        case PSBT_IN_BIP32_DERIVATION:
            if ((ret = pull_map(cursor, max, key, key_len, &result->keypaths,
                                wally_ec_public_key_verify)) != WALLY_OK)
                return ret;
            break;
        case PSBT_IN_FINAL_SCRIPTSIG:
            PSBT_PULL_B(input, final_scriptsig);
            break;
        case PSBT_IN_FINAL_SCRIPTWITNESS: {
            uint64_t num_witnesses;
            size_t i;
            if (result->final_witness)
                return WALLY_EINVAL; /* Duplicate value */
            subfield_nomore_end(cursor, max, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(cursor, max,
                                pull_varint(cursor, max),
                                &val, &val_max);
            num_witnesses = pull_varint(&val, &val_max);
            ret = wally_tx_witness_stack_init_alloc(num_witnesses, &result->final_witness);
            if (ret != WALLY_OK)
                return ret;

            for (i = 0; i < num_witnesses; ++i) {
                uint64_t witness_len = pull_varint(&val, &val_max);
                ret = wally_tx_witness_stack_set(result->final_witness, i,
                                                 pull_skip(&val, &val_max, witness_len),
                                                 witness_len);
                if (ret != WALLY_OK)
                    return ret;
            }
            subfield_nomore_end(cursor, max, val, val_max);
            break;
        }
        case PSBT_IN_PREVIOUS_TXID: {
            if (result->psbt_version == 0 || result->previous_txid)
                return WALLY_EINVAL;

            PSBT_PULL_B(input, previous_txid);
            break;
        }
        case PSBT_IN_OUTPUT_INDEX: {
            if (result->psbt_version == 0 || found_output_index)
                return WALLY_EINVAL;

            found_output_index = true;
            subfield_nomore_end(cursor, max, key, key_len);
            pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_max);

            if (val_max != sizeof(result->output_index))
                return WALLY_EINVAL;

            result->output_index = pull_le32(&val, &val_max);
            pull_subfield_end(cursor, max, val, val_max);

            break;
        }
        case PSBT_IN_SEQUENCE: {
            if (result->psbt_version == 0 || result->has_sequence)
                return WALLY_EINVAL;

            subfield_nomore_end(cursor, max, key, key_len);
            pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_max);

            if (val_max != sizeof(result->sequence))
                return WALLY_EINVAL;

            result->sequence = pull_le32(&val, &val_max);
            result->has_sequence = 1u;
            pull_subfield_end(cursor, max, val, val_max);

            break;
        }
        case PSBT_IN_REQUIRED_TIME_LOCKTIME: {
            if (result->psbt_version == 0 || result->has_required_locktime)
                return WALLY_EINVAL;

            subfield_nomore_end(cursor, max, key, key_len);
            pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_max);

            if (val_max != sizeof(result->required_locktime))
                return WALLY_EINVAL;

            result->required_locktime = pull_le32(&val, &val_max);
            if (result->required_locktime < PSBT_LOCKTIME_MIN_TIMESTAMP)
                return WALLY_EINVAL;
            result->has_required_locktime = 1u;
            pull_subfield_end(cursor, max, val, val_max);

            break;
        }
        case PSBT_IN_REQUIRED_HEIGHT_LOCKTIME: {
            if (result->psbt_version == 0 || result->has_required_locktime)
                return WALLY_EINVAL;

            subfield_nomore_end(cursor, max, key, key_len);
            pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_max);

            if (val_max != sizeof(result->required_locktime))
                return WALLY_EINVAL;

            result->required_locktime = pull_le32(&val, &val_max);
            if (result->required_locktime >= PSBT_LOCKTIME_MIN_TIMESTAMP)
                return WALLY_EINVAL;
            result->has_required_locktime = 1u;
            pull_subfield_end(cursor, max, val, val_max);

            break;
        }

#ifdef BUILD_ELEMENTS
        case PSBT_PROPRIETARY_TYPE: {
            const uint64_t id_len = pull_varlength(&key, &key_len);

            if (!is_elements_prefix(key, id_len))
                goto unknown_type;

            /* Skip the elements_id prefix */
            pull_skip(&key, &key_len, sizeof(PSET_KEY_PREFIX));

            switch (pull_varint(&key, &key_len)) {

            case PSBT_ELEMENTS_IN_ISSUANCE_VALUE: {
                if (result->has_issuance_amount)
                    return WALLY_EINVAL;
                subfield_nomore_end(cursor, max, key, key_len);
                pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_max);

                if (val_max != sizeof(result->issuance_amount))
                    return WALLY_EINVAL;

                result->issuance_amount = pull_le64(&val, &val_max);
                result->has_issuance_amount = 1u;
                pull_subfield_end(cursor, max, val, val_max);
                break;
            }
            case PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT: {
                PSBT_PULL_B(input, issuance_amount_commitment);
                break;
            }
            case PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF: {
                PSBT_PULL_B(input, issuance_amount_rangeproof);
                break;
            }
            case PSBT_ELEMENTS_IN_ISSUANCE_KEYS_RANGEPROOF: {
                PSBT_PULL_B(input, inflation_keys_rangeproof);
                break;
            }
            case PSBT_ELEMENTS_IN_PEG_IN_TX: {
                if (result->pegin_tx)
                    return WALLY_EINVAL; /* Duplicate value */

                subfield_nomore_end(cursor, max, key, key_len);

                /* Start parsing the value field. */
                pull_subfield_start(cursor, max,
                                    pull_varint(cursor, max),
                                    &val, &val_max);

                //TODO: We don't know if the parent chain is elements or not. We will assume parent chain is not an Elements tx.
                ret = wally_tx_from_bytes(val, val_max, 0, &result->pegin_tx);
                if (ret != WALLY_OK)
                    return ret;

                pull_subfield_end(cursor, max, val, val_max);
                break;
            }
            case PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF:
                PSBT_PULL_B(input, txoutproof);
                break;
            case PSBT_ELEMENTS_IN_PEG_IN_GENESIS:
                PSBT_PULL_B(input, genesis_blockhash);
                break;
            case PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT:
                PSBT_PULL_B(input, claim_script);
                break;
            case PSBT_ELEMENTS_IN_PEG_IN_VALUE: {
                if (result->has_pegin_amount)
                    return WALLY_EINVAL;
                subfield_nomore_end(cursor, max, key, key_len);
                pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_max);

                if (val_max != sizeof(result->pegin_amount))
                    return WALLY_EINVAL;

                result->pegin_amount = pull_le64(&val, &val_max);
                result->has_pegin_amount = 1u;
                pull_subfield_end(cursor, max, val, val_max);
                break;
            }
            case PSBT_ELEMENTS_IN_PEG_IN_WITNESS: {
                uint64_t num_witnesses;
                size_t i;
                if (result->pegin_witness)
                    return WALLY_EINVAL; /* Duplicate value */
                subfield_nomore_end(cursor, max, key, key_len);

                /* Start parsing the value field. */
                pull_subfield_start(cursor, max,
                                    pull_varint(cursor, max),
                                    &val, &val_max);
                num_witnesses = pull_varint(&val, &val_max);
                ret = wally_tx_witness_stack_init_alloc(num_witnesses, &result->pegin_witness);
                if (ret != WALLY_OK)
                    return ret;

                for (i = 0; i < num_witnesses; ++i) {
                    uint64_t witness_len = pull_varint(&val, &val_max);
                    ret = wally_tx_witness_stack_set(result->pegin_witness, i,
                                                     pull_skip(&val, &val_max, witness_len),
                                                     witness_len);
                    if (ret != WALLY_OK)
                        return ret;
                }
                subfield_nomore_end(cursor, max, val, val_max);
                break;
            }
            case PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS: {
                if (result->has_inflation_keys)
                    return WALLY_EINVAL;
                subfield_nomore_end(cursor, max, key, key_len);
                pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_max);

                if (val_max != sizeof(result->inflation_keys))
                    return WALLY_EINVAL;

                result->inflation_keys = pull_le64(&val, &val_max);
                result->has_inflation_keys = 1u;
                pull_subfield_end(cursor, max, val, val_max);
                break;
            }
            case PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT: {
                PSBT_PULL_B(input, inflation_keys_commitment);
                break;
            }
            case PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE: {
                PSBT_PULL_B(input, blinding_nonce);
                break;
            }
            case PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY: {
                PSBT_PULL_B(input, entropy);
                break;
            }
            case PSBT_ELEMENTS_IN_UTXO_RANGEPROOF:
                PSBT_PULL_B(input, utxo_rangeproof);
                break;
            case PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF: {
                PSBT_PULL_B(input, issuance_amount_blind_proof);
                break;
            }
            case PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF: {
                PSBT_PULL_B(input, inflation_keys_blind_proof);
                break;
            }
            default:
                goto unknown_type;
            }
            break;
        }
#endif /* BUILD_ELEMENTS */
        default: {
unknown_type:
            /* Unknown case without elements or for unknown proprietary types */
            ret = pull_unknown_key_value(cursor, max, pre_key, &result->unknowns);
            if (ret != WALLY_OK)
                return ret;
            break;
        }
        }
        pre_key = *cursor;
    }

    if (result->psbt_version >= 2 && (!result->previous_txid || !found_output_index))
        return WALLY_EINVAL;
#ifdef BUILD_ELEMENTS
    if (result->has_issuance_amount && result->issuance_amount_commitment && !result->issuance_amount_blind_proof)
        return WALLY_EINVAL;
    if (result->issuance_amount_blind_proof && !result->issuance_amount_commitment)
        return WALLY_EINVAL;
    if (result->has_inflation_keys && result->inflation_keys_commitment && !result->inflation_keys_blind_proof)
        return WALLY_EINVAL;
    if (result->inflation_keys_blind_proof && !result->inflation_keys_commitment)
        return WALLY_EINVAL;
#endif /* BUILD_ELEMENTS */
    return WALLY_OK;
}

static int pull_psbt_output(const unsigned char **cursor, size_t *max,
                            struct wally_psbt_output *result)
{
    int ret;
    size_t key_len, vl_len;
    const unsigned char *pre_key, *vl_p;

    /* Read key value */
    pre_key = *cursor;
    while ((key_len = pull_varlength(cursor, max)) != 0) {
        const unsigned char *key, *val;
        size_t val_max;

        /* Start parsing key */
        pull_subfield_start(cursor, max, key_len, &key, &key_len);

        /* Process based on type */
        switch (pull_varint(&key, &key_len)) {
        case PSBT_OUT_REDEEM_SCRIPT:
            PSBT_PULL_B(output, redeem_script);
            break;
        case PSBT_OUT_WITNESS_SCRIPT:
            PSBT_PULL_B(output, witness_script);
            break;
        case PSBT_OUT_BIP32_DERIVATION:
            if ((ret = pull_map(cursor, max, key, key_len, &result->keypaths,
                                wally_ec_public_key_verify)) != WALLY_OK)
                return ret;
            break;
        case PSBT_OUT_AMOUNT:
            if(result->psbt_version == 0)
                return WALLY_EINVAL;
            subfield_nomore_end(cursor, max, key, key_len);
            pull_subfield_start(cursor, max, pull_varint(cursor, max), &val, &val_max);

            if (val_max != sizeof(result->amount))
                return WALLY_EINVAL;

            result->amount = pull_le64(&val, &val_max);
            result->has_amount = 1u;
            pull_subfield_end(cursor, max, val, val_max);
            break;
        case PSBT_OUT_SCRIPT:
            PSBT_PULL_B(output, script);
            break;
#ifdef BUILD_ELEMENTS
        case PSBT_PROPRIETARY_TYPE: {
            const uint64_t id_len = pull_varlength(&key, &key_len);

            if (!is_elements_prefix(key, id_len))
                goto unknown_type;

            /* Skip the elements_id prefix */
            pull_skip(&key, &key_len, sizeof(PSET_KEY_PREFIX));

            switch (pull_varint(&key, &key_len)) {
            case PSBT_ELEMENTS_OUT_VALUE_COMMITMENT:
                PSBT_PULL_B(output, value_commitment);
                break;
            case PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF:
                PSBT_PULL_B(output, rangeproof);
                break;
            case PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF:
                PSBT_PULL_B(output, surjectionproof);
                break;
            case PSBT_ELEMENTS_OUT_BLINDING_PUBKEY:
                PSBT_PULL_B(output, blinding_pubkey);
                break;
            case PSBT_ELEMENTS_OUT_ECDH_PUBKEY:
                PSBT_PULL_B(output, nonce);
                break;
            default:
                goto unknown_type;
            }
            break;
        }
#endif /* BUILD_ELEMENTS */
        default: {
unknown_type:
            /* Unknown case without elements or for unknown proprietary types */
            ret = pull_unknown_key_value(cursor, max, pre_key, &result->unknowns);
            if (ret != WALLY_OK)
                return ret;
            break;
        }
        }
        pre_key = *cursor;
    }

    if (result->psbt_version >= 2 && (!result->has_amount || !result->script))
        return WALLY_EINVAL;

    return WALLY_OK;
}

int wally_psbt_from_bytes(const unsigned char *bytes, size_t len,
                          struct wally_psbt **output)
{
    const unsigned char *magic, *pre_key;
    int ret;
    size_t i, key_len, input_count = 0, output_count = 0, is_elements;
    struct wally_psbt *result = NULL;
    uint32_t flags = 0, pre144flag = WALLY_TX_FLAG_PRE_BIP144;
    bool found_input_count = false, found_output_count = false,
         found_tx_version = false, found_fallback_locktime = false,
         found_tx_modifiable_flags = false;

    TX_CHECK_OUTPUT;

    magic = pull_skip(&bytes, &len, sizeof(PSBT_MAGIC));
    if (!magic) {
        ret = WALLY_EINVAL;  /* Not enough bytes */
        goto fail;
    }
    if (memcmp(magic, PSBT_MAGIC, sizeof(PSBT_MAGIC)) != 0 ) {
#ifdef BUILD_ELEMENTS
        if (memcmp(magic, PSET_MAGIC, sizeof(PSET_MAGIC)) != 0) {
            ret = WALLY_EINVAL;  /* Invalid Magic */
            goto fail;
        }
        flags |= WALLY_TX_FLAG_USE_ELEMENTS;
        pre144flag = 0;
#else
        ret = WALLY_EINVAL;  /* Invalid Magic */
        goto fail;
#endif /* BUILD_ELEMENTS */
    }

    /* Make the wally_psbt */
    if ((ret = wally_psbt_init_alloc(0, 0, 0, 8, &result)) != WALLY_OK)
        goto fail;

    /* Set the magic */
    memcpy(result->magic, magic, sizeof(PSBT_MAGIC));

    if ((ret = wally_psbt_is_elements(result, &is_elements)) != WALLY_OK)
        goto fail;

    /* Read globals first */
    pre_key = bytes;
    while ((key_len = pull_varlength(&bytes, &len)) != 0) {
        const unsigned char *key, *val;
        size_t val_max;

        /* Start parsing key */
        pull_subfield_start(&bytes, &len, key_len, &key, &key_len);

        /* Process based on type */
        switch (pull_varint(&key, &key_len)) {
        case PSBT_GLOBAL_UNSIGNED_TX: {
            struct wally_tx *tx;

            subfield_nomore_end(&bytes, &len, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(&bytes, &len,
                                pull_varint(&bytes, &len),
                                &val, &val_max);
            ret = wally_tx_from_bytes(val, val_max, flags | pre144flag, &tx);
            if (ret == WALLY_OK) {
                ret = psbt_set_global_tx(result, tx, false);
                if (ret != WALLY_OK)
                    wally_tx_free(tx);
            }
            if (ret != WALLY_OK)
                goto fail;
            pull_subfield_end(&bytes, &len, val, val_max);
            break;
        }
        case PSBT_GLOBAL_VERSION: {
            if (result->version > 0) {
                ret = WALLY_EINVAL;    /* Version already provided */
                goto fail;
            }
            subfield_nomore_end(&bytes, &len, key, key_len);

            /* Start parsing the value field. */
            pull_subfield_start(&bytes, &len,
                                pull_varint(&bytes, &len),
                                &val, &val_max);
            result->version = pull_le32(&val, &val_max);
            subfield_nomore_end(&bytes, &len, val, val_max);
            if (result->version > WALLY_PSBT_HIGHEST_VERSION || result->version == 1) {
                ret = WALLY_EINVAL;    /* Unsupported version number */
                goto fail;
            }
            break;
        }
        case PSBT_GLOBAL_INPUT_COUNT: {
            if (found_input_count == true) {
                ret = WALLY_EINVAL;
                goto fail;
            }
            found_input_count = true;
            subfield_nomore_end(&bytes, &len, key, key_len);
            pull_subfield_start(&bytes, &len,
                                pull_varint(&bytes, &len),
                                &val, &val_max);
            input_count = pull_varint(&val, &val_max);
            subfield_nomore_end(&bytes, &len, val, val_max);
            break;
        }
        case PSBT_GLOBAL_OUTPUT_COUNT: {
            if (found_output_count == true) {
                ret = WALLY_EINVAL;
                goto fail;
            }
            found_output_count = true;
            subfield_nomore_end(&bytes, &len, key, key_len);
            pull_subfield_start(&bytes, &len,
                                pull_varint(&bytes, &len),
                                &val, &val_max);
            output_count = pull_varint(&val, &val_max);
            subfield_nomore_end(&bytes, &len, val, val_max);
            break;
        }
        case PSBT_GLOBAL_TX_VERSION: {
            if (found_tx_version == true) {
                ret = WALLY_EINVAL;
                goto fail;
            }
            found_tx_version = true;
            subfield_nomore_end(&bytes, &len, key, key_len);
            pull_subfield_start(&bytes, &len,
                                pull_varint(&bytes, &len),
                                &val, &val_max);
            result->tx_version = pull_le32(&val, &val_max);
            subfield_nomore_end(&bytes, &len, val, val_max);
            break;
        }
        case PSBT_GLOBAL_FALLBACK_LOCKTIME: {
            if (found_fallback_locktime == true) {
                ret = WALLY_EINVAL;
                goto fail;
            }
            found_fallback_locktime = true;
            subfield_nomore_end(&bytes, &len, key, key_len);
            pull_subfield_start(&bytes, &len,
                                pull_varint(&bytes, &len),
                                &val, &val_max);
            result->fallback_locktime = pull_le32(&val, &val_max);
            result->has_fallback_locktime = 1u;
            subfield_nomore_end(&bytes, &len, val, val_max);
            break;
        }
        case PSBT_GLOBAL_TX_MODIFIABLE: {
            if (found_tx_modifiable_flags == true) {
                ret = WALLY_EINVAL;
                goto fail;
            }
            found_tx_modifiable_flags = true;
            subfield_nomore_end(&bytes, &len, key, key_len);
            pull_subfield_start(&bytes, &len,
                                pull_varint(&bytes, &len),
                                &val, &val_max);
            result->tx_modifiable_flags = pull_u8(&val, &val_max);
            subfield_nomore_end(&bytes, &len, val, val_max);
            break;
        }
#ifdef BUILD_ELEMENTS
        case PSBT_PROPRIETARY_TYPE: {
            const uint64_t id_len = pull_varlength(&key, &key_len);

            if (!is_elements_prefix(key, id_len))
                goto unknown_type;

            /* Skip the elements_id prefix */
            pull_skip(&key, &key_len, sizeof(PSET_KEY_PREFIX));

            switch (pull_varint(&key, &key_len)) {
            case PSBT_ELEMENTS_GLOBAL_SCALAR: {
                unsigned char scalar[32];
                if (key_len != 32 || result->scalar)
                    return WALLY_EINVAL;
                pull_bytes(scalar, 32, &key, &key_len);
                if((ret = replace_bytes(scalar, 32, &result->scalar, &result->scalar_len)) != WALLY_OK)
                    goto fail;
                subfield_nomore_end(&bytes, &len, key, key_len);
                pull_subfield_start(&bytes, &len,
                                    pull_varint(&bytes, &len),
                                    &val, &val_max);
                if (val_max != 0)
                    return WALLY_EINVAL;
                subfield_nomore_end(&bytes, &len, val, val_max);
                break;
            }
            case PSBT_ELEMENTS_GLOBAL_TX_MODIFIABLE:
                subfield_nomore_end(&bytes, &len, key, key_len);
                pull_subfield_start(&bytes, &len,
                                    pull_varint(&bytes, &len),
                                    &val, &val_max);
                if (val_max != 1)
                    return WALLY_EINVAL;
                result->elements_tx_modifiable_flags = pull_u8(&val, &val_max);
                subfield_nomore_end(&bytes, &len, val, val_max);
                break;
            default:
                goto unknown_type;
            }
            break;

        }
#endif /* BUILD_ELEMENTS */
        /* Unknowns */
        default: {
unknown_type:
            ret = pull_unknown_key_value(&bytes, &len, pre_key, &result->unknowns);
            if (ret != WALLY_OK)
                goto fail;
            break;
        }
        }
        pre_key = bytes;
    }

    if (is_elements && result->version == 0) {
        ret = WALLY_EINVAL;
        goto fail;
    }
    /* We don't technically need to test here, but it's a minor optimization */
    if (!bytes) {
        ret = WALLY_EINVAL; /* Missing global separator */
        goto fail;
    }

    if (result->version == 0 && (!result->tx || found_input_count ||
                                 found_output_count || found_tx_version ||
                                 found_fallback_locktime || found_tx_modifiable_flags)) {
        ret = WALLY_EINVAL; /* Missing required field or includes invalid field */
        goto fail;
    }

    if (result->version >= 2 && (!found_input_count || !found_output_count || !found_tx_version)) {
        ret = WALLY_EINVAL; /* Missing required field */
        goto fail;
    }

    if (!result->tx && result->version == 0) {
        ret = WALLY_EINVAL; /* No global tx */
        goto fail;
    }

    if (!result->tx) {
        result->num_inputs = input_count;
        result->inputs = wally_calloc(result->num_inputs * sizeof(struct wally_psbt_input));

        result->num_outputs = output_count;
        result->outputs = wally_calloc(result->num_outputs * sizeof(struct wally_psbt_output));

        if (!result->inputs || !result->outputs) {
            ret = WALLY_ENOMEM;
            goto fail;
        }

        result->inputs_allocation_len = result->num_inputs;
        result->outputs_allocation_len = result->num_outputs;
    }

    else if (result->version >= 2) {
        if (result->num_inputs != input_count || result->num_outputs != output_count) {
            ret = WALLY_EINVAL;
            goto fail;
        }
    }

    /* Read inputs */
    for (i = 0; i < result->num_inputs; ++i) {
        result->inputs[i].psbt_version = result->version;
        ret = pull_psbt_input(&bytes, &len, flags, &result->inputs[i]);
        if (ret != WALLY_OK)
            goto fail;
    }

    /* Read outputs */
    for (i = 0; i < result->num_outputs; ++i) {
        result->outputs[i].psbt_version = result->version;
        ret = pull_psbt_output(&bytes, &len, &result->outputs[i]);
        if (ret != WALLY_OK)
            goto fail;
    }

    /* If we ran out of data anywhere, fail. */
    if (!bytes) {
        ret = WALLY_EINVAL;
        goto fail;
    }

    *output = result;
    return WALLY_OK;

fail:
    wally_psbt_free(result);
    return ret;
}

int wally_psbt_get_length(const struct wally_psbt *psbt, uint32_t flags, size_t *written)
{
    return wally_psbt_to_bytes(psbt, flags, NULL, 0, written);
}

/* Literally a varbuff containing only type as a varint, then optional data */
static void push_psbt_key(unsigned char **cursor, size_t *max,
                          uint64_t type, const void *extra, size_t extra_len)
{
    push_varint(cursor, max, varint_get_length(type) + extra_len);
    push_varint(cursor, max, type);
    push_bytes(cursor, max, extra, extra_len);
}

#ifdef BUILD_ELEMENTS
/* Common case of pushing elements proprietary type keys */
static void push_elements_key(unsigned char **cursor, size_t *max,
                              uint64_t type, const void *extra, size_t extra_len)
{
    push_varint(cursor, max, varint_get_length(PSBT_PROPRIETARY_TYPE)
                + varint_get_length(sizeof(PSET_KEY_PREFIX))
                + sizeof(PSET_KEY_PREFIX) + varint_get_length(type) + extra_len);

    push_varint(cursor, max, PSBT_PROPRIETARY_TYPE);
    push_varbuff(cursor, max, PSET_KEY_PREFIX, sizeof(PSET_KEY_PREFIX));
    push_varint(cursor, max, type);
    push_bytes(cursor, max, extra, extra_len);
}

static void push_elements_varbuff(unsigned char **cursor, size_t *max,
                                  uint64_t type,
                                  const unsigned char *bytes, size_t bytes_len)
{
    /* Note that due to dummy mallocs, bytes can be non-NULL while
     * bytes_len is 0. This represents a present-but-empty varbuff.
     */
    if (bytes) {
        push_elements_key(cursor, max, type, NULL, 0);
        push_varbuff(cursor, max, bytes, bytes_len);
    }
}

#endif /* BUILD_ELEMENTS */

static int push_length_and_tx(unsigned char **cursor, size_t *max,
                              const struct wally_tx *tx, uint32_t flags)
{
    int ret;
    size_t tx_len;
    unsigned char *p;

    if ((ret = wally_tx_get_length(tx, flags, &tx_len)) != WALLY_OK)
        return ret;

    push_varint(cursor, max, tx_len);

    /* TODO: convert wally_tx to use push  */
    if (!(p = push_bytes(cursor, max, NULL, tx_len)))
        return WALLY_OK; /* We catch this in caller. */

    return wally_tx_to_bytes(tx, flags, p, tx_len, &tx_len);
}

static void push_witness_stack(unsigned char **cursor, size_t *max,
                               const struct wally_tx_witness_stack *witness)
{
    size_t i;

    push_varint(cursor, max, witness->num_items);
    for (i = 0; i < witness->num_items; ++i) {
        push_varbuff(cursor, max, witness->items[i].witness,
                     witness->items[i].witness_len);
    }
}

static void push_typed_map(unsigned char **cursor, size_t *max,
                           uint64_t type, const struct wally_map *map_in)
{
    size_t i;
    for (i = 0; i < map_in->num_items; ++i) {
        const struct wally_map_item *item = &map_in->items[i];
        push_psbt_key(cursor, max, type, item->key, item->key_len);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
}

static void push_typed_varbuff(unsigned char **cursor, size_t *max,
                               uint64_t type,
                               const unsigned char *bytes, size_t bytes_len)
{
    if (bytes) {
        push_psbt_key(cursor, max, type, NULL, 0);
        push_varbuff(cursor, max, bytes, bytes_len);
    }
}

static void push_map(unsigned char **cursor, size_t *max,
                     const struct wally_map *map_in)
{
    size_t i;
    for (i = 0; i < map_in->num_items; ++i) {
        const struct wally_map_item *item = &map_in->items[i];
        push_varbuff(cursor, max, item->key, item->key_len);
        push_varbuff(cursor, max, item->value, item->value_len);
    }
}

static int push_psbt_input(unsigned char **cursor, size_t *max, uint32_t flags,
                           const struct wally_psbt_input *input)
{
    int ret;

    (void)flags;

    /* Non witness utxo */
    if (input->utxo) {
        push_psbt_key(cursor, max, PSBT_IN_NON_WITNESS_UTXO, NULL, 0);
        if ((ret = push_length_and_tx(cursor, max,
                                      input->utxo,
                                      WALLY_TX_FLAG_USE_WITNESS)) != WALLY_OK)
            return ret;
    }

    /* Witness utxo */
#ifdef BUILD_ELEMENTS
    if ((flags & WALLY_TX_FLAG_USE_ELEMENTS) && input->witness_utxo) {
        struct wally_tx_output *utxo = input->witness_utxo;
        const size_t buff_len = push_elements_bytes_size(utxo);
        size_t remaining = buff_len;
        unsigned char buff[1024], *buff_p = buff, *ptr;

        if (buff_len > sizeof(buff) && !(buff_p = wally_malloc(buff_len)))
            return WALLY_ENOMEM;
        ptr = buff_p;

        /* Push the asset, value, nonce, then scriptpubkey */
        push_psbt_key(cursor, max, PSBT_IN_WITNESS_UTXO, NULL, 0);

        push_elements_bytes(&ptr, &remaining, utxo->asset, utxo->asset_len);
        push_elements_bytes(&ptr, &remaining, utxo->value, utxo->value_len);
        push_elements_bytes(&ptr, &remaining, utxo->nonce, utxo->nonce_len);
        push_varbuff(&ptr, &remaining, utxo->script, utxo->script_len);

        if (!remaining)
            push_varbuff(cursor, max, buff_p, buff_len);
        if (buff_p != buff)
            clear_and_free(buff_p, buff_len);
        if (remaining)
            return WALLY_ERROR; /* Should not happen! */
    } else
#endif /* BUILD_ELEMENTS */
    if (input->witness_utxo) {
        unsigned char wit_bytes[50], *w = wit_bytes; /* Witness outputs can be no larger than 50 bytes as specified in BIP 141 */
        size_t wit_max = sizeof(wit_bytes);

        push_psbt_key(cursor, max, PSBT_IN_WITNESS_UTXO, NULL, 0);

        push_le64(&w, &wit_max, input->witness_utxo->satoshi);
        push_varbuff(&w, &wit_max,
                     input->witness_utxo->script,
                     input->witness_utxo->script_len);
        if (!w)
            return WALLY_EINVAL;

        push_varbuff(cursor, max, wit_bytes, w - wit_bytes);
    }
    /* Partial sigs */
    push_typed_map(cursor, max, PSBT_IN_PARTIAL_SIG, &input->signatures);
    /* Sighash type */
    if (input->sighash > 0) {
        push_psbt_key(cursor, max, PSBT_IN_SIGHASH_TYPE, NULL, 0);
        push_varint(cursor, max, sizeof(uint32_t));
        push_le32(cursor, max, input->sighash);
    }
    /* Redeem script */
    push_typed_varbuff(cursor, max, PSBT_IN_REDEEM_SCRIPT,
                       input->redeem_script, input->redeem_script_len);
    /* Witness script */
    push_typed_varbuff(cursor, max, PSBT_IN_WITNESS_SCRIPT,
                       input->witness_script, input->witness_script_len);
    /* Keypaths */
    push_typed_map(cursor, max, PSBT_IN_BIP32_DERIVATION, &input->keypaths);
    /* Final scriptSig */
    push_typed_varbuff(cursor, max, PSBT_IN_FINAL_SCRIPTSIG,
                       input->final_scriptsig, input->final_scriptsig_len);
    /* Final scriptWitness */
    if (input->final_witness) {
        size_t wit_len = 0;

        push_psbt_key(cursor, max, PSBT_IN_FINAL_SCRIPTWITNESS, NULL, 0);

        /* First pass simply calculates length */
        push_witness_stack(NULL, &wit_len, input->final_witness);

        push_varint(cursor, max, wit_len);
        push_witness_stack(cursor, max, input->final_witness);
    }

    if (input->psbt_version >= 2) {
        push_psbt_key(cursor, max, PSBT_IN_PREVIOUS_TXID, NULL, 0);
        push_varint(cursor, max, WALLY_TXHASH_LEN);
        push_bytes(cursor, max, input->previous_txid, WALLY_TXHASH_LEN);

        push_psbt_key(cursor, max, PSBT_IN_OUTPUT_INDEX, NULL, 0);
        push_varint(cursor, max, sizeof(input->output_index));
        push_le32(cursor, max, input->output_index);

        if (input->has_sequence) {
            push_psbt_key(cursor, max, PSBT_IN_SEQUENCE, NULL, 0);
            push_varint(cursor, max, sizeof(input->sequence));
            push_le32(cursor, max, input->sequence);
        }

        if (input->has_required_locktime && input->required_locktime >= PSBT_LOCKTIME_MIN_TIMESTAMP) {
            push_psbt_key(cursor, max, PSBT_IN_REQUIRED_TIME_LOCKTIME, NULL, 0);
            push_varint(cursor, max, sizeof(input->required_locktime));
            push_le32(cursor, max, input->required_locktime);
        }

        if (input->has_required_locktime && input->required_locktime < PSBT_LOCKTIME_MIN_TIMESTAMP) {
            push_psbt_key(cursor, max, PSBT_IN_REQUIRED_HEIGHT_LOCKTIME, NULL, 0);
            push_varint(cursor, max, sizeof(input->required_locktime));
            push_le32(cursor, max, input->required_locktime);
        }
    }
#ifdef BUILD_ELEMENTS
    if (input->has_issuance_amount) {
        push_elements_key(cursor, max, PSBT_ELEMENTS_IN_ISSUANCE_VALUE, NULL, 0);
        push_varint(cursor, max, sizeof(input->issuance_amount));
        push_le64(cursor, max, input->issuance_amount);
    }
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_ISSUANCE_VALUE_COMMITMENT,
                          input->issuance_amount_commitment, input->issuance_amount_commitment_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_ISSUANCE_VALUE_RANGEPROOF,
                          input->issuance_amount_rangeproof, input->issuance_amount_rangeproof_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_ISSUANCE_KEYS_RANGEPROOF,
                          input->inflation_keys_rangeproof, input->inflation_keys_rangeproof_len);
    if (input->pegin_tx) {
        push_elements_key(cursor, max, PSBT_ELEMENTS_IN_PEG_IN_TX, NULL, 0);
        if ((ret = push_length_and_tx(cursor, max,
                                      input->pegin_tx,
                                      WALLY_TX_FLAG_USE_WITNESS)) != WALLY_OK)
            return ret;
    }
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_PEG_IN_TXOUT_PROOF,
                          input->txoutproof, input->txoutproof_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_PEG_IN_GENESIS,
                          input->genesis_blockhash, input->genesis_blockhash_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_PEG_IN_CLAIM_SCRIPT,
                          input->claim_script, input->claim_script_len);
    if (input->has_pegin_amount) {
        push_elements_key(cursor, max, PSBT_ELEMENTS_IN_PEG_IN_VALUE, NULL, 0);
        push_varint(cursor, max, sizeof(input->pegin_amount));
        push_le64(cursor, max, input->pegin_amount);
    }
    if (input->pegin_witness) {
        size_t wit_len = 0;

        push_elements_key(cursor, max, PSBT_ELEMENTS_IN_PEG_IN_WITNESS, NULL, 0);

        /* First pass simply calculates length */
        push_witness_stack(NULL, &wit_len, input->pegin_witness);

        push_varint(cursor, max, wit_len);
        push_witness_stack(cursor, max, input->pegin_witness);
    }
    if (input->has_inflation_keys) {
        push_elements_key(cursor, max, PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS, NULL, 0);
        push_varint(cursor, max, sizeof(input->inflation_keys));
        push_le64(cursor, max, input->inflation_keys);
    }
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_ISSUANCE_INFLATION_KEYS_COMMITMENT,
                          input->inflation_keys_commitment, input->inflation_keys_commitment_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_ISSUANCE_BLINDING_NONCE,
                          input->blinding_nonce, input->blinding_nonce_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_ISSUANCE_ASSET_ENTROPY,
                          input->entropy, input->entropy_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_UTXO_RANGEPROOF,
                          input->utxo_rangeproof, input->utxo_rangeproof_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_ISSUANCE_BLIND_VALUE_PROOF,
                          input->issuance_amount_blind_proof, input->issuance_amount_blind_proof_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_IN_ISSUANCE_BLIND_INFLATION_KEYS_PROOF,
                          input->inflation_keys_blind_proof, input->inflation_keys_blind_proof_len);
#endif /* BUILD_ELEMENTS */
    /* Unknowns */
    push_map(cursor, max, &input->unknowns);
    /* Separator */
    push_u8(cursor, max, PSBT_SEPARATOR);
    return WALLY_OK;
}

static int push_psbt_output(unsigned char **cursor, size_t *max,
                            const struct wally_psbt_output *output)
{
    /* Redeem script */
    push_typed_varbuff(cursor, max, PSBT_OUT_REDEEM_SCRIPT,
                       output->redeem_script, output->redeem_script_len);
    /* Witness script */
    push_typed_varbuff(cursor, max, PSBT_OUT_WITNESS_SCRIPT,
                       output->witness_script, output->witness_script_len);
    /* Keypaths */
    push_typed_map(cursor, max, PSBT_OUT_BIP32_DERIVATION, &output->keypaths);

    if (output->psbt_version >= 2) {
        if (output->has_amount) {
            push_psbt_key(cursor, max, PSBT_OUT_AMOUNT, NULL, 0);
            push_varint(cursor, max, sizeof(output->amount));
            push_le64(cursor, max, output->amount);
        }
        if (output->script != NULL) {
            push_typed_varbuff(cursor, max, PSBT_OUT_SCRIPT, output->script, output->script_len);
        }
    }

#ifdef BUILD_ELEMENTS
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_OUT_VALUE_COMMITMENT,
                          output->value_commitment, output->value_commitment_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_OUT_VALUE_RANGEPROOF,
                          output->rangeproof, output->rangeproof_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_OUT_ASSET_SURJECTION_PROOF,
                          output->surjectionproof, output->surjectionproof_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_OUT_BLINDING_PUBKEY,
                          output->blinding_pubkey, output->blinding_pubkey_len);
    push_elements_varbuff(cursor, max, PSBT_ELEMENTS_OUT_ECDH_PUBKEY,
                          output->nonce, output->nonce_len);
#endif /* BUILD_ELEMENTS */
    /* Unknowns */
    push_map(cursor, max, &output->unknowns);
    /* Separator */
    push_u8(cursor, max, PSBT_SEPARATOR);
    return WALLY_OK;
}

int wally_psbt_to_bytes(const struct wally_psbt *psbt, uint32_t flags,
                        unsigned char *bytes_out, size_t len,
                        size_t *written)
{
    unsigned char *cursor = bytes_out;
    size_t max = len, i, is_elements;
    uint32_t tx_flags;
    int ret;

    if (written)
        *written = 0;

    if (flags != 0 || !written)
        return WALLY_EINVAL;

    if ((ret = wally_psbt_is_elements(psbt, &is_elements)) != WALLY_OK)
        return ret;

    tx_flags = is_elements ? WALLY_TX_FLAG_USE_ELEMENTS : 0;
    push_bytes(&cursor, &max, psbt->magic, sizeof(psbt->magic));

    /* Global tx */
    if(psbt->tx) {
        push_psbt_key(&cursor, &max, PSBT_GLOBAL_UNSIGNED_TX, NULL, 0);
        ret = push_length_and_tx(&cursor, &max, psbt->tx,
                                 WALLY_TX_FLAG_ALLOW_PARTIAL | WALLY_TX_FLAG_PRE_BIP144);
        if (ret != WALLY_OK)
            return ret;
    }

    if (psbt->version >= 2) {
        size_t n;
        unsigned char buf[sizeof(uint8_t) + sizeof(uint64_t)];

        push_psbt_key(&cursor, &max, PSBT_GLOBAL_VERSION, NULL, 0);
        push_varint(&cursor, &max, sizeof(uint32_t));
        push_le32(&cursor, &max, psbt->version);

        push_psbt_key(&cursor, &max, PSBT_GLOBAL_TX_VERSION, NULL, 0);
        push_varint(&cursor, &max, sizeof(uint32_t));
        push_le32(&cursor, &max, psbt->tx_version);

        if (psbt->has_fallback_locktime) {
            push_psbt_key(&cursor, &max, PSBT_GLOBAL_FALLBACK_LOCKTIME, NULL, 0);
            push_varint(&cursor, &max, sizeof(uint32_t));
            push_le32(&cursor, &max, psbt->fallback_locktime);
        }

        push_psbt_key(&cursor, &max, PSBT_GLOBAL_INPUT_COUNT, NULL, 0);
        n = varint_to_bytes(psbt->num_inputs, buf);
        push_varbuff(&cursor, &max, buf, n);

        push_psbt_key(&cursor, &max, PSBT_GLOBAL_OUTPUT_COUNT, NULL, 0);
        n = varint_to_bytes(psbt->num_outputs, buf);
        push_varbuff(&cursor, &max, buf, n);

        if (psbt->tx_modifiable_flags != 0) {
            push_psbt_key(&cursor, &max, PSBT_GLOBAL_TX_MODIFIABLE, NULL, 0);
            push_varint(&cursor, &max, sizeof(uint8_t));
            push_u8(&cursor, &max, psbt->tx_modifiable_flags);
        }
#ifdef BUILD_ELEMENTS
        if (psbt->scalar) {
            push_elements_key(&cursor, &max, PSBT_ELEMENTS_GLOBAL_SCALAR, psbt->scalar, 32);
            push_varbuff(&cursor, &max, 0, 0);
        }
        if (psbt->elements_tx_modifiable_flags != 0) {
            push_elements_key(&cursor, &max, PSBT_ELEMENTS_GLOBAL_TX_MODIFIABLE, NULL, 0);
            push_varint(&cursor, &max, sizeof(psbt->elements_tx_modifiable_flags));
            push_u8(&cursor, &max, psbt->elements_tx_modifiable_flags);
        }
#endif /* BUILD_ELEMENTS */
    }

    /* Unknowns */
    push_map(&cursor, &max, &psbt->unknowns);

    /* Separator */
    push_u8(&cursor, &max, PSBT_SEPARATOR);

    /* Push each input and output */
    for (i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input *input = &psbt->inputs[i];
        if ((ret = push_psbt_input(&cursor, &max, tx_flags, input)) != WALLY_OK)
            return ret;
    }
    for (i = 0; i < psbt->num_outputs; ++i) {
        const struct wally_psbt_output *output = &psbt->outputs[i];
        if ((ret = push_psbt_output(&cursor, &max, output)) != WALLY_OK)
            return ret;
    }

    if (cursor == NULL) {
        /* Once cursor is NULL, max holds how many bytes we needed */
        *written = len + max;
    } else {
        *written = len - max;
    }

    return WALLY_OK;
}

int wally_psbt_from_base64(const char *base64, struct wally_psbt **output)
{
    unsigned char *decoded;
    size_t max_len, written;
    int ret;

    TX_CHECK_OUTPUT;
    if ((ret = wally_base64_get_maximum_length(base64, 0, &max_len)) != WALLY_OK)
        return ret;

    /* Allocate the buffer to decode into */
    if ((decoded = wally_malloc(max_len)) == NULL)
        return WALLY_ENOMEM;

    /* Decode the base64 psbt into binary */
    if ((ret = wally_base64_to_bytes(base64, 0, decoded, max_len, &written)) != WALLY_OK)
        goto done;

    if (written <= sizeof(PSBT_MAGIC)) {
        ret = WALLY_EINVAL; /* Not enough bytes for the magic + any data */
        goto done;
    }
    if (written > max_len) {
        ret = WALLY_ERROR; /* Max len too small, should never happen! */
        goto done;
    }

    /* decode the psbt */
    ret = wally_psbt_from_bytes(decoded, written, output);

done:
    clear_and_free(decoded, max_len);
    return ret;
}

int wally_psbt_to_base64(const struct wally_psbt *psbt, uint32_t flags, char **output)
{
    unsigned char *buff;
    size_t len, written;
    int ret = WALLY_OK;

    TX_CHECK_OUTPUT;
    if (!psbt)
        return WALLY_EINVAL;

    if ((ret = wally_psbt_get_length(psbt, flags, &len)) != WALLY_OK)
        return ret;

    if ((buff = wally_malloc(len)) == NULL)
        return WALLY_ENOMEM;

    /* Get psbt bytes */
    if ((ret = wally_psbt_to_bytes(psbt, flags, buff, len, &written)) != WALLY_OK)
        goto done;

    if (written != len) {
        ret = WALLY_ERROR; /* Length calculated incorrectly */
        goto done;
    }

    /* Base64 encode */
    ret = wally_base64_from_bytes(buff, len, 0, output);

done:
    clear_and_free(buff, len);
    return ret;
}

#define COMBINE_BYTES(typ, member)  do { \
        if (!dst->member && src->member) { \
            if (src->member && !src->member ## _len) { \
                if ((dst->member = wally_malloc(1)) == NULL) ret = WALLY_ENOMEM; \
            } else \
                ret = wally_psbt_ ## typ ## _set_ ## member(dst, src->member, src->member ## _len); \
            if (ret != WALLY_OK) \
                return ret; \
        } } while (0)

#define COMBINE_BYTES_GLOBAL(member)  do { \
        if (!psbt->member && src->member) { \
            if (src->member && !src->member ## _len) { \
                if ((psbt->member = wally_malloc(1)) == NULL) ret = WALLY_ENOMEM; \
            } else \
                ret = wally_psbt_set_ ## member(psbt, src->member, src->member ## _len); \
            if (ret != WALLY_OK) \
                return ret; \
        } } while (0)


static int combine_txs(struct wally_tx **dst, struct wally_tx *src)
{
    if (!dst)
        return WALLY_EINVAL;

    if (!*dst && src)
        return tx_clone_alloc(src, dst);

    return WALLY_OK;
}

static int combine_inputs(struct wally_psbt_input *dst,
                          const struct wally_psbt_input *src)
{
    int ret;

    if ((ret = combine_txs(&dst->utxo, src->utxo)) != WALLY_OK)
        return ret;

    if (!dst->witness_utxo && src->witness_utxo) {
        ret = wally_tx_output_clone_alloc(src->witness_utxo, &dst->witness_utxo);
        if (ret != WALLY_OK)
            return ret;
    }

    COMBINE_BYTES(input, redeem_script);
    COMBINE_BYTES(input, witness_script);
    COMBINE_BYTES(input, final_scriptsig);

    if (!dst->final_witness && src->final_witness &&
        (ret = wally_psbt_input_set_final_witness(dst, src->final_witness)) != WALLY_OK)
        return ret;
    if ((ret = map_extend(&dst->keypaths, &src->keypaths, wally_ec_public_key_verify)) != WALLY_OK)
        return ret;
    if ((ret = map_extend(&dst->signatures, &src->signatures, wally_ec_public_key_verify)) != WALLY_OK)
        return ret;
    if ((ret = map_extend(&dst->unknowns, &src->unknowns, NULL)) != WALLY_OK)
        return ret;
    if (!dst->sighash && src->sighash)
        dst->sighash = src->sighash;


    COMBINE_BYTES(input, previous_txid);

    if (!dst->output_index && src->output_index)
        dst->output_index = src->output_index;

    if (!dst->has_sequence && src->has_sequence) {
        dst->sequence = src->sequence;
        dst->has_sequence = 1u;
    }
    if (!dst->has_required_locktime && src->has_required_locktime) {
        dst->required_locktime = src->required_locktime;
        dst->has_required_locktime = 1u;
    }

#ifdef BUILD_ELEMENTS
    if (!dst->has_issuance_amount && src->has_issuance_amount) {
        dst->has_issuance_amount = src->has_issuance_amount;
        dst->issuance_amount = src->issuance_amount;
    }
    COMBINE_BYTES(input, issuance_amount_commitment);
    COMBINE_BYTES(input, issuance_amount_rangeproof);
    COMBINE_BYTES(input, issuance_amount_blind_proof);

    COMBINE_BYTES(input, blinding_nonce);
    COMBINE_BYTES(input, entropy);

    if (!dst->has_inflation_keys && src->has_inflation_keys) {
        dst->has_inflation_keys = src->has_inflation_keys;
        dst->inflation_keys = src->inflation_keys;
    }
    COMBINE_BYTES(input, inflation_keys_commitment);
    COMBINE_BYTES(input, inflation_keys_rangeproof);
    COMBINE_BYTES(input, inflation_keys_blind_proof);
    if ((ret = combine_txs(&dst->pegin_tx, src->pegin_tx)) != WALLY_OK)
        return ret;
    COMBINE_BYTES(input, txoutproof);
    COMBINE_BYTES(input, genesis_blockhash);
    COMBINE_BYTES(input, claim_script);
    if (!dst->has_pegin_amount && src->has_pegin_amount) {
        dst->has_pegin_amount = src->has_pegin_amount;
        dst->pegin_amount = src->pegin_amount;
    }
    if (!dst->pegin_witness && src->pegin_witness &&
        (ret = wally_psbt_input_set_pegin_witness(dst, src->pegin_witness)) != WALLY_OK)
        return ret;
    COMBINE_BYTES(input, utxo_rangeproof);
#endif
    return WALLY_OK;
}

static int combine_outputs(struct wally_psbt_output *dst,
                           const struct wally_psbt_output *src)
{
    int ret;

    if (dst->script_len != 0 && dst->script_len != src->script_len)
        return WALLY_EINVAL;
    if (memcmp(dst->script, src->script, dst->script_len) != 0)
        return WALLY_EINVAL;
    if (dst->has_amount && !src->has_amount)
        return WALLY_EINVAL;
    if (dst->has_amount && src->has_amount && dst->amount != src->amount)
        return WALLY_EINVAL;

    if ((ret = map_extend(&dst->keypaths, &src->keypaths, wally_ec_public_key_verify)) != WALLY_OK)
        return ret;
    if ((ret = map_extend(&dst->unknowns, &src->unknowns, NULL)) != WALLY_OK)
        return ret;

    COMBINE_BYTES(output, redeem_script);
    COMBINE_BYTES(output, witness_script);
    COMBINE_BYTES(output, script);
    if (!dst->has_amount && src->has_amount) {
        dst->amount = src->amount;
        dst->has_amount = src->has_amount;
    }

#ifdef BUILD_ELEMENTS
    COMBINE_BYTES(output, blinding_pubkey);
    COMBINE_BYTES(output, value_commitment);
    COMBINE_BYTES(output, asset_commitment);
    COMBINE_BYTES(output, nonce);
    COMBINE_BYTES(output, rangeproof);
    COMBINE_BYTES(output, surjectionproof);
#endif
    return WALLY_OK;
}
#undef COMBINE_BYTES

static int psbt_combine(struct wally_psbt *psbt, const struct wally_psbt *src)
{
    size_t i;
    int ret = WALLY_OK;

    if (!psbt->has_fallback_locktime && src->has_fallback_locktime) {
        psbt->fallback_locktime = src->fallback_locktime;
        psbt->has_fallback_locktime = src->has_fallback_locktime;
    }

    if (!psbt->tx_modifiable_flags && src->tx_modifiable_flags) {
        psbt->tx_modifiable_flags = src->tx_modifiable_flags;
    }

#ifdef BUILD_ELEMENTS
    if (!psbt->elements_tx_modifiable_flags && src->elements_tx_modifiable_flags)
        psbt->elements_tx_modifiable_flags = src->elements_tx_modifiable_flags;

    COMBINE_BYTES_GLOBAL(scalar);

#endif /* BUILD_ELEMENTS */

    for (i = 0; ret == WALLY_OK && i < psbt->num_inputs; ++i) {
        psbt->inputs[i].psbt_version = psbt->version;
        ret = combine_inputs(&psbt->inputs[i], &src->inputs[i]);
    }

    for (i = 0; ret == WALLY_OK && i < psbt->num_outputs; ++i) {
        psbt->outputs[i].psbt_version = psbt->version;
        ret = combine_outputs(&psbt->outputs[i], &src->outputs[i]);
    }

    if (ret == WALLY_OK)
        ret = map_extend(&psbt->unknowns, &src->unknowns, NULL);

    return ret;
}

int psbt_calculate_locktime(const struct wally_psbt *psbt, uint32_t *locktime)
{
    bool has_time_locktime = false, has_height_locktime = false;

    for (size_t i = 0; i < psbt->num_inputs; i++) {
        if (psbt->inputs[i].has_required_locktime) {
            if (psbt->inputs[i].required_locktime < PSBT_LOCKTIME_MIN_TIMESTAMP) {
                if (has_time_locktime)
                    return WALLY_EINVAL;
                has_height_locktime = true;
                *locktime = *locktime > psbt->inputs[i].required_locktime ? *locktime : psbt->inputs[i].required_locktime;
            }
            else {
                if (has_height_locktime)
                    return WALLY_EINVAL;
                has_time_locktime = true;
                *locktime = *locktime > psbt->inputs[i].required_locktime ? *locktime : psbt->inputs[i].required_locktime;
            }
        }
    }

    if (!has_time_locktime && !has_height_locktime) {
        if (psbt->has_fallback_locktime)
            *locktime = psbt->fallback_locktime;
        else
            *locktime = 0;
    }

    return WALLY_OK;
}

int psbt_build_tx(const struct wally_psbt *psbt, struct wally_tx **tx)
{
    int ret;

    uint32_t locktime;
    size_t is_elements;

    if ((ret = wally_psbt_is_elements(psbt, &is_elements)) != WALLY_OK)
        return ret;

    ret = psbt_calculate_locktime(psbt, &locktime);

    if ((ret = wally_tx_init_alloc(psbt->tx_version, locktime, psbt->num_inputs, psbt->num_outputs, tx)) != WALLY_OK)
        return ret;

    for (size_t i = 0; i < psbt->num_inputs; i++) {
        struct wally_psbt_input *psbt_input = &psbt->inputs[i];
        uint32_t sequence;
        sequence = psbt_input->has_sequence ? psbt_input->sequence : WALLY_TX_SEQUENCE_FINAL;
        struct wally_tx_input *input;

        if (is_elements) {
#ifdef BUILD_ELEMENTS
            //TODO, figure out issuance, if its commitment or raw value
            if ((ret = wally_tx_elements_input_init_alloc(psbt_input->previous_txid, psbt_input->previous_txid_len,
                                                          psbt_input->output_index, sequence, NULL, 0, NULL, psbt_input->blinding_nonce, psbt_input->blinding_nonce_len,
                                                          psbt_input->entropy, psbt_input->entropy_len, NULL, 0, NULL, 0, psbt_input->issuance_amount_rangeproof,
                                                          psbt_input->issuance_amount_rangeproof_len, psbt_input->inflation_keys_rangeproof, psbt_input->inflation_keys_rangeproof_len,
                                                          NULL, &input)) != WALLY_OK) {
                wally_tx_free(*tx);
                return ret;
            }
#endif /* BUILD_ELEMENTS */
#ifndef BUILD_ELEMENTS
            return WALLY_EINVAL;
#endif /* BUILD_ELEMENTS */
        }
        else {
            if ((ret = wally_tx_input_init_alloc(psbt_input->previous_txid, psbt_input->previous_txid_len, psbt_input->output_index, sequence, NULL, 0, NULL, &input)) != WALLY_OK) {
                wally_tx_free(*tx);
                return ret;
            }
        }
        if ((ret = wally_tx_add_input(*tx, input)) != WALLY_OK) {
            wally_tx_free(*tx);
            wally_tx_input_free(input);
            return ret;
        }
    }

    for (size_t i = 0; i < psbt->num_outputs; i++) {
        struct wally_psbt_output *psbt_output = &psbt->outputs[i];
        if (is_elements) {
            return WALLY_EINVAL;
        }
        else {
            struct wally_tx_output *output;

            if ((ret = wally_tx_output_init_alloc(psbt_output->amount, psbt_output->script, psbt_output->script_len, &output)) != WALLY_OK) {
                wally_tx_free(*tx);
                return ret;
            }

            if ((ret = wally_tx_add_output(*tx, output)) != WALLY_OK) {
                wally_tx_output_free(output);
                wally_tx_free(*tx);
                return ret;
            }
        }
    }

    return WALLY_OK;
}

int psbt_get_unique_id(const struct wally_psbt *psbt, unsigned char *txid, size_t txid_len)
{
    int ret;
    struct wally_tx *built_tx;
    if (psbt->tx) {
        ret = wally_tx_get_txid(psbt->tx, txid, txid_len) != WALLY_OK;
        return ret;
    }

    if ((ret = psbt_build_tx(psbt, &built_tx)) != WALLY_OK)
        return ret;
    built_tx->locktime = 0;

    for (size_t i = 0; i < built_tx->num_inputs; i++) {
        built_tx->inputs[i].sequence = 0;
    }

    ret = wally_tx_get_txid(built_tx, txid, txid_len);
    wally_tx_free(built_tx);

    return ret;
}

int wally_psbt_combine(struct wally_psbt *psbt, const struct wally_psbt *src)
{
    unsigned char src_txid[WALLY_TXHASH_LEN], dest_txid[WALLY_TXHASH_LEN];
    int ret;

    if (!psbt || (psbt->version == 0 && !psbt->tx) || !src || (src->version == 0 && !src->tx))
        return WALLY_EINVAL;

    if ((ret = psbt_get_unique_id(psbt, dest_txid, WALLY_TXHASH_LEN)) != WALLY_OK)
        return ret;

    if ((ret = psbt_get_unique_id(src, src_txid, WALLY_TXHASH_LEN)) != WALLY_OK) {
        wally_clear(dest_txid, sizeof(dest_txid));
        return ret;
    }

    if (memcmp(src_txid, dest_txid, WALLY_TXHASH_LEN) != 0)
        ret = WALLY_EINVAL;

    wally_clear(src_txid, sizeof(src_txid));
    wally_clear(dest_txid, sizeof(dest_txid));
    return ret == WALLY_OK ? psbt_combine(psbt, src) : ret;
}

int wally_psbt_clone_alloc(const struct wally_psbt *psbt, uint32_t flags,
                           struct wally_psbt **output)
{
#ifdef BUILD_ELEMENTS
    size_t is_elements;
#endif /* BUILD_ELEMENTS */
    int ret;

    if (output)
        *output = NULL;
    if (!psbt || flags || !output)
        return WALLY_EINVAL;

#ifdef BUILD_ELEMENTS
    if ((ret = wally_psbt_is_elements(psbt, &is_elements)) != WALLY_OK)
        return ret;

    if (is_elements)
        ret = wally_psbt_elements_init_alloc(psbt->version,
                                             psbt->inputs_allocation_len,
                                             psbt->outputs_allocation_len,
                                             psbt->unknowns.items_allocation_len,
                                             output);
    else
#endif /* BUILD_ELEMENTS */
    ret = wally_psbt_init_alloc(psbt->version,
                                psbt->inputs_allocation_len,
                                psbt->outputs_allocation_len,
                                psbt->unknowns.items_allocation_len,
                                output);
    if (ret == WALLY_OK) {
        (*output)->num_inputs = psbt->num_inputs;
        (*output)->num_outputs = psbt->num_outputs;
        ret = psbt_combine(*output, psbt);

        if (ret == WALLY_OK && psbt->tx)
            ret = tx_clone_alloc(psbt->tx, &(*output)->tx);
        if (ret != WALLY_OK) {
            wally_psbt_free(*output);
            *output = NULL;
        }
    }
    return ret;
}

static int psbt_input_sign(struct wally_psbt_input *input,
                           const unsigned char *priv_key, size_t priv_key_len,
                           const unsigned char *pub_key, size_t pub_key_len,
                           const unsigned char *bytes, size_t bytes_len,
                           uint32_t flags)
{
    unsigned char sig[EC_SIGNATURE_LEN], der[EC_SIGNATURE_DER_MAX_LEN + 1];
    size_t der_len;
    uint32_t sighash = input && input->sighash ? input->sighash : WALLY_SIGHASH_ALL;
    int ret;

    if (!input || !priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        (wally_ec_public_key_verify(pub_key, pub_key_len) != WALLY_OK) ||
        !bytes || bytes_len != SHA256_LEN || (flags & ~EC_FLAGS_ALL) ||
        (sighash & 0xffffff00))
        return WALLY_EINVAL;

    /* Only grinding flag is relevant */
    flags = EC_FLAG_ECDSA | (flags & EC_FLAG_GRIND_R);
    if ((ret = wally_ec_sig_from_bytes(priv_key, priv_key_len,
                                       bytes, SHA256_LEN, flags,
                                       sig, sizeof(sig))) != WALLY_OK)
        return ret;

    if ((ret = wally_ec_sig_to_der(sig, sizeof(sig), der,
                                   sizeof(der), &der_len)) != WALLY_OK)
        return ret;

    /* Convert sig to DER, add sighash byte and store in the input */
    der[der_len++] = sighash & 0xff;
    ret = wally_psbt_input_add_signature(input, pub_key, pub_key_len,
                                         der, der_len);
    wally_clear_2(sig, sizeof(sig), der, sizeof(der));
    return ret;
}

/* Get the script to sign with */
static bool input_get_scriptcode(const struct wally_psbt_input *input,
                                 uint32_t input_index,
                                 const unsigned char **script,
                                 size_t *script_len)
{
    const struct wally_tx_output *utxo = NULL;
    const struct wally_tx_output *out;

    if (!input || !script || !script_len)
        return false;

    *script = NULL;
    *script_len = 0;

    if (input->utxo) {
        if (input_index >= input->utxo->num_outputs)
            return false; /* Invalid input index */
        utxo = &input->utxo->outputs[input_index];
    }

    out = input->witness_utxo ? input->witness_utxo : utxo;
    if (!out)
        return false; /* No prevout to get the script from */

    if (input->redeem_script) {
        unsigned char p2sh[WALLY_SCRIPTPUBKEY_P2SH_LEN];
        size_t p2sh_len;

        if (wally_scriptpubkey_p2sh_from_bytes(input->redeem_script,
                                               input->redeem_script_len,
                                               WALLY_SCRIPT_HASH160,
                                               p2sh, sizeof(p2sh),
                                               &p2sh_len) != WALLY_OK)
            return false;

        if (out->script_len != p2sh_len || memcmp(p2sh, out->script, p2sh_len))
            return false; /* Script mismatch */

        *script = input->redeem_script;
        *script_len = input->redeem_script_len;
        return true;
    }

    *script = out->script;
    *script_len = out->script_len;
    return true;
}

#ifdef BUILD_ELEMENTS
int psbt_build_pegin_witness_alloc(const struct wally_psbt_input *input, struct wally_tx_witness_stack **witness)
{
    int ret = WALLY_OK;
    unsigned char pegin_amount[8];
    unsigned char *pegin_tx_bytes, *cursor;
    size_t pegin_tx_len, written, max = sizeof(pegin_amount);

    // TODO: This is hardcoded for Liquid since the field is not available in PSET currently. This should be a PSET field.
    unsigned char asset[] = {0x6f, 0x02, 0x79, 0xe9, 0xed, 0x04, 0x1c, 0x3d, 0x71, 0x0a, 0x9f, 0x57, 0xd0, 0xc0, 0x29, 0x28, 0x41,
                             0x64, 0x60, 0xc4, 0xb7, 0x22, 0xae, 0x34, 0x57, 0xa1, 0x1e, 0xec, 0x38, 0x1c, 0x52, 0x6d};

    cursor = pegin_amount;
    push_le64(&cursor, &max, input->pegin_amount);

    if ((ret = wally_tx_get_length(input->pegin_tx, 0, &pegin_tx_len)) != WALLY_OK)
        return ret;

    pegin_tx_bytes = wally_calloc(pegin_tx_len);
    if (!pegin_tx_bytes)
        return WALLY_ENOMEM;

    if ((ret = wally_tx_to_bytes(input->pegin_tx, 0, pegin_tx_bytes, pegin_tx_len, &written)) != WALLY_OK)
        goto cleanup;

    if ((ret = wally_tx_witness_stack_init_alloc(6, witness)) != WALLY_OK)
        goto cleanup;
    if ((ret = wally_tx_witness_stack_add(*witness, pegin_amount, sizeof(pegin_amount))) != WALLY_OK)
        goto cleanup;
    if ((ret = wally_tx_witness_stack_add(*witness, asset, sizeof(asset))) != WALLY_OK)
        goto cleanup;
    if ((ret = wally_tx_witness_stack_add(*witness, input->genesis_blockhash, input->genesis_blockhash_len)) != WALLY_OK)
        goto cleanup;
    if ((ret = wally_tx_witness_stack_add(*witness, input->claim_script, input->claim_script_len)) != WALLY_OK)
        goto cleanup;
    if ((ret = wally_tx_witness_stack_add(*witness, pegin_tx_bytes, pegin_tx_len)) != WALLY_OK)
        goto cleanup;
    if ((ret = wally_tx_witness_stack_add(*witness, input->txoutproof, input->txoutproof_len)) != WALLY_OK)
        goto cleanup;

cleanup:
    wally_free(pegin_tx_bytes);
    if (ret != WALLY_OK)
        wally_tx_witness_stack_free(*witness);
    return ret;
}

#endif

int wally_psbt_sign(struct wally_psbt *psbt,
                    const unsigned char *key, size_t key_len, uint32_t flags)
{
    unsigned char pubkey[EC_PUBLIC_KEY_LEN], full_pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    const size_t pubkey_len = sizeof(pubkey), full_pubkey_len = sizeof(full_pubkey);
    unsigned char wpkh_sc[WALLY_SCRIPTPUBKEY_P2PKH_LEN];
    size_t is_elements, i;
    int ret;
    struct wally_tx *tx;

    if (!psbt || (psbt->version == 0 && !psbt->tx) || !key || key_len != EC_PRIVATE_KEY_LEN ||
        (flags & ~EC_FLAGS_ALL)) {
        return WALLY_EINVAL;
    }

    if (psbt->tx) {
        if ((ret = wally_tx_clone_alloc(psbt->tx, 0, &tx)) != WALLY_OK)
            return ret;
    }
    else {
        if ((ret = psbt_build_tx(psbt, &tx)) != WALLY_OK)
            return ret;
    }

    if ((ret = wally_psbt_is_elements(psbt, &is_elements)) != WALLY_OK)
        return ret;
#ifndef BUILD_ELEMENTS
    if (is_elements) {
        ret = WALLY_EINVAL;
        goto cleanup;
    }
#endif /* ndef BUILD_ELEMENTS */

    /* Get the pubkey */
    ret = wally_ec_public_key_from_private_key(key, key_len,
                                               pubkey, pubkey_len);
    if (ret == WALLY_OK)
        ret = wally_ec_public_key_decompress(pubkey, pubkey_len,
                                             full_pubkey, full_pubkey_len);
    if (ret != WALLY_OK)
        goto cleanup;

    /* Go through each of the inputs */
    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        struct wally_tx_input *txin = &tx->inputs[i];
        unsigned char signature_hash[SHA256_LEN];
        const unsigned char *scriptcode;
        size_t keypath_index = 0, scriptcode_len;
        uint32_t sighash;

#ifdef BUILD_ELEMENTS
        if (input->pegin_tx && input->txoutproof && input->claim_script &&
            input->genesis_blockhash && input->pegin_amount) {
            wally_tx_witness_stack_free(input->pegin_witness);
            if ((ret = psbt_build_pegin_witness_alloc(input, &input->pegin_witness)) != WALLY_OK)
                return ret;
        }
        if (input->pegin_witness) {
            if (!wally_tx_witness_stack_clone_alloc(input->pegin_witness, &txin->pegin_witness))
                return ret;
        }
#endif
        /* See if this input has a keypath matching the pubkey of the private key supplied */
        ret = wally_map_find(&input->keypaths, full_pubkey, full_pubkey_len, &keypath_index);
        if (ret == WALLY_OK && !keypath_index)
            ret = wally_map_find(&input->keypaths, pubkey, pubkey_len, &keypath_index);
        if (ret != WALLY_OK)
            continue;

        if (!keypath_index)
            continue; /* Didn't find a keypath matching this pubkey: skip it */
        keypath_index -= 1; /* Use 0 based index below */

        /* Make sure we don't already have a sig for this input */
        size_t is_found;
        ret = wally_map_find(&input->signatures, full_pubkey, full_pubkey_len, &is_found);
        if (ret == WALLY_OK && !is_found)
            ret = wally_map_find(&input->signatures, pubkey, pubkey_len, &is_found);

        if (ret != WALLY_OK || is_found)
            continue; /* Already got a partial sig for this pubkey on this input */

        /* From this point, any failure to sign returns an error, since we
        * have the key to sign this input we are expected to be able to */

        if (!input_get_scriptcode(input, txin->index, &scriptcode, &scriptcode_len)) {
            ret = WALLY_EINVAL; /* Couldn't find the script to sign with */
            goto cleanup;
        }

        sighash = input->sighash ? input->sighash : WALLY_SIGHASH_ALL;

        if (input->witness_utxo) {
            size_t type;

            ret = wally_scriptpubkey_get_type(scriptcode, scriptcode_len, &type);
            if (ret != WALLY_OK)
                goto cleanup;

            if (type == WALLY_SCRIPT_TYPE_P2WPKH) {
                ret = wally_scriptpubkey_p2pkh_from_bytes(&scriptcode[2],
                                                          HASH160_LEN, 0,
                                                          wpkh_sc, sizeof(wpkh_sc),
                                                          &scriptcode_len);
                if (ret != WALLY_OK)
                    goto cleanup;

                scriptcode = wpkh_sc;
            } else if (type == WALLY_SCRIPT_TYPE_P2WSH && input->witness_script) {
                unsigned char p2wsh[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
                size_t written;

                ret = wally_witness_program_from_bytes(input->witness_script,
                                                       input->witness_script_len,
                                                       WALLY_SCRIPT_SHA256,
                                                       p2wsh, sizeof(p2wsh),
                                                       &written);
                if (ret != WALLY_OK)
                    goto cleanup;

                if (scriptcode_len != sizeof(p2wsh) ||
                    memcmp(p2wsh, scriptcode, sizeof(p2wsh))) {
                    ret = WALLY_EINVAL;
                    goto cleanup;

                }

                scriptcode = input->witness_script;
                scriptcode_len = input->witness_script_len;
            }
            else {
                ret = WALLY_EINVAL; /* Unknown scriptPubKey type/not enough info */
                goto cleanup;
            }

#ifdef BUILD_ELEMENTS
            if (is_elements)
                ret = wally_tx_get_elements_signature_hash(tx, i,
                                                           scriptcode, scriptcode_len,
                                                           input->witness_utxo->value,
                                                           input->witness_utxo->value_len,
                                                           sighash,
                                                           WALLY_TX_FLAG_USE_WITNESS,
                                                           signature_hash, SHA256_LEN);
            else
#endif /* BUILD_ELEMENTS */
            ret = wally_tx_get_btc_signature_hash(tx, i,
                                                  scriptcode, scriptcode_len,
                                                  input->witness_utxo->satoshi,
                                                  sighash,
                                                  WALLY_TX_FLAG_USE_WITNESS,
                                                  signature_hash, SHA256_LEN);
            if (ret != WALLY_OK)
                goto cleanup;
        } else if (input->utxo) {
            if (!is_matching_txid(input->utxo,
                                  txin->txhash, sizeof(txin->txhash))) {
                ret = WALLY_EINVAL; /* prevout doesn't match this input */
                goto cleanup;
            }

            ret = wally_tx_get_btc_signature_hash(tx, i,
                                                  scriptcode, scriptcode_len,
                                                  0, sighash, 0,
                                                  signature_hash, SHA256_LEN);
            if (ret != WALLY_OK)
                goto cleanup;
        }

        ret = psbt_input_sign(input, key, key_len,
                              input->keypaths.items[keypath_index].key,
                              input->keypaths.items[keypath_index].key_len,
                              signature_hash, SHA256_LEN, flags);
        if (ret != WALLY_OK)
            goto cleanup;
    }

cleanup:
    wally_tx_free(tx);
    return ret;
}

static bool finalize_p2pkh(struct wally_psbt_input *input)
{
    unsigned char script[WALLY_SCRIPTSIG_P2PKH_MAX_LEN];
    size_t script_len;
    const struct wally_map_item *sig;

    if (input->signatures.num_items != 1)
        return false; /* Must be single key, single sig */

    sig = &input->signatures.items[0];

    if (wally_scriptsig_p2pkh_from_der(sig->key, sig->key_len,
                                       sig->value, sig->value_len,
                                       script, sizeof(script),
                                       &script_len) != WALLY_OK)
        return false;

    if (!clone_bytes(&input->final_scriptsig, script, script_len))
        return false;
    input->final_scriptsig_len = script_len;
    return true;
}

static bool finalize_p2sh_wrapped(struct wally_psbt_input *input)
{
    unsigned char *script;
    size_t script_len, push_len;

    /* P2SH wrapped witness: add scriptSig pushing the redeemScript */
    script_len = script_get_push_size(input->redeem_script_len);
    if ((script = wally_malloc(script_len)) != NULL &&
        wally_script_push_from_bytes(input->redeem_script,
                                     input->redeem_script_len, 0,
                                     script, script_len,
                                     &push_len) == WALLY_OK) {
        input->final_scriptsig = script;
        input->final_scriptsig_len = push_len;
        return true;
    }
    /* Failed: clear caller-created witness stack before returning */
    wally_free(script);
    wally_tx_witness_stack_free(input->final_witness);
    input->final_witness = NULL;
    return false;
}

static bool finalize_p2wpkh(struct wally_psbt_input *input)
{
    const struct wally_map_item *sig;

    if (input->signatures.num_items != 1)
        return false; /* Must be single key, single sig */

    sig = &input->signatures.items[0];

    if (wally_witness_p2wpkh_from_der(sig->key, sig->key_len,
                                      sig->value, sig->value_len,
                                      &input->final_witness) != WALLY_OK)
        return false;

    return input->redeem_script ? finalize_p2sh_wrapped(input) : true;
}

static bool finalize_multisig(struct wally_psbt_input *input,
                              const unsigned char *out_script, size_t out_script_len,
                              bool is_witness, bool is_p2sh)
{
    unsigned char sigs[EC_SIGNATURE_LEN * 15];
    uint32_t sighashes[15];
    const unsigned char *p = out_script, *end = p + out_script_len;
    size_t threshold, n_pubkeys, n_found = 0, i;
    bool ret = false;

    if (!script_is_op_n(out_script[0], false, &threshold) ||
        input->signatures.num_items < threshold ||
        !script_is_op_n(out_script[out_script_len - 2], false, &n_pubkeys) ||
        n_pubkeys > 15)
        goto fail; /* Failed to parse or invalid script */

    ++p; /* Skip the threshold */

    /* Collect signatures corresponding to pubkeys in the multisig script */
    for (i = 0; i < n_pubkeys && p < end; ++i) {
        size_t opcode_size, found_pubkey_len;
        const unsigned char *found_pubkey;
        const struct wally_map_item *found_sig;
        size_t sig_index;

        if (script_get_push_size_from_bytes(p, end - p,
                                            &found_pubkey_len) != WALLY_OK ||
            script_get_push_opcode_size_from_bytes(p, end - p,
                                                   &opcode_size) != WALLY_OK)
            goto fail; /* Script is malformed, bail */

        p += opcode_size;
        found_pubkey = p;
        p += found_pubkey_len; /* Move to next pubkey push */

        /* Find the associated signature for this pubkey */
        if (wally_map_find(&input->signatures,
                           found_pubkey, found_pubkey_len,
                           &sig_index) != WALLY_OK || !sig_index)
            continue; /* Not found: try the next pubkey in the script */

        found_sig = &input->signatures.items[sig_index - 1];

        /* Sighash is appended to the DER signature */
        sighashes[n_found] = found_sig->value[found_sig->value_len - 1];
        /* Convert the DER signature to compact form */
        if (wally_ec_sig_from_der(found_sig->value, found_sig->value_len - 1,
                                  sigs + n_found * EC_SIGNATURE_LEN,
                                  EC_SIGNATURE_LEN) != WALLY_OK)
            continue; /* Failed to parse, try next pubkey */

        if (++n_found == threshold)
            break; /* We have enough signatures, ignore any more */
    }

    if (n_found != threshold)
        goto fail; /* Failed to find enough signatures */

    if (is_witness) {
        if (wally_witness_multisig_from_bytes(out_script, out_script_len,
                                              sigs, n_found * EC_SIGNATURE_LEN,
                                              sighashes, n_found,
                                              0, &input->final_witness) != WALLY_OK)
            goto fail;

        if (is_p2sh && !finalize_p2sh_wrapped(input))
            goto fail;
    } else {
        size_t max_len = n_found * (EC_SIGNATURE_DER_MAX_LEN + 2) + out_script_len;
        unsigned char *script = wally_malloc(max_len);
        size_t script_len;

        if (!script ||
            wally_scriptsig_multisig_from_bytes(out_script, out_script_len,
                                                sigs, n_found * EC_SIGNATURE_LEN,
                                                sighashes, n_found, 0,
                                                script, max_len,
                                                &script_len) != WALLY_OK) {
            wally_free(script);
            goto fail;
        }
        input->final_scriptsig = script;
        input->final_scriptsig_len = script_len;
    }
    ret = true;
fail:
    wally_clear_2(sigs, sizeof(sigs), sighashes, sizeof(sighashes));
    return ret;
}

int wally_psbt_finalize(struct wally_psbt *psbt)
{
    size_t i;
    int ret;

    struct wally_tx *tx;

    if (!psbt || (psbt->version == 0 && (!psbt->tx || psbt->tx->num_inputs != psbt->num_inputs)))
        return WALLY_EINVAL;

    if (psbt->tx) {
        if ((ret = wally_tx_clone_alloc(psbt->tx, 0, &tx)) != WALLY_OK)
            return ret;
    }
    else {
        if ((ret = psbt_build_tx(psbt, &tx)) != WALLY_OK)
            return ret;
    }

    for (i = 0; i < psbt->num_inputs; ++i) {
        struct wally_psbt_input *input = &psbt->inputs[i];
        const uint32_t utxo_index = tx->inputs[i].index;

        /* Script for this input. originally set to the input's scriptPubKey, but in the case of a p2sh/p2wsh
         * input, it will be eventually be set to the unhashed script, if known */
        unsigned char *out_script = NULL;
        size_t out_script_len, type;
        bool is_witness = false, is_p2sh = false;

        if (input->final_scriptsig || input->final_witness)
            continue; /* Already finalized */

        /* Note that if we patch libwally to supply the non-witness utxo tx field (tx) for
        * witness inputs also, we'll need a different way to signal p2sh-p2wpkh scripts */
        if (input->witness_utxo && input->witness_utxo->script_len > 0) {
            out_script = input->witness_utxo->script;
            out_script_len = input->witness_utxo->script_len;
            is_witness = true;
        } else if (input->utxo && utxo_index < input->utxo->num_outputs) {
            struct wally_tx_output *out = &input->utxo->outputs[utxo_index];
            out_script = out->script;
            out_script_len = out->script_len;
        }
        if (input->redeem_script) {
            out_script = input->redeem_script;
            out_script_len = input->redeem_script_len;
            is_p2sh = true;
        }
        if (input->witness_script) {
            out_script = input->witness_script;
            out_script_len = input->witness_script_len;
            is_witness = true;
        }

        if (!out_script)
            continue; /* We need an outscript to do anything */

        if (wally_scriptpubkey_get_type(out_script, out_script_len, &type) != WALLY_OK)
            continue; /* Can't identify the type, skip */

        switch(type) {
        case WALLY_SCRIPT_TYPE_P2PKH:
            if (!finalize_p2pkh(input))
                continue;
            break;
        case WALLY_SCRIPT_TYPE_P2WPKH:
            if (!finalize_p2wpkh(input))
                continue;
            break;
        case WALLY_SCRIPT_TYPE_MULTISIG:
            if (!finalize_multisig(input, out_script, out_script_len, is_witness, is_p2sh))
                continue;
            break;
        default:
            continue; /* Can't finalize this input, skip */
        }

        /* Clear non-final things */
        clear_and_free(input->redeem_script, input->redeem_script_len);
        input->redeem_script_len = 0;
        input->redeem_script = NULL;
        clear_and_free(input->witness_script, input->witness_script_len);
        input->witness_script_len = 0;
        input->witness_script = NULL;
        wally_map_clear(&input->keypaths);
        wally_map_clear(&input->signatures);
        input->sighash = 0;
    }

    wally_tx_free(tx);
    return WALLY_OK;
}

int wally_psbt_extract(const struct wally_psbt *psbt, struct wally_tx **output)
{
    struct wally_tx *result = NULL;
    size_t i;
    int ret;

    TX_CHECK_OUTPUT;

    if (!psbt || (psbt->version == 0 && (!psbt->tx || !psbt->num_inputs || !psbt->num_outputs ||
                                         psbt->tx->num_inputs != psbt->num_inputs ||
                                         psbt->tx->num_outputs != psbt->num_outputs)))
        return WALLY_EINVAL;

    if (psbt->tx) {
        if ((ret = wally_tx_clone_alloc(psbt->tx, 0, &result)) != WALLY_OK)
            return ret;
    }
    else {
        if ((ret = psbt_build_tx(psbt, &result)) != WALLY_OK)
            return ret;
    }

    for (i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input *input = &psbt->inputs[i];
        struct wally_tx_input *tx_input = &result->inputs[i];

        if (!input->final_scriptsig && !input->final_witness) {
            ret = WALLY_EINVAL;
            break;
        }

        if (input->final_scriptsig) {
            if (tx_input->script) {
                /* Our global tx shouldn't have a scriptSig */
                ret = WALLY_EINVAL;
                break;
            }
            if (!clone_bytes(&tx_input->script,
                             input->final_scriptsig,
                             input->final_scriptsig_len)) {
                ret = WALLY_ENOMEM;
                break;
            }
            tx_input->script_len = input->final_scriptsig_len;
        }
        if (input->final_witness) {
            if (tx_input->witness) {
                /* Our global tx shouldn't have a witness */
                ret = WALLY_EINVAL;
                break;
            }
            ret = wally_tx_witness_stack_clone_alloc(input->final_witness,
                                                     &tx_input->witness);
            if (ret != WALLY_OK)
                break;
        }
    }

    if (ret == WALLY_OK)
        *output = result;
    else
        wally_tx_free(result);
    return ret;
}

int wally_psbt_is_elements(const struct wally_psbt *psbt, size_t *written)
{
    if (!psbt || !written)
        return WALLY_EINVAL;

    *written = memcmp(psbt->magic, PSET_MAGIC, sizeof(PSET_MAGIC)) ? 0 : 1;
    return WALLY_OK;
}

#if defined(SWIG) || defined (SWIG_JAVA_BUILD) || defined (SWIG_PYTHON_BUILD) || defined (SWIG_JAVASCRIPT_BUILD)

static struct wally_psbt_input *psbt_get_input(const struct wally_psbt *psbt, size_t index)
{
    return psbt && index < psbt->num_inputs ? &psbt->inputs[index] : NULL;
}

static struct wally_psbt_output *psbt_get_output(const struct wally_psbt *psbt, size_t index)
{
    return psbt && index < psbt->num_outputs ? &psbt->outputs[index] : NULL;
}

/* Getters for maps in inputs/outputs */
#define PSBT_GET_K(typ, name) \
    int wally_psbt_get_ ## typ ## _ ## name ## s_size(const struct wally_psbt *psbt, size_t index, \
                                                      size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written) return WALLY_EINVAL; \
        *written = p->name ## s ? p->name ## s->num_items : 0; \
        return WALLY_OK; \
    }

#define PSBT_GET_M(typ, name) \
    int wally_psbt_get_ ## typ ## _ ## name ## s_size(const struct wally_psbt *psbt, size_t index, \
                                                      size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written) return WALLY_EINVAL; \
        *written = p->name ## s.num_items; \
        return WALLY_OK; \
    } \
    int wally_psbt_find_ ## typ ## _ ## name(const struct wally_psbt *psbt, size_t index, \
                                             const unsigned char *key, size_t key_len, size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !key || !key_len || !written) return WALLY_EINVAL; \
        return wally_psbt_ ## typ ## _find_ ## name(p, key, key_len, written); \
    } \
    int wally_psbt_get_ ## typ ## _ ## name(const struct wally_psbt *psbt, size_t index, \
                                            size_t subindex, unsigned char *bytes_out, size_t len, size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !bytes_out || !len || !written || subindex >= p->name ## s.num_items) return WALLY_EINVAL; \
        *written = p->name ## s.items[subindex].value_len; \
        if (*written <= len) \
            memcpy(bytes_out, p->name ## s.items[subindex].value, *written); \
        return WALLY_OK; \
    } \
    int wally_psbt_get_ ## typ ## _ ## name ## _len(const struct wally_psbt *psbt, size_t index, \
                                                    size_t subindex, size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written || subindex >= p->name ## s.num_items) return WALLY_EINVAL; \
        *written = p->name ## s.items[subindex].value_len; \
        return WALLY_OK; \
    }


/* Get a binary buffer value from an input/output */
#define PSBT_GET_B(typ, name) \
    int wally_psbt_get_ ## typ ## _ ## name ## _len(const struct wally_psbt *psbt, size_t index, \
                                                    size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written) return WALLY_EINVAL; \
        *written = p->name ## _len; \
        return WALLY_OK; \
    } \
    int wally_psbt_get_ ## typ ## _ ## name(const struct wally_psbt *psbt, size_t index, \
                                            unsigned char *bytes_out, size_t len, size_t *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written) return WALLY_EINVAL; \
        *written = p->name ## _len; \
        if (p->name ## _len <= len) \
            memcpy(bytes_out, p->name, p->name ## _len); \
        return WALLY_OK; \
    }

/* Set a binary buffer value on an input/output */
#define PSBT_SET_B(typ, name) \
    int wally_psbt_set_ ## typ ## _ ## name(struct wally_psbt *psbt, size_t index, \
                                            const unsigned char *name, size_t name ## _len) { \
        return wally_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), name, name ## _len); \
    }

/* Get an integer value from an input/output */
#define PSBT_GET_I(typ, name, inttyp) \
    int wally_psbt_get_ ## typ ## _ ## name(const struct wally_psbt *psbt, size_t index, \
                                            inttyp *written) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (written) *written = 0; \
        if (!p || !written) return WALLY_EINVAL; \
        *written = p->name; \
        return WALLY_OK; \
    }

/* Set an integer value on an input/output */
#define PSBT_SET_I(typ, name, inttyp) \
    int wally_psbt_set_ ## typ ## _ ## name(struct wally_psbt *psbt, size_t index, \
                                            inttyp v) { \
        return wally_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), v); \
    }

/* Get a struct from an input/output */
#define PSBT_GET_S(typ, name, structtyp, clonefn) \
    int wally_psbt_get_ ## typ ## _ ## name ## _alloc(const struct wally_psbt *psbt, size_t index, \
                                                      struct structtyp **output) { \
        struct wally_psbt_ ## typ *p = psbt_get_ ## typ(psbt, index); \
        if (output) *output = NULL; \
        if (!p || !output) return WALLY_EINVAL; \
        return clonefn(p->name, output); \
    }

/* Set a struct on an input/output */
#define PSBT_SET_S(typ, name, structtyp) \
    int wally_psbt_set_ ## typ ## _ ## name(struct wally_psbt *psbt, size_t index, \
                                            const struct structtyp *p) { \
        return wally_psbt_ ## typ ## _set_ ## name(psbt_get_ ## typ(psbt, index), p); \
    }

PSBT_GET_S(input, utxo, wally_tx, tx_clone_alloc)
PSBT_GET_S(input, witness_utxo, wally_tx_output, wally_tx_output_clone_alloc)
PSBT_GET_B(input, redeem_script)
PSBT_GET_B(input, witness_script)
PSBT_GET_B(input, final_scriptsig)
PSBT_GET_S(input, final_witness, wally_tx_witness_stack, wally_tx_witness_stack_clone_alloc)
PSBT_GET_M(input, keypath)
PSBT_GET_M(input, signature)
PSBT_GET_M(input, unknown)
PSBT_GET_I(input, sighash, size_t)
PSBT_GET_B(input, previous_txid)
PSBT_GET_I(input, output_index, size_t)
PSBT_GET_I(input, sequence, size_t)
PSBT_GET_I(input, required_locktime, size_t)

PSBT_SET_S(input, utxo, wally_tx)
PSBT_SET_S(input, witness_utxo, wally_tx_output)
PSBT_SET_B(input, redeem_script)
PSBT_SET_B(input, witness_script)
PSBT_SET_B(input, final_scriptsig)
PSBT_SET_S(input, final_witness, wally_tx_witness_stack)
PSBT_SET_S(input, keypaths, wally_map)
PSBT_SET_S(input, signatures, wally_map)
PSBT_SET_S(input, unknowns, wally_map)
PSBT_SET_I(input, sighash, uint32_t)
PSBT_SET_B(input, previous_txid)
PSBT_SET_I(input, output_index, uint32_t)
PSBT_SET_I(input, sequence, uint32_t)
int wally_psbt_clear_input_sequence(struct wally_psbt *psbt, size_t index) {
    return wally_psbt_input_clear_sequence(psbt_get_input(psbt, index));
}
PSBT_SET_I(input, required_locktime, uint32_t)
int wally_psbt_clear_input_required_locktime(struct wally_psbt *psbt, size_t index) {
    return wally_psbt_input_clear_required_locktime(psbt_get_input(psbt, index));
}

#ifdef BUILD_ELEMENTS
PSBT_GET_I(input, issuance_amount, size_t)
PSBT_GET_B(input, issuance_amount_commitment)
PSBT_GET_B(input, issuance_amount_rangeproof)
PSBT_GET_B(input, issuance_amount_blind_proof)
PSBT_GET_B(input, blinding_nonce)
PSBT_GET_B(input, entropy)
PSBT_GET_I(input, inflation_keys, size_t)
PSBT_GET_B(input, inflation_keys_commitment)
PSBT_GET_B(input, inflation_keys_rangeproof)
PSBT_GET_B(input, inflation_keys_blind_proof)
PSBT_GET_S(input, pegin_tx, wally_tx, tx_clone_alloc)
PSBT_GET_B(input, txoutproof)
PSBT_GET_B(input, genesis_blockhash)
PSBT_GET_B(input, claim_script)
PSBT_GET_I(input, pegin_amount, size_t)
PSBT_GET_S(input, pegin_witness, wally_tx_witness_stack, wally_tx_witness_stack_clone_alloc)
PSBT_GET_B(input, utxo_rangeproof)

PSBT_SET_I(input, issuance_amount, uint64_t)
int wally_psbt_clear_input_issuance_amount(struct wally_psbt *psbt, size_t index) {
    return wally_psbt_input_clear_issuance_amount(psbt_get_input(psbt, index));
}
PSBT_SET_B(input, issuance_amount_commitment)
PSBT_SET_B(input, issuance_amount_rangeproof)
PSBT_SET_B(input, issuance_amount_blind_proof)
PSBT_SET_B(input, blinding_nonce)
PSBT_SET_B(input, entropy)
PSBT_SET_I(input, inflation_keys, uint64_t)
int wally_psbt_clear_input_inflation_keys(struct wally_psbt *psbt, size_t index) {
    return wally_psbt_input_clear_inflation_keys(psbt_get_input(psbt, index));
}
PSBT_SET_B(input, inflation_keys_commitment)
PSBT_SET_B(input, inflation_keys_rangeproof)
PSBT_SET_B(input, inflation_keys_blind_proof)
PSBT_SET_S(input, pegin_tx, wally_tx)
PSBT_SET_B(input, txoutproof)
PSBT_SET_B(input, genesis_blockhash)
PSBT_SET_B(input, claim_script)
PSBT_SET_I(input, pegin_amount, uint64_t)
int wally_psbt_clear_input_pegin_amount(struct wally_psbt *psbt, size_t index) {
    return wally_psbt_input_clear_pegin_amount(psbt_get_input(psbt, index));
}
PSBT_SET_S(input, pegin_witness, wally_tx_witness_stack)
PSBT_SET_B(input, utxo_rangeproof)
#endif /* BUILD_ELEMENTS */

PSBT_GET_B(output, redeem_script)
PSBT_GET_B(output, witness_script)
PSBT_GET_M(output, keypath)
PSBT_GET_M(output, unknown)
PSBT_GET_I(output, amount, uint64_t)
PSBT_GET_B(output, script)

PSBT_SET_B(output, redeem_script)
PSBT_SET_B(output, witness_script)
PSBT_SET_S(output, keypaths, wally_map)
PSBT_SET_S(output, unknowns, wally_map)
PSBT_SET_I(output, amount, uint64_t)
PSBT_SET_B(output, script)
#ifdef BUILD_ELEMENTS
PSBT_GET_B(output, blinding_pubkey)
PSBT_GET_B(output, value_commitment)
PSBT_GET_B(output, asset_commitment)
PSBT_GET_B(output, nonce)
PSBT_GET_B(output, rangeproof)
PSBT_GET_B(output, surjectionproof)

PSBT_SET_B(output, blinding_pubkey)
PSBT_SET_B(output, value_commitment)
PSBT_SET_B(output, asset_commitment)
PSBT_SET_B(output, nonce)
PSBT_SET_B(output, rangeproof)
PSBT_SET_B(output, surjectionproof)
#endif /* BUILD_ELEMENTS */

#endif /* SWIG/SWIG_JAVA_BUILD/SWIG_PYTHON_BUILD/SWIG_JAVASCRIPT_BUILD */
