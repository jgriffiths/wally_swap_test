from utils import *
import secrets

# Whether to dump the decoded PSETs using core
DECODE=False

def setup_alice(asset_swap_details):
    # Alice gets LBTC_SATOSHI L-BTC @ alice.lbtc_address, with
    # the UTXO in alice.lbtc_utxo
    global ALICE_MNEMONIC
    if not ALICE_MNEMONIC:
        ALICE_MNEMONIC = gdk.generate_mnemonic()
        print('Alice mnemonic: ' + ALICE_MNEMONIC)
    alice = gdk_create_session(ALICE_MNEMONIC)
    alice.asset_id = LBTC_ASSET
    addr_details = {'subaccount': alice.subaccount['pointer']}
    alice.lbtc_address = alice.get_receive_address(addr_details).resolve()
    num_confs = 0
    sent_to = core_send_blinded(LBTC_ASSET, alice.lbtc_address['address'],
                                asset_swap_details, alice.subaccount['receiving_id'])
    if sent_to != alice.lbtc_address['address']:
        alice.lbtc_address = gdk_get_address_details(alice, sent_to) # From faucet to GAID
        assert sent_to == alice.lbtc_address['address']
        num_confs = 1 # AMP assets must be confirmed to swap
    alice.lbtc_utxo = gdk_wait_for_utxo(alice, LBTC_ASSET, alice.lbtc_address['pointer'], num_confs)
    return alice

def setup_bob(asset_swap_details):
    # Bob gets ASSET_SATOSHI bob.asset_id @ bob.asset_address, with
    # the UTXO in bob.asset_utxo
    global BOB_MNEMONIC
    if not BOB_MNEMONIC:
        BOB_MNEMONIC = gdk.generate_mnemonic()
        print('Bob mnemonic: ' + BOB_MNEMONIC)
    bob = gdk_create_session(BOB_MNEMONIC)
    bob.asset_id = asset_swap_details['asset_id']
    addr_details = {'subaccount': bob.subaccount['pointer']}
    bob.asset_address = bob.get_receive_address(addr_details).resolve()
    sent_to = core_send_blinded(bob.asset_id, bob.asset_address['address'],
                                asset_swap_details, bob.subaccount['receiving_id'])
    num_confs = 0
    if sent_to != bob.asset_address['address']:
        bob.asset_address = gdk_get_address_details(bob, sent_to) # From faucet to GAID
        assert sent_to == bob.asset_address['address']
        num_confs = 1 # AMP assets must be confirmed to swap
    bob.asset_utxo = gdk_wait_for_utxo(bob, bob.asset_id, bob.asset_address['pointer'], num_confs)
    return bob

def user_key_from_utxo(session, utxo):
    seed = bip39_mnemonic_to_seed512(session.mnemonic, None)
    version = BIP32_VER_TEST_PRIVATE if 'test' in NETWORK else BIP32_VER_MAIN_PRIVATE
    master_extkey = bip32_key_from_seed(seed, version, 0)
    path = utxo['user_path']
    derived_extkey = bip32_key_from_parent_path(master_extkey, path,
                                                BIP32_FLAG_SKIP_HASH)
    assert b2h(bip32_key_get_pub_key(derived_extkey)) == utxo['public_key']
    return derived_extkey

def add_input_utxo(session, psbt, utxo, addr):
    # Add a users UTXO from gdk as a PSET input
    if 'script' in utxo:
        # FIXME: script missing from singlesig
        assert utxo['script'] == addr['blinding_script']

    # Add the input to the psbt
    idx = psbt_get_num_inputs(psbt)
    seq = 0xFFFFFFFE # RBF not enabled for liquid yet
    psbt_add_tx_input_at(psbt, idx, 0,
                         tx_input_init(h2b_rev(utxo['txhash']), utxo['pt_idx'],
                                       seq, None, None))

    # Non-witness UTXO: Get from gdk (with caching)
    funding_tx_hex = session.get_transaction_details(utxo['txhash'])['transaction']
    funding_tx = tx_from_hex(funding_tx_hex, WALLY_TX_FLAG_USE_ELEMENTS)
    # Not needed for non-segwit/Liquid
    #psbt_set_input_utxo(psbt, idx, funding_tx)

    # Witness UTXO
    # We *could* construct a tx output from the utxo data here, but
    # since we have the utxo tx already, this is simpler.
    psbt_set_input_witness_utxo_from_tx(psbt, idx, funding_tx, utxo['pt_idx'])

    # UTXO rangeproof
    psbt_set_input_utxo_rangeproof(psbt, idx,
                                   tx_get_output_rangeproof(funding_tx,
                                                            utxo['pt_idx']))
    # Redeemscript
    pubkey = h2b(utxo['public_key']) if 'public_key' in utxo else None
    if utxo['address_type'] in ['csv', 'p2wsh']:
        # Note: 'csv' and 'p2wsh' for multisig is p2sh wrapped p2wsh.
        witness_script = utxo['prevout_script']
        psbt_set_input_witness_script(psbt, idx, h2b(witness_script))
        scriptpubkey = h2b(addr['script'])
        script = witness_program_from_bytes(scriptpubkey, WALLY_SCRIPT_SHA256)
        psbt_set_input_redeem_script(psbt, idx, script)
    elif utxo['address_type'] in ['p2sh-p2wpkh']:
        script = witness_program_from_bytes(pubkey, WALLY_SCRIPT_HASH160)
        psbt_set_input_redeem_script(psbt, idx, script)
    elif utxo['address_type'] not in ['p2wpkh', 'p2pkh']:
        assert False, 'unknown address type ' + utxo['address_type']

    if ADD_EXPLICIT_PROOFS:
        psbt_generate_input_explicit_proofs(psbt, idx, utxo['satoshi'],
                                            h2b_rev(utxo["asset_id"]),
                                            h2b_rev(utxo["assetblinder"]),
                                            h2b_rev(utxo["amountblinder"]),
                                            secrets.token_bytes(32))
    # Key path
    if pubkey:
        user_extkey = user_key_from_utxo(session, utxo)
        fingerprint = bip32_key_get_fingerprint(user_extkey)
        keypaths = map_keypath_public_key_init(1)
        map_keypath_add(keypaths, pubkey, fingerprint, utxo['user_path'])
        psbt_set_input_keypaths(psbt, idx, keypaths)
    return idx

def create_alice_partial_swap_psbt(alice, psbt, asset_swap_details):
    # Add Alice's L-BTC input
    idx = add_input_utxo(alice, psbt, alice.lbtc_utxo, alice.lbtc_address)

    # Add Alice's ASSET output
    addr_details = {'subaccount': alice.subaccount['pointer']}
    addr = alice.get_receive_address(addr_details).resolve()
    alice.asset_receive_address = addr
    asset_tag = bytearray([1]) + h2b_rev(asset_swap_details['asset_id']) # Unblinded
    value = tx_confidential_value_from_satoshi(asset_swap_details['satoshi']) # Unblinded
    txout = tx_elements_output_init(h2b(addr['blinding_script']), asset_tag,
                                    value, None)
    output_idx = psbt_get_num_outputs(psbt)
    psbt_add_tx_output_at(psbt, output_idx, 0, txout)
    psbt_set_output_blinding_public_key(psbt, output_idx, h2b(addr['blinding_key']))
    return psbt

def create_bob_full_swap_psbt(bob, psbt, asset_swap_details):
    # Add Bob's ASSET input
    idx = add_input_utxo(bob, psbt, bob.asset_utxo, bob.asset_address)

    # Add Bob's L-BTC output
    addr_details = {'subaccount': bob.subaccount['pointer']}
    addr = bob.get_receive_address(addr_details).resolve()
    bob.lbtc_receive_address = addr
    lbtc_tag = bytearray([1]) + h2b_rev(LBTC_ASSET) # Unblinded
    satoshi = VALUES.LBTC_SATOSHI - LBTC_FEE_SATOSHI
    value = tx_confidential_value_from_satoshi(satoshi) # Unblinded
    txout = tx_elements_output_init(h2b(addr['blinding_script']), lbtc_tag,
                                    value, None)
    output_idx = psbt_get_num_outputs(psbt)
    psbt_add_tx_output_at(psbt, output_idx, 0, txout)
    psbt_set_output_blinding_public_key(psbt, output_idx, h2b(addr['blinding_key']))

    # Add the fee output
    value = tx_confidential_value_from_satoshi(LBTC_FEE_SATOSHI) # Unblinded
    fee_txout = tx_elements_output_init(None, lbtc_tag, value)
    psbt_add_tx_output_at(psbt, output_idx + 1, 0, fee_txout)
    return psbt

def set_blinding_data(idx, utxo, values, vbfs, assets, abfs):
    map_add_integer(values, idx, tx_confidential_value_from_satoshi(utxo['satoshi']))
    map_add_integer(vbfs, idx, h2b_rev(utxo["amountblinder"]))
    map_add_integer(assets, idx, h2b_rev(utxo["asset_id"]))
    map_add_integer(abfs, idx, h2b_rev(utxo["assetblinder"]))

def get_entropy(num_outputs_to_blind):
    # For each output to blind, we need 32 bytes of entropy for each of:
    # - Output assetblinder
    # - Output amountblinder
    # - Ephemeral rangeproof ECDH key
    # - Explicit value rangeproof
    # - Surjectionproof seed
    return secrets.token_bytes(num_outputs_to_blind * 5 * 32)

def get_blinding_nonce(psbt, ephemeral_keys, output_index):
    ephemeral_key = map_get_item(ephemeral_keys, 0)
    blinding_pubkey = psbt_get_output_blinding_public_key(psbt, output_index)
    return ecdh_nonce_hash(blinding_pubkey, ephemeral_key)

if __name__ == '__main__':
    # Regtest: fund the core wallet with LBTC and issue the asset
    asset_swap_details = core_fund()
    print('Asset details: ', json.dumps(asset_swap_details, indent=2))

    # Set up Alice and Bob with UTXOs to swap
    alice = setup_alice(asset_swap_details)
    print('Alice UTXO: ' + json.dumps(alice.lbtc_utxo, indent=2))
    print('Alice L-BTC Address: ' + json.dumps(alice.lbtc_address, indent=2))
    bob = setup_bob(asset_swap_details)
    print('Bob UTXO: ' + json.dumps(bob.asset_utxo, indent=2))
    print('Bob ASSET Address: ' + json.dumps(bob.asset_address, indent=2))

    # Alice adds her input and output to a new swap PSET
    psbt = psbt_init(2, 0, 0, 0, WALLY_PSBT_INIT_PSET)
    psbt = create_alice_partial_swap_psbt(alice, psbt, asset_swap_details)
    # Along with the PSET, Alice must send her input blinding info
    alice_values, alice_vbfs, alice_assets, alice_abfs = [map_init(1, None) for _ in range(4)]
    set_blinding_data(0, alice.lbtc_utxo,
                      alice_values, alice_vbfs, alice_assets, alice_abfs)

    # Alice sends the resulting PSET and blinding info to Bob
    psbt_b64_to_send = psbt_to_base64(psbt, 0)


    # Bob adds his input and output to the swap PSET
    psbt = psbt_from_base64(psbt_b64_to_send, PSBT_PARSE_MODE)
    psbt = create_bob_full_swap_psbt(bob, psbt, asset_swap_details)
    # And collects his own blinding data
    bob_values, bob_vbfs, bob_assets, bob_abfs = [map_init(1, None) for _ in range(4)]
    set_blinding_data(1, bob.asset_utxo,
                      bob_values, bob_vbfs, bob_assets, bob_abfs)

    # PSET is now complete: set Blinder Index for each output.
    # Ordinarily, the blinder index would refer to an input the user owns,
    # however for swaps this is reversed.
    psbt_set_output_blinder_index(psbt, 0, 1) # Alices output comes from Bob
    psbt_set_output_blinder_index(psbt, 1, 0) # Bobs output comes from Alice

    # Perform the blinding in two steps for testing purposes.
    # 1. Bob blinds his output (1) using Alices values and blinders.
    entropy = get_entropy(1)
    flags = 0
    bob_ephemeral_keys = psbt_blind(psbt, alice_values, alice_vbfs,
                                    alice_assets, alice_abfs, entropy, 1, flags)
    bob_nonce = get_blinding_nonce(psbt, bob_ephemeral_keys, 1)
    print('Pre-blinding PSET: ' + psbt_to_base64(psbt, 0))
    if DECODE:
        print('Decoded pre-blinding PSET: ' + core_cmd('decodepsbt', psbt_to_base64(psbt, 0)))

    # 2. Bob blinds Alices output (0) using his values and blinders
    entropy = get_entropy(1)
    alice_ephemeral_keys = psbt_blind(psbt, bob_values, bob_vbfs,
                                      bob_assets, bob_abfs, entropy, 0, flags)
    alice_nonce = get_blinding_nonce(psbt, alice_ephemeral_keys, 0)

    # Pass the blinding nonces for both blinded outputs.
    # These are only required for AMP subaccounts, but we pass them
    # in all cases since they are cheap to compute.
    # Note the empty nonce for the final fee output which is never blinded.
    nonces = [b2h(alice_nonce), b2h(bob_nonce), '']

    b64 = psbt_to_base64(psbt, 0)
    print('Blinded PSET: ' + b64)
    if DECODE:
        print('Decoded Blinded PSET: ' + core_cmd('decodepsbt', b64))
        print('Analyzed Blinded PSET: ' + core_cmd('analyzepsbt', b64))

    # psbt_get_details from gdk can be used to examine each parties inputs and outputs
    alice_gdk_details = alice.psbt_get_details({'psbt': b64, 'utxos': [alice.lbtc_utxo]}).resolve()
    print('Alice gdk psbt_get_details: ' + json.dumps(alice_gdk_details, indent=2))

    bob_gdk_details = bob.psbt_get_details({'psbt': b64, 'utxos': [bob.asset_utxo]}).resolve()
    print('Bob gdk psbt_get_details: ' + json.dumps(bob_gdk_details, indent=2))

    if SIGN_WITH_GDK or 'electrum' not in NETWORK:
        # Multisig, or singlesig and we are signing with gdk
        # Bob signs his asset input in the PSET
        bob_sign_details = bob.psbt_sign({
            'psbt': b64,
            'utxos': [bob.asset_utxo],
            'blinding_nonces': nonces}).resolve()
        b64 = bob_sign_details['psbt']
        print('Bob signed PSET details: ' + json.dumps(bob_sign_details, indent=2))
        if DECODE:
            print('Decoded Bob signed PSET: ' + core_cmd('decodepsbt', b64))

        # Alice then signs her LBTC input in the PSET
        alice_sign_details = alice.psbt_sign({
            'psbt': b64,
            'utxos': [alice.lbtc_utxo],
            'blinding_nonces': nonces}).resolve()
        b64 = alice_sign_details['psbt']
        print('Alice signed PSET details: ' + json.dumps(alice_sign_details, indent=2))
        if DECODE:
            print('Decoded Alice signed PSET: ' + core_cmd('decodepsbt', b64))
    else:
        # Singlesig, signing manually
        # Bob signs his asset input in the PSET
        psbt = psbt_from_base64(b64, PSBT_PARSE_MODE)
        bob_extkey = user_key_from_utxo(bob, bob.asset_utxo)
        psbt_sign(psbt, bip32_key_get_priv_key(bob_extkey), EC_FLAG_GRIND_R)

        # Alice then signs her LBTC input in the PSET
        alice_extkey = user_key_from_utxo(alice, alice.lbtc_utxo)
        psbt_sign(psbt, bip32_key_get_priv_key(alice_extkey), EC_FLAG_GRIND_R)
        b64 = psbt_to_base64(psbt, 0)

    if DECODE:
        print('Decoded Signed PSET: ' + core_cmd('decodepsbt', b64))
        print('Analyzed Signed PSET: ' + core_cmd('analyzepsbt', b64))

    # Alice finalizes the signed PSET to get the signed raw transaction hex
    psbt = psbt_from_base64(b64, PSBT_PARSE_MODE)
    psbt_finalize(psbt)
    tx = psbt_extract(psbt, 0)
    tx_hex = tx_to_hex(tx, WALLY_TX_FLAG_USE_WITNESS)

    if 'localtest' in NETWORK:
        # Just for testing, verify that core and wally finalize to the same tx
        core_finalized = json.loads(core_cmd('finalizepsbt', b64, 'true'))
        assert tx_hex == core_finalized['hex']

    # Alice then sends the transaction via gdk (it can be broadcast by any method)
    txid = alice.broadcast_transaction(tx_hex)
    print('Sent Txid: ' + txid)

    # Wait for Alice and Bob to see the new tx, updating their UTXOs
    gdk_wait_for_utxo(alice, bob.asset_id, alice.lbtc_address['pointer'] + 1)
    alice_utxos = alice.get_unspent_outputs({'subaccount': alice.subaccount['pointer'],
                                             'num_confs': 0}).resolve()
    alice_utxos = alice_utxos['unspent_outputs']
    print('Alice UTXOs after swap:' + json.dumps(alice_utxos, indent=2))

    gdk_wait_for_utxo(bob, alice.asset_id, bob.asset_address['pointer'] + 1)
    bob_utxos = bob.get_unspent_outputs({'subaccount': bob.subaccount['pointer'],
                                         'num_confs': 0}).resolve()
    bob_utxos = bob_utxos['unspent_outputs']
    print('Bob UTXOs after swap:' + json.dumps(bob_utxos, indent=2))

    # TODO: Make sure the newly received UTXOs are spendable by sending them
    # back to core (or the faucet, for testnet)
