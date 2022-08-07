from utils import *
import secrets

def setup_alice():
    # Alice gets LBTC_SATOSHI + LBTC_FEE_SATOSHI L-BTC @ alice.lbtc_address, with
    # the UTXO in alice.lbtc_utxo
    alice = gdk_create_session(gdk.generate_mnemonic())
    alice.asset_id = LBTC_ASSET
    addr_details = {'subaccount': alice.subaccount}
    alice.lbtc_address = alice.get_receive_address(addr_details).resolve()
    amount = LBTC_SATOSHI + LBTC_FEE_SATOSHI
    core_send_blinded(LBTC_ASSET, alice.lbtc_address['address'], amount)
    alice.lbtc_utxo = gdk_wait_for_utxo(alice, alice.subaccount, LBTC_ASSET)
    return alice

def setup_bob(asset_details):
    # Bob gets ASSET_SATOSHI bob.asset_id @ bob.asset_address, with
    # the UTXO in bob.asset_utxo
    bob = gdk_create_session(gdk.generate_mnemonic())
    bob.asset_id = asset_details['asset']
    addr_details = {'subaccount': bob.subaccount}
    bob.asset_address = bob.get_receive_address(addr_details).resolve()
    core_send_blinded(bob.asset_id, bob.asset_address['address'], ASSET_SATOSHI)
    bob.asset_utxo = gdk_wait_for_utxo(bob, bob.subaccount, bob.asset_id)
    return bob

def add_input_utxo(psbt, utxo, addr):
    # Add a users UTXO from gdk as a PSBT input
    assert utxo['script'] == addr['blinding_script']

    # Add the input to the psbt
    idx = psbt_get_num_inputs(psbt)
    seq = 0xFFFFFFFE # RBF not enabled for liquid yet
    psbt_add_tx_input_at(psbt, idx, 0,
                         tx_input_init(h2b_rev(utxo['txhash']), utxo['pt_idx'],
                                       seq, None, None))

    # Non-witness UTXO
    funding_tx_hex = core_cmd('getrawtransaction', utxo['txhash'])
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
    script = h2b(addr['script'])
    if utxo['address_type'] in ['csv', 'p2wsh']:
        # Note: 'p2wsh' for multisig is p2sh wrapped p2wsh.
        # For Green multisig swaps, Green server signing currently requires
        # that swap inputs are *provably* segwit in order to eliminate
        # malleation from the processing state machine.
        # For p2sh-p2wsh wrapped inputs, this currently requires passing
        # the witness program as the redeem script when signing; The server
        # uses this to validate the input before signing with the actual
        # script.
        # TODO: This isn't documented in the gdk or backend API docs, and
        # should probably be done with a PSET input extension field instead.
        script = witness_program_from_bytes(script, WALLY_SCRIPT_SHA256)
    psbt_set_input_redeem_script(psbt, idx, script)
    return idx

def create_alice_partial_swap_psbt(alice, psbt, asset_details):
    # Add Alice's L-BTC input
    idx = add_input_utxo(psbt, alice.lbtc_utxo, alice.lbtc_address)

    # Add Alice's ASSET output
    addr_details = {'subaccount': alice.subaccount}
    addr = alice.get_receive_address(addr_details).resolve()
    alice.asset_receive_address = addr
    asset_tag = bytearray([1]) + h2b_rev(asset_details['asset']) # Unblinded
    value = tx_confidential_value_from_satoshi(asset_details['satoshi']) # Unblinded
    txout = tx_elements_output_init(h2b(addr['blinding_script']), asset_tag,
                                    value, h2b(addr['blinding_key']))
    output_idx = psbt_get_num_outputs(psbt)
    psbt_add_tx_output_at(psbt, output_idx, 0, txout)
    return psbt

def create_bob_full_swap_psbt(bob, psbt, asset_details):
    # Add Bob's ASSET input
    idx = add_input_utxo(psbt, bob.asset_utxo, bob.asset_address)

    # Add Bob's L-BTC output
    bob_details = {'subaccount': alice.subaccount}
    addr = bob.get_receive_address(bob_details).resolve()
    bob.lbtc_receive_address = addr
    lbtc_tag = bytearray([1]) + h2b_rev(LBTC_ASSET) # Unblinded
    value = tx_confidential_value_from_satoshi(LBTC_SATOSHI) # Unblinded
    txout = tx_elements_output_init(h2b(addr['blinding_script']), lbtc_tag,
                                    value, h2b(addr['blinding_key']))
    output_idx = psbt_get_num_outputs(psbt)
    psbt_add_tx_output_at(psbt, output_idx, 0, txout)

    # Add the fee output
    value = tx_confidential_value_from_satoshi(LBTC_FEE_SATOSHI) # Unblinded
    fee_txout = tx_elements_output_init(None, lbtc_tag, value)
    psbt_add_tx_output_at(psbt, output_idx + 1, 0, fee_txout)
    return psbt

def get_blinding_data(alice, bob):
    # Get the input blinding data required to blind the psbt
    values, vbfs, assets, abfs = [map_init(2, None) for _ in range(4)]
    # Input 0 is Alice's L-BTC
    map_add_integer(values, 0, tx_confidential_value_from_satoshi(alice.lbtc_utxo['satoshi']))
    map_add_integer(vbfs, 0, h2b_rev(alice.lbtc_utxo["amountblinder"]))
    map_add_integer(assets, 0, h2b_rev(LBTC_ASSET))
    map_add_integer(abfs, 0, h2b_rev(alice.lbtc_utxo["assetblinder"]))
    # Input 1 is Bob's ASSET
    map_add_integer(values, 1, tx_confidential_value_from_satoshi(bob.asset_utxo['satoshi']))
    map_add_integer(vbfs, 1, h2b_rev(bob.asset_utxo["amountblinder"]))
    map_add_integer(assets, 1, h2b_rev(bob.asset_utxo['asset_id']))
    map_add_integer(abfs, 1, h2b_rev(bob.asset_utxo["assetblinder"]))
    # For each output to blind, we need 32 bytes of entropy for each of:
    # - Output assetblinder
    # - Output amountblinder
    # - Ephemeral rangeproof ECDH key
    # - Explicit value rangeproof
    # - Surjectionproof seed
    num_outputs_to_blind = 2
    entropy = secrets.token_bytes(num_outputs_to_blind * 5 * 32)
    return values, vbfs, assets, abfs, entropy

def get_blinding_nonce(psbt, ephemeral_keys, output_index):
    ephemeral_key = map_get_item(ephemeral_keys, output_index)
    blinding_pubkey = psbt_get_output_blinding_public_key(psbt, output_index)
    return ecdh_nonce_hash(blinding_pubkey, ephemeral_key)

if __name__ == '__main__':
    # Regtest: fund the core wallet with LBTC and issue the asset
    asset_details = core_fund()
    print('Asset details: ', json.dumps(asset_details, indent=2))

    # Set up Alice and Bob with UTXOs to swap
    alice = setup_alice()
    bob = setup_bob(asset_details)

    # Alice then Bob add their inputs and outputs to the swap PSET
    psbt = psbt_init(2, 0, 0, 0, WALLY_PSBT_INIT_PSET)
    psbt = create_alice_partial_swap_psbt(alice, psbt, asset_details)
    psbt = create_bob_full_swap_psbt(bob, psbt, asset_details)

    print('Alice UTXO: ' + json.dumps(alice.lbtc_utxo, indent=2))
    print('Alice L-BTC Address: ' + json.dumps(alice.lbtc_address, indent=2))
    print('Bob UTXO: ' + json.dumps(bob.asset_utxo, indent=2))
    print('Bob ASSET Address: ' + json.dumps(bob.asset_address, indent=2))

    # PSET now has both inputs: set Blinder Index for each output.
    # Ordinarily, the blinder index would refer to an input the user owns,
    # however for swaps this is reversed.
    psbt_set_output_blinder_index(psbt, 0, 1) # Alices output comes from Bob
    psbt_set_output_blinder_index(psbt, 1, 0) # Bobs output comes from Alice
    print('Decoded pre-blinding PSBT: ' + core_cmd('decodepsbt', psbt_to_base64(psbt, 0)))

    # Get the blinding data required and blind the PSBT
    # Note that any party can blind once they have the given blinding data.
    # TODO: Agree on a method to pass blinding data out-of-band.
    values, vbfs, assets, abfs, entropy = get_blinding_data(alice, bob)
    flags = 0
    ephemeral_keys = psbt_blind(psbt, values, vbfs, assets, abfs, entropy, flags)
    b64 = psbt_to_base64(psbt, 0)

    # Get the blinding nonces for both blinded outputs.
    # These are only required for AMP subaccounts, but we pass them
    # in all cases since they are cheap to compute.
    alice_nonce = get_blinding_nonce(psbt, ephemeral_keys, 0)
    bob_nonce = get_blinding_nonce(psbt, ephemeral_keys, 1)
    nonces = [b2h(alice_nonce), b2h(bob_nonce), '']

    print('Blinded PSBT: ' + b64)
    print('Decoded Blinded PSBT: ' + core_cmd('decodepsbt', b64))
    print('Analyzed Blinded PSBT: ' + core_cmd('analyzepsbt', b64))

    # psbt_get_details from gdk can be used to examine each parties inputs and outputs
    alice_gdk_details = alice.psbt_get_details({'psbt': b64, 'utxos': [alice.lbtc_utxo]}).resolve()
    print('Alice gdk psbt_get_details: ' + json.dumps(alice_gdk_details, indent=2))

    bob_gdk_details = bob.psbt_get_details({'psbt': b64, 'utxos': [bob.asset_utxo]}).resolve()
    print('Bob gdk psbt_get_details: ' + json.dumps(bob_gdk_details, indent=2))

    # Bob signs his asset input in the PSBT
    bob_sign_details = bob.psbt_sign({
        'psbt': b64,
        'utxos': [bob.asset_utxo],
        'blinding_nonces': nonces}).resolve()
    b64 = bob_sign_details['psbt']
    print('Bob signed PSBT: ' + json.dumps(bob_sign_details, indent=2))

    # Alice then signs her LBTC input in the PSBT
    alice_sign_details = alice.psbt_sign({
        'psbt': b64,
        'utxos': [alice.lbtc_utxo],
        'blinding_nonces': nonces}).resolve()
    b64 = alice_sign_details['psbt']
    print('Alice signed PSBT: ' + json.dumps(alice_sign_details, indent=2))

    #print('Decoded Signed PSBT: ' + core_cmd('decodepsbt', b64))
    #print('Analyzed Signed PSBT: ' + core_cmd('analyzepsbt', b64))

    # Finalize the PSBT to get the signed raw transaction hex
    # FIXME: finalize with wally
    finalized = json.loads(core_cmd('finalizepsbt', b64, 'true'))

    # Alice then sends the transaction via gdk (it can be broadcast by any method)
    txid = alice.broadcast_transaction(finalized['hex'])
    print('Sent Txid: ' + txid)

    # Wait for Alice and Bob to see the new tx, updating their UTXOs
    gdk_wait_for_utxo(alice, alice.subaccount, bob.asset_id)
    alice_utxos = alice.get_unspent_outputs({'subaccount': alice.subaccount, 'num_confs': 0}).resolve()
    alice_utxos = alice_utxos['unspent_outputs']
    print('Alice UTXOs after swap:' + json.dumps(alice_utxos, indent=2))

    gdk_wait_for_utxo(bob, bob.subaccount, alice.asset_id)
    bob_utxos = bob.get_unspent_outputs({'subaccount': bob.subaccount, 'num_confs': 0}).resolve()
    bob_utxos = bob_utxos['unspent_outputs']
    print('Bob UTXOs after swap:' + json.dumps(bob_utxos, indent=2))

    # TODO: Make sure the newly received UTXOs are spendable
