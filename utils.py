import greenaddress as gdk
from wallycore import *
from subprocess import call, Popen, PIPE
import json, os, requests, sys, time


# Config: adjust as needed

# Network to use. localtest is for Green developer use only
#NETWORK = 'localtest-liquid'
#NETWORK = 'electrum-localtest-liquid'
NETWORK = 'testnet-liquid' # Liquid Testnet (Multisig)
#NETWORK = 'electrum-testnet-liquid' # Liquid Testnet (Singlesig)
GDK_INIT_DETAILS = {
    'datadir': os.getenv('PWD', '.') + '/.wally_swap_test',
    'log_level': 'warn'
}
gdk.init(GDK_INIT_DETAILS)

# User mnemonics. None = create new wallets each time
ALICE_MNEMONIC = 'kidney found mammal link toy patient repair duty very mesh panda frozen perfect upset caution future oblige senior reduce decade bicycle ethics story client'
BOB_MNEMONIC = 'party occur rare design lunar royal useless opinion hunt vanish rigid fold'

# Account Type choices:
# Multisig: '2of2' (Non-AMP) or '2of2_no_recovery' (AMP, default).
# Singlesig: 'p2sh-p2wpkh' (default), 'p2wpkh', 'p2pkh'
ACCOUNT_TYPE = '2of2_no_recovery'

# Amounts to send. overwritten by whatever the faucet gives us for testnet
class VALUES:
    LBTC_SATOSHI = None
    ASSET_SATOSHI = None

# Amount of L-BTC to pay in fees
LBTC_FEE_SATOSHI = 500

# Parsing flags for PSETs. WALLY_PSBT_PARSE_FLAG_STRICT is strongly suggested
# in order to catch malicious or otherwise invalid PSETs that Elements will
# allow. Set 0 to disable.
PSBT_PARSE_MODE = WALLY_PSBT_PARSE_FLAG_STRICT

# Whether to add input explicit value/asset proofs for non-intermediated swap scenarios.
# NOTE: This exposes the unblinded value/asset and should only be used for
#       swaps and other co-operatively created/blinded/signed txs where
#       the other party requires this information to blind, but you do not
#       wish to share blinding factors, for example the liquidex swap protocol.
ADD_EXPLICIT_PROOFS = False

NETWORKS = gdk.get_networks()
NETWORK_INFO = NETWORKS[NETWORK]
LBTC_ASSET = NETWORK_INFO['policy_asset']

if 'localtest' in NETWORK:
    CORE_CLI = '/home/user/develop/work/ga-backend/ga_setup/liquidd/bin/liquid-cli'
    CORE_CONF = '-conf=/home/user/develop/work/ga-backend/ga_setup/.liquidd.conf'


def h2b(h):
    return hex_to_bytes(h)

def h2b_rev(h):
    return hex_to_bytes(h)[::-1]

def b2h(b):
    return hex_from_bytes(b)

def b2h_rev(b):
    return hex_from_bytes(b[::-1])

def core_cmd(cmd, *args):
    """Run a liquidd command"""
    call_args = [CORE_CLI, CORE_CONF, cmd] + list(args)
    #print('CALL:', ' '.join(call_args))
    (stdout, stderr) = Popen(call_args, stdout=PIPE).communicate()
    return stdout.decode('utf-8').strip()

def core_fund():
    """Fund the core wallet with L-BTC and a new asset ASSET (for regtest)"""
    if 'localtest' in NETWORK:
        core_address = core_cmd('getnewaddress')
        core_cmd('generatetoaddress', '1', core_address)
        details = json.loads(core_cmd('issueasset', str(1), '0'))
        return {'name': '', 'asset_id': details['asset']}
    else:
        # Testnet: use TEST or AMP asset
        if ACCOUNT_TYPE == '2of2_no_recovery':
            name, asset_id = 'amp', 'bea126b86ac7f7b6fc4709d1bb1a8482514a68d35633a5580d50b18504d5c322'
        else:
            name, asset_id = 'test', '38fca2d939696061a8f76d4e6b5eecd54e3b4221c846f24a6b279e79952850a5'
        return {'name': name, 'asset_id': asset_id}

def core_send_blinded(asset_id, asset_addr, asset_swap_details, gaid):
    """Send blinded LBTC or an asset to a user from the core wallet (for regtest)"""
    if 'localtest' in NETWORK:
        # Note we send back to core here to ensure the tx is blinded
        if not VALUES.LBTC_SATOSHI:
            VALUES.LBTC_SATOSHI, VALUES.ASSET_SATOSHI = int(1e8), int(1e8)
        satoshi = VALUES.LBTC_SATOSHI if asset_id == LBTC_ASSET else VALUES.ASSET_SATOSHI
        core_address = core_cmd('getnewaddress')
        amounts = json.dumps({asset_addr: str(satoshi/1e8), core_address: '0.001'})
        assets =  json.dumps({asset_addr: asset_id, core_address: LBTC_ASSET})
        core_cmd('sendmany', '', amounts, '0', '', '["'+core_address+'"]',
                 'false', '1', 'unset', assets, 'false')
        sent_addr = asset_addr
    else:
        # Use the liquidtestnet.com faucet to fetch L-BTC/TEST/AMP asset
        name = 'lbtc' if asset_id == LBTC_ASSET else asset_swap_details['name']
        params = {'action':name,
                  'address': gaid if name == 'amp' else asset_addr }
        result = requests.get(url='https://liquidtestnet.com/faucet',
                              params=params).text
        to_search = ' ' + name.upper() + ' to address '
        end = result.find(to_search)
        assert end != -1, 'unexpected faucet response: ' + result
        satoshi = int(float(result[:end].split(' ')[-1]) * 10**8)
        if name == 'lbtc':
            VALUES.LBTC_SATOSHI = satoshi
        elif name == 'amp':
            satoshi //= 10**8 # AMP asset is reported as satoshi, not BTC
            VALUES.ASSET_SATOSHI = satoshi
        else:
            VALUES.ASSET_SATOSHI = satoshi
        sent_addr = result[end + len(to_search):].split(' ')[0]
    if asset_id != LBTC_ASSET:
        asset_swap_details['satoshi'] = satoshi
    return sent_addr

def gdk_create_session(mnemonic):
    """Create and return a new gdk session"""
    net_params = {'name': NETWORK}
    session = gdk.Session(net_params)
    session.net_params = net_params
    session.mnemonic = mnemonic
    credentials = {'mnemonic': session.mnemonic}
    session.register_user({}, credentials).resolve()
    session.post_login_data = session.login_user({}, credentials).resolve()
    # Create a subaccount of the right type if we don't have one already
    subaccounts = session.get_subaccounts().resolve()['subaccounts']
    matching_sa = [sa for sa in subaccounts if sa['type'] == ACCOUNT_TYPE]
    if matching_sa:
        session.subaccount = matching_sa[0]
    else:
        session.subaccount = session.create_subaccount({
            'name': 'wally_swap_test',
            'type': ACCOUNT_TYPE}).resolve()
    return session

def gdk_get_address_details(session, sent_to):
    # The testnet faucet takes a GAID and returns us the address that was
    # sent to. We need the full address details, so search for them in our
    # address history.
    # Note: we could also get this from our UTXOs with confs=0.
    details = {'subaccount': session.subaccount['pointer']}
    while True:
        addrs = session.get_previous_addresses(details).resolve()
        found = [a for a in addrs['list'] if a['address'] == sent_to]
        if found:
            return found[0]
        details['last_pointer'] = addrs['last_pointer'] # Try next page

def gdk_wait_for_utxo(user, asset_id, pointer, num_confs=0):
    """Wait for user to receive a utxo for an asset and return it"""
    # Note this does a busy wait since this is only for testing.
    # Production apps should process transaction notifications instead.
    count = 0
    while True:
        utxos = user.get_unspent_outputs({'subaccount': user.subaccount['pointer'],
                                          'num_confs': num_confs}).resolve()
        asset_utxos = utxos.get('unspent_outputs', dict()).get(asset_id, list())
        asset_utxos = [u for u in asset_utxos if u['pointer'] >= pointer]
        if asset_utxos:
            return asset_utxos[0]
        count += 1
        if count > 120 and num_confs:
            # See if the UTXO appears unconfirmed, if so return it.
            # FIXME: this happens on Liquid with AMP UTXOs only: find out why
            utxos = user.get_unspent_outputs({'subaccount': user.subaccount['pointer'],
                                              'num_confs': 0}).resolve()
            asset_utxos = utxos.get('unspent_outputs', dict()).get(asset_id, list())
            asset_utxos = [u for u in asset_utxos if u['pointer'] >= pointer]
            if asset_utxos:
                return asset_utxos[0] # Assume confirmed to work around gdk issue
            count = 0
        time.sleep(1)
