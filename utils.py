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
BOB_MNEMONIC = 'cement medal castle alcohol ivory festival sphere shell dish inform twelve dove school direct amount focus media laundry already capable remind woman crumble blanket'

# Account Type choices:
# Multisig: '2of2' (Non-AMP, default) or '2of2_no_recovery' (AMP).
# Singlesig: 'p2sh-p2wpkh' (default), 'p2wpkh', 'p2pkh'
ACCOUNT_TYPE = '2of2'

# Amounts to send. overwritten by whatever the faucet gives us for testnet
class VALUES:
    LBTC_SATOSHI = None
    ASSET_SATOSHI = None

# Amount of L-BTC to pay in fees
LBTC_FEE_SATOSHI = 500

NETWORKS = gdk.get_networks()
NETWORK_INFO = NETWORKS[NETWORK]
LBTC_ASSET = NETWORK_INFO['policy_asset']

if 'localtest' in NETWORK:
    CORE_CLI = '/home/user/develop/work/ga-backend/ga_setup/liquidd/bin/liquid-cli'
    CORE_CONF = '-conf=/home/user/develop/work/ga-backend/ga_setup/.liquidd.conf'

    if NETWORK_INFO['server_type'] == 'electrum':
        # Hack the RPC port to 19002 for testing
        # FIXME: Make this the gdk default for electrum-localtest
        NETWORK_INFO['electrum_url'] = NETWORKS['localtest']['electrum_url']
        gdk.register_network(NETWORK, NETWORK_INFO)

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

def core_send_blinded(asset_id, asset_addr, asset_swap_details):
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
    else:
        # Use the liquidtestnet.com faucet to fetch L-BTC/TEST/AMP asset
        name = 'lbtc' if asset_id == LBTC_ASSET else asset_swap_details['name']
        result = requests.get(url='https://liquidtestnet.com/faucet',
                              params={'address':asset_addr, 'action':name}).text
        end = result.find(' ' + name.upper() + ' to address ')
        assert end != -1, 'unexpected faucet response: ' + result
        satoshi = int(float(result[:end].split(' ')[-1]) * 10**8)
        if name == 'lbtc':
            VALUES.LBTC_SATOSHI = satoshi
        else:
            VALUES.ASSET_SATOSHI = satoshi
    if asset_id != LBTC_ASSET:
        asset_swap_details['satoshi'] = satoshi

def gdk_create_session(mnemonic):
    """Create and return a new gdk session"""
    net_params = {'name': NETWORK}
    session = gdk.Session(net_params)
    session.net_params = net_params
    session.mnemonic = mnemonic
    credentials = {'mnemonic': session.mnemonic}
    session.register_user({}, credentials).resolve()
    session.post_login_data = session.login_user({}, credentials).resolve()
    sa = 0 # Default to the initial subaccount
    if ACCOUNT_TYPE in ['2of2_no_recovery', 'p2wpkh', 'p2pkh']:
        # Non-default subaccount type: create it
        sa = session.create_subaccount({
            'name': 'wally_swap_test',
            'type': ACCOUNT_TYPE}).resolve()['pointer']
    session.subaccount = sa
    return session

def gdk_wait_for_utxo(user, asset_id, pointer, return_all=False):
    """Wait for user to receive a utxo for an asset and return it"""
    # Note this does a busy wait since this is only for testing.
    # Production apps should process transaction notifications instead.
    while True:
        utxos = user.get_unspent_outputs({'subaccount': user.subaccount,
                                          'num_confs': 0}).resolve()
        asset_utxos = utxos.get('unspent_outputs', dict()).get(asset_id, list())
        asset_utxos = [u for u in asset_utxos if u['pointer'] >= pointer]
        if asset_utxos:
            return asset_utxos if return_all else asset_utxos[0]
        time.sleep(1)
