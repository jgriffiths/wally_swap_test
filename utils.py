import greenaddress as gdk
from wallycore import *
from subprocess import call, Popen, PIPE
import json, os, sys


# Config: adjust as needed
CORE_CLI = '/home/user/develop/work/ga-backend/ga_setup/liquidd/bin/liquid-cli'
CORE_CONF = '-conf=/home/user/develop/work/ga-backend/ga_setup/.liquidd.conf'
NETWORK = 'localtest-liquid'
GDK_INIT_DETAILS = {
    'datadir': os.getenv('PWD', '.') + '/.wally_swap_test',
    'log_level': 'warn'
}
gdk.init(GDK_INIT_DETAILS)
LBTC_ASSET = gdk.get_networks()[NETWORK]['policy_asset']
LBTC_SATOSHI = int(1e8)
LBTC_FEE_SATOSHI = 5000
ASSET_SATOSHI = int(1e8)

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
    core_address = core_cmd('getnewaddress')
    core_cmd('generatetoaddress', '1', core_address)
    asset_details = json.loads(core_cmd('issueasset', str(ASSET_SATOSHI/1e8), '0'))
    asset_details['satoshi'] = ASSET_SATOSHI
    return asset_details

def core_send_blinded(asset_id, asset_addr, amount):
    """Send blinded LBTC or an asset to a user from the core wallet (for regtest)"""
    # Note we send back to core here to ensure the tx is blinded
    core_address = core_cmd('getnewaddress')
    amounts = json.dumps({asset_addr: str(amount/1e8), core_address: '0.001'})
    assets =  json.dumps({asset_addr: asset_id, core_address: LBTC_ASSET})
    core_cmd('sendmany', '', amounts, '0', '', '["'+core_address+'"]',
             'false', '1', 'unset', assets, 'false')

def gdk_create_session(mnemonic):
    """Create and return a new gdk session"""
    net_params = {'name': NETWORK}
    session = gdk.Session(net_params)
    session.net_params = net_params
    session.mnemonic = mnemonic
    credentials = {'mnemonic': session.mnemonic}
    session.register_user({}, credentials).resolve()
    session.post_login_data = session.login_user({}, credentials).resolve()
    return session

def gdk_wait_for_utxo(user, subaccount, asset_id):
    """Wait for user to receive a utxo for an asset and return it"""
    # Note this does a busy wait since this is only for testing.
    # Production apps should process transaction notifications instead.
    while True:
        utxos = user.get_unspent_outputs({'subaccount': subaccount,
                                          'num_confs': 0}).resolve()
        asset_utxos = utxos.get('unspent_outputs', dict()).get(asset_id, list())
        if asset_utxos:
            return asset_utxos[0]
