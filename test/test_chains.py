# Copyright(C) 2017 by Abe developers.

# test_chains.py: test Abe Chain code with static data

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/agpl.html>.

import pytest
import os
import json
import Abe.Chain as Chain
import Abe.util as util


# Chains to test
CHAINNAMES = ["Bitcoin"]
CHAINS = {}
for chain in CHAINNAMES:
    CHAINS[chain] = Chain.create(chain)

# Script types map between Abe/Client, from Bitcoin-core's script/standard.cpp
SCRIPT = {
    Chain.SCRIPT_TYPE_INVALID:  'nonstandard',
    Chain.SCRIPT_TYPE_UNKNOWN:  'nonstandard',
    Chain.SCRIPT_TYPE_PUBKEY:   'pubkey',
    Chain.SCRIPT_TYPE_ADDRESS:  'pubkeyhash',
    Chain.SCRIPT_TYPE_BURN:     'nulldata',
    Chain.SCRIPT_TYPE_MULTISIG: 'multisig',
    Chain.SCRIPT_TYPE_P2SH:     'scripthash',
    99: 'witness_v0_keyhash',    # TODO: P2WKH
    98: 'witness_v0_scripthash', # TODO: P2WSH
}


def txparams():
    basepath = os.path.join(os.path.split(__file__)[0], "data")

    for chainname, chain in CHAINS.iteritems():
        txfile = os.path.join(basepath, "%s_tx.json" % chainname)
        if not os.path.exists(txfile):
            # Skip (return single element) if data submodule hasn't been imported
            yield (chainname,)
            return

        with open(txfile, 'r') as fd:
            txdata = json.load(fd)
        for tx in txdata:
            if os.environ.get('ABE_TEST') == 'quick' and \
                    len(tx[0]) > 1048576: # 512k after decoding
                # Also skip large TX with quick tests
                yield (tx[0],)
            else:
                # Trailing rubbish ensures we don't read past end of tx
                binary_tx = tx[0].decode('hex') + 'some trailing rubbish'
                yield (chain, chain.parse_transaction(binary_tx), tx[1])


@pytest.fixture(scope="module", params=txparams())
def txdata(request):
    if len(request.param) == 1:
        param, = request.param
        if param in CHAINS:
            pytest.skip('Skipping all tests for %s (Import data submodule '
                        'to run Chain tests)' % param)
        else:
            pytest.skip('Skipping large TX (%i bytes)' % (len(param) / 2))
    yield request.param

def test_tx_version(txdata):
    chain, tx, reftx = txdata
    assert tx['version'] == reftx['version']

def test_tx_locktime(txdata):
    chain, tx, reftx = txdata
    assert tx['lockTime'] == reftx['locktime']

def test_tx_txin_cnt(txdata):
    chain, tx, reftx = txdata
    assert len(tx['txIn']) == len(reftx['vin'])

def test_tx_txout_cnt(txdata):
    chain, tx, reftx = txdata
    assert len(tx['txOut']) == len(reftx['vout'])

def test_tx_txins(txdata):
    chain, tx, reftx = txdata
    for txin in xrange(len(tx['txIn'])):
        assert tx['txIn'][txin]['sequence'] == \
                reftx['vin'][txin]['sequence']

        if 'txid' in reftx['vin'][txin]:
            assert tx['txIn'][txin]['prevout_hash'] == \
                    reftx['vin'][txin]['txid'].decode('hex')[::-1]
            assert tx['txIn'][txin]['prevout_n'] == \
                    reftx['vin'][txin]['vout']
        else:
            # Coinbase
            assert tx['txIn'][txin]['prevout_hash'] == '\0' * 32
            assert tx['txIn'][txin]['scriptSig'] == \
                    reftx['vin'][txin]['coinbase'].decode('hex')

def test_tx_witness(txdata):
    chain, tx, reftx = txdata
    for txin in xrange(len(tx['txIn'])):
        assert len(tx['txIn'][txin]['txWitness']) == \
                len(reftx['vin'][txin].get('txinwitness', []))
        for wit in xrange(len(tx['txIn'][txin]['txWitness'])):
            assert tx['txIn'][txin]['txWitness'][wit] == \
                    reftx['vin'][txin]['txinwitness'][wit].decode('hex')

def test_tx_txouts(txdata):
    chain, tx, reftx = txdata
    for txout in xrange(len(tx['txOut'])):
        assert tx['txOut'][txout]['scriptPubKey'] == \
                reftx['vout'][txout]['scriptPubKey']['hex'].decode('hex')
        # Why do we even use floats? For the purpose of this test discarding
        # rounding error should be sufficient...
        assert tx['txOut'][txout]['value'] == \
                int(round(reftx['vout'][txout]['value'] * 10e7))

def test_tx_txOut_scripts(txdata):
    chain, tx, reftx = txdata
    for txout in xrange(len(tx['txOut'])):
        if len(tx['txOut'][txout]['scriptPubKey']) > 0:
            txotype, data = chain.parse_txout_script(tx['txOut'][txout]['scriptPubKey'])
            assert SCRIPT[txotype] == reftx['vout'][txout]['scriptPubKey']['type']
            if txotype in (Chain.SCRIPT_TYPE_P2SH, Chain.SCRIPT_TYPE_ADDRESS):
                version = chain.address_version
                # This is probably only valid for Bitcoin/Testnet
                # FIXME: Check What Would Abe Do (WWAD)
                if txotype == Chain.SCRIPT_TYPE_P2SH:
                    version = '\x05' if version=='\x00' else '\xC4'
                assert util.hash_to_address(version, data) == \
                        reftx['vout'][txout]['scriptPubKey']['addresses'][0]

def test_tx_size(txdata):
    chain, tx, reftx = txdata
    assert tx['size'] == reftx['size']

def test_tx_vsize(txdata):
    chain, tx, reftx = txdata
    assert tx['vsize'] == reftx['vsize']

def test_tx_hash(txdata):
    chain, tx, reftx = txdata
    assert tx['__hash__'] == reftx['hash'].decode('hex')[::-1]

def test_tx_hash_reserialize(txdata):
    chain, tx, reftx = txdata
    assert chain.transaction_hash(chain.serialize_transaction(tx)) == \
            reftx['hash'].decode('hex')[::-1]

def test_tx_id(txdata):
    chain, tx, reftx = txdata
    assert chain.transaction_hash(tx['__data__']) == \
            reftx['txid'].decode('hex')[::-1]

