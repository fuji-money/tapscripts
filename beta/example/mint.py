#!/usr/bin/env python3

# pylama:ignore=E501

import os
import sys
import time
import random
import struct
import hashlib

from decimal import Decimal

from typing import Optional, List

from multiprocessing import Process, Lock

import bitcointx
import elementstx

if len(sys.argv) > 3:
    secp256k1_path = sys.argv[3]
    bitcointx.set_custom_secp256k1_path(secp256k1_path)
    elementstx.set_custom_secp256k1_path(secp256k1_path)

from bitcointx import select_chain_params
from bitcointx.wallet import CCoinKey
from bitcointx.util import tagged_hasher

from bitcointx.core.key import tap_tweak_pubkey
from bitcointx.core.serialize import BytesSerializer
from elementstx.core import CoreElementsParams

from bitcointx.rpc import RPCCaller, VerifyRejectedError, JSONRPCError
from bitcointx.core import coins_to_satoshi, satoshi_to_coins, x, lx, b2lx, Uint256
from bitcointx.core.key import XOnlyPubKey, CKey
from bitcointx.core.script import (
    CScript, ScriptElement_Type, TaprootScriptTree, DATA, NUMBER,
    OP_EQUALVERIFY, OP_NUMEQUALVERIFY, OP_DUP, OP_LESSTHANOREQUAL, OP_VERIFY,
    OP_NUMEQUAL, OP_IF, OP_ELSE, OP_ENDIF, OP_LSHIFT, OP_SWAP, OP_SUBSTR,
    OP_ROT, OP_2DUP, OP_TOALTSTACK, OP_CAT, OP_SHA256, OP_FROMALTSTACK,
    OP_SIZE, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG, OP_CHECKLOCKTIMEVERIFY,
    OP_DROP, OP_TUCK, OP_TRUE, OP_RETURN, OP_EQUAL, OP_WITHIN, OP_ADD,
    CScriptWitness
)

from elementstx.wallet import (
    P2TRElementsAddress, CCoinConfidentialAddress,
    P2TRElementsConfidentialAddress, P2WPKHElementsAddress
)
from elementstx.core import (
    CAsset, CElementsTransaction,
    CElementsMutableTransaction, CElementsTxIn, CElementsTxOut,
    CElementsOutPoint, CConfidentialValue, CConfidentialAsset,
    CAssetIssuance, BlindingInputDescriptor,
    BlindingSuccess, UnblindingSuccess
)
from elementstx.core.script import (
    CElementsScript, OP_INSPECTOUTPUTASSET, OP_INSPECTOUTPUTSCRIPTPUBKEY,
    OP_TWEAKVERIFY, OP_INSPECTNUMINPUTS,
    OP_INSPECTINPUTASSET, OP_INSPECTINPUTSCRIPTPUBKEY, OP_INSPECTNUMOUTPUTS,
    OP_CHECKSIGFROMSTACKVERIFY, OP_DIV64, OP_MUL64, OP_ADD64, OP_LE64TOSCRIPTNUM,
    OP_SCRIPTNUMTOLE64, OP_GREATERTHANOREQUAL64, OP_INSPECTOUTPUTVALUE
)

select_chain_params('elements/elementsregtest')

FIXED_FEE_SATOSHI = 10000  # For simplicity, we use fixed fee amount per tx

# NOTE: this is not a real Safe covenant script. We use a simple address
# Instead of the full Safe covenant, because this example shows Mint covenant
# in isolation from other covenants
mock_safe_key = CCoinKey.from_secret_bytes(os.urandom(32))
spk_of_safe_covenant = P2TRElementsAddress.from_pubkey(
    mock_safe_key.pub).to_scriptPubKey()

print("Mock Safe key: ", mock_safe_key,
      "scriptPubKey:", spk_of_safe_covenant.hex())

# must be above certain threshold that would discourage wasteful minting
# attempts using expired price data
MIN_BOND_AMOUNT = 1000

CURRENCY_CODE = b'USD'

LEAF_VERSION = b'\xC4'

# TODO: take below values from command-line arguments

lbtc_precision = 8
price_precision = 2
synth_precision = 2

ORACLE_MESSAGE_TAG = b'le64-price-oracle-X-1.0'
price_message_hasher = tagged_hasher(ORACLE_MESSAGE_TAG)

if price_precision != 2:
    print(f"WARNING: oracle messge format {ORACLE_MESSAGE_TAG.decode('utf-8')}"
          f"expects price precision 2, but it is {price_precision}")

precision_shift = price_precision-synth_precision

lbtc_price = Decimal('10000.32')
lbtc_price_int = int(lbtc_price * Decimal(10)**price_precision)

synth_amount_to_reissue = Decimal('8000.01')
synth_amount_satoshi = int(synth_amount_to_reissue * Decimal(10)**synth_precision)

assert (
    synth_amount_to_reissue * Decimal(10)**synth_precision
    - Decimal(synth_amount_satoshi)
    == Decimal('0')
)
assert (
    lbtc_price * Decimal(10)**price_precision - Decimal(lbtc_price_int)
    == Decimal('0')
)


synth_amount_scaled = int(
    # the 150% over-collateralization ratio is hardcoded,
    # because it is easy to calculate in the covenant code
    (synth_amount_satoshi + synth_amount_satoshi//2)

    * (10**(lbtc_precision+precision_shift))
)

assert synth_amount_scaled < 2**63, \
    (f"precision adjustment calc must fit into signed 64-bit arithmetic, "
     f"but synth_amount_scaled is {synth_amount_scaled:x}")

collateral_amount_satoshi = synth_amount_scaled // lbtc_price_int

print(f'Collateral is {collateral_amount_satoshi} lbtc sat '
      f'({satoshi_to_coins(collateral_amount_satoshi)} lbtc) '
      f'For {synth_amount_satoshi} synth sat ({synth_amount_to_reissue} synth)\n'
      f'With price {lbtc_price} synth per 1 lbtc')

lbtc_price_le64 = struct.pack(b"<q", lbtc_price_int)
bond_amount = max(collateral_amount_satoshi // 10, MIN_BOND_AMOUNT)
minting_fee_satoshi = 1000

# make sure that there's some synth left after substracting minting fee
assert(synth_amount_satoshi - minting_fee_satoshi >= 1000)

# if < 512, then delay is measured in blocks, else in seconds, but with
# 512 second granularity
#
# NOTE: synth burn timestamp is in seconds, so having synth_release_delay
# in blocks while synth burn timestamp is in seconds can result in mismatches
# if the blocks are late or too fast for some reason. Therefore it is advised
# to keep synth_release_delay in seconds, or use blocks for burn delay. But
# also note that there's no code in this example for burn delay to be measured
# in blocks, and it is most likely that real-world oracle won't use blocks
# for timestamp either
synth_release_delay = 512

if synth_release_delay >= 512:
    assert synth_release_delay % 512 == 0, \
        "per-second delay has 512 second granularity"
    # We will set 5 minutes between synth releasse time and burn time
    # in this example. At least 4 blocks should fit into this window
    # with 1-minute inter-block interval
    synth_burn_delay = synth_release_delay+300
    # how long the mock functionary will wait between blocks
    # because the synth release delay granularity is 512 seconds, we can
    # use the same delay as in real Liquid network
    time_between_blocks_in_seconds = 60
else:
    # how long the mock functionary will wait between blocks
    # because the release delay is in blocks with granularity 1, we can use
    # very small delay between blocks, and the example will be completed
    # much faster
    time_between_blocks_in_seconds = 2
    synth_burn_delay = synth_release_delay*time_between_blocks_in_seconds*3

print("synth_release_delay is", synth_release_delay)
print("synth_burn_delay is", synth_burn_delay)

# We don't do anything with the minting fee in this example, so we just
# use a random address. But we need this address to be known by the minter
# to be able to construct the Claim covenant
treasury_fee_address = P2WPKHElementsAddress.from_pubkey(CKey(os.urandom(32)).pub)

print("treasury fee scriptPubKey:", treasury_fee_address.to_scriptPubKey().hex())

console_lock = None

ansi_colors = {
    'minter': '\033[1;32m',  # green
    'burner': '\033[1;35m'  # purple
}
end_color = '\033[0m'


def wait_one_block(rpc: RPCCaller, elements_config_path: str):
    if synth_release_delay < 512:
        time.sleep(2)
    else:
        time.sleep(60)
        rpc = RPCCaller(conf_file=elements_config_path)
    return rpc


def pack_le64(v):
    return struct.pack(b"<q", v)


def find_utxo(rpc, asset, amount):
    lbtc_utxo_list = rpc.listunspent(0, 9999, [], False,
                                     {'asset': asset.to_hex()})

    for utxo in lbtc_utxo_list:
        if utxo['assetblinder'] != "00"*32:
            continue

        # NOTE: we look for utxo reasonably bigger than requested amount,
        # so that there will also be some change. This is just to make
        # the example code simpler and skip the edge case handling
        if coins_to_satoshi(utxo["amount"]) > amount + 1000:
            try:
                rpc.lockunspent(False, [{'txid': utxo['txid'],
                                         'vout': utxo['vout']}])
                return utxo
            except JSONRPCError:
                pass

    assert 0, f"cannot find big enough *_unconfidential_* L-BTC utxo (requested amount {amount}+1000)"


def participant_says(name, msg):
    """A helper function to coordinate
    console message output between processes"""

    color = ansi_colors.get(name.strip().lower(), '')
    console_lock.acquire()
    try:
        print("{}{}: {}{}".format(color, name, msg,
                                  end_color if color else ''))
    finally:
        console_lock.release()


def minter_process(elements_config_path: str, mint_tx: CElementsTransaction,
                   minter_key: CKey, claim_cov_tree: TaprootScriptTree,
                   mint_mediantime: int,
                   lbtc_asset: CAsset, synth_asset: CAsset):
    """A function that simulates the minter"""
    rpc = RPCCaller(conf_file=elements_config_path)

    def say(msg):
        participant_says('minter', msg)

    lbtc_utxo = find_utxo(
        rpc, lbtc_asset,
        collateral_amount_satoshi-bond_amount+FIXED_FEE_SATOSHI)

    lbtc_tx = CElementsTransaction.deserialize(
        x(rpc.getrawtransaction(lbtc_utxo['txid']))
    )

    change_amount = (
        coins_to_satoshi(lbtc_utxo['amount'])
        - collateral_amount_satoshi
        + bond_amount
        - FIXED_FEE_SATOSHI
    )

    synth_recv_addr = CCoinConfidentialAddress(rpc.getnewaddress())

    lbtc_change_addr = CCoinConfidentialAddress(rpc.getnewaddress())

    tx = CElementsMutableTransaction(
        vin=[
            CElementsTxIn(prevout=CElementsOutPoint(
                hash=mint_tx.GetTxid(), n=1)),
            CElementsTxIn(prevout=CElementsOutPoint(
                hash=mint_tx.GetTxid(), n=2)),
            CElementsTxIn(prevout=CElementsOutPoint(
                hash=lx(lbtc_utxo['txid']), n=lbtc_utxo['vout']))
        ],
        vout=[
            CElementsTxOut(
                nValue=CConfidentialValue(collateral_amount_satoshi),
                nAsset=CConfidentialAsset(lbtc_asset),
                scriptPubKey=spk_of_safe_covenant),
            CElementsTxOut(
                nValue=CConfidentialValue(minting_fee_satoshi),
                nAsset=CConfidentialAsset(synth_asset),
                scriptPubKey=treasury_fee_address.to_scriptPubKey()),
            CElementsTxOut(
                nValue=CConfidentialValue(synth_amount_satoshi-minting_fee_satoshi),
                nAsset=CConfidentialAsset(synth_asset),
                scriptPubKey=synth_recv_addr.to_scriptPubKey()),
            CElementsTxOut(
                nValue=CConfidentialValue(change_amount),
                nAsset=CConfidentialAsset(lbtc_asset),
                scriptPubKey=lbtc_change_addr.to_scriptPubKey()),
            CElementsTxOut(nValue=CConfidentialValue(FIXED_FEE_SATOSHI),
                           nAsset=CConfidentialAsset(lbtc_asset))
        ]
    )

    if synth_release_delay < 512:
        tx.vin[0].nSequence = synth_release_delay
        tx.vin[1].nSequence = synth_release_delay
    else:
        # set SEQUENCE_LOCKTIME_TYPE_FLAG so that delay is measured
        # in seconds with 512-second granularity
        tx.vin[0].nSequence = (synth_release_delay // 512) | (1 << 22)
        tx.vin[1].nSequence = (synth_release_delay // 512) | (1 << 22)

    semi_signed_tx_dict = rpc.signrawtransactionwithwallet(tx.serialize().hex())

    tx = CElementsMutableTransaction.deserialize(
        x(semi_signed_tx_dict['hex'])
    ).to_mutable()

    swcb = claim_cov_tree.get_script_with_control_block('release')
    assert swcb is not None
    scr, cb = swcb
    assert isinstance(scr, CElementsScript)

    genesis_block_hash = lx(rpc.getblockhash(0))

    sig = minter_key.sign_schnorr_no_tweak(
        scr.sighash_schnorr(tx, 0, [mint_tx.vout[1], mint_tx.vout[2],
                                    lbtc_tx.vout[lbtc_utxo['vout']]],
                            genesis_block_hash=genesis_block_hash))

    tx.wit.vtxinwit[0].scriptWitness = CScriptWitness(
            [sig, scr, cb])

    sig = minter_key.sign_schnorr_no_tweak(
        scr.sighash_schnorr(tx, 1, [mint_tx.vout[1], mint_tx.vout[2],
                                    lbtc_tx.vout[lbtc_utxo['vout']]],
                            genesis_block_hash=genesis_block_hash))

    tx.wit.vtxinwit[1].scriptWitness = CScriptWitness(
            [sig, scr, cb])

    try:
        rpc.sendrawtransaction(tx.serialize().hex())
        assert 0, "sendrawtransaction should have failed"
    except VerifyRejectedError:
        say("Before-timeout spend failed, as expected")

    while True:
        send_tx_dict = rpc.getrawtransaction(b2lx(mint_tx.GetTxid()), 1)
        if synth_release_delay < 512:
            confirmations = int(send_tx_dict.get('confirmations', 0))
            if confirmations >= synth_release_delay:
                break
            say(f'waiting for {synth_release_delay-confirmations} blocks '
                f'for synth to be released')
        else:
            cur_timestamp = rpc.getblockchaininfo()['mediantime']
            if cur_timestamp > mint_mediantime + synth_release_delay:
                break
            say(f'waiting for timestamp {mint_mediantime + synth_release_delay} '
                f'(current {cur_timestamp}) to claim the synth')

        rpc = wait_one_block(rpc, elements_config_path)

    success_txid = rpc.sendrawtransaction(tx.serialize().hex())

    say(f"Successfully spent release covenant, txid {success_txid}")


def burner_process(elements_config_path, mint_tx: CElementsTransaction,
                   claim_cov_tree: TaprootScriptTree, timestamp: int,
                   lbtc_asset: CAsset, synth_asset: CAsset):
    """A function that simulates a burner who tries to burn
    malicious mint attempts"""
    rpc = RPCCaller(conf_file=elements_config_path)

    def say(msg):
        participant_says('burner', msg)

    loot_recv_addr = CCoinConfidentialAddress(rpc.getnewaddress())

    # Note: we use FIXED_FEE_SATOSHI*2 for the fee to be able
    # to RBF-replace the minter's transaction

    tx = CElementsMutableTransaction(
        vin=[
            CElementsTxIn(prevout=CElementsOutPoint(
                hash=mint_tx.GetTxid(), n=1)),
            CElementsTxIn(prevout=CElementsOutPoint(
                hash=mint_tx.GetTxid(), n=2)),
        ],
        vout=[
            CElementsTxOut(
                nValue=CConfidentialValue(synth_amount_satoshi),
                nAsset=CConfidentialAsset(synth_asset),
                scriptPubKey=CScript([OP_RETURN])),
            CElementsTxOut(
                nValue=CConfidentialValue(bond_amount-FIXED_FEE_SATOSHI*2),
                nAsset=CConfidentialAsset(lbtc_asset),
                scriptPubKey=loot_recv_addr.to_scriptPubKey()),
            CElementsTxOut(nValue=CConfidentialValue(FIXED_FEE_SATOSHI*2),
                           nAsset=CConfidentialAsset(lbtc_asset))
        ]
    )

    tx.vin[0].nSequence = 0xfffffffe
    tx.vin[1].nSequence = 0xfffffffe

    tx.nLockTime = timestamp + synth_burn_delay

    swcb = claim_cov_tree.get_script_with_control_block('burn')
    assert swcb is not None
    scr, cb = swcb

    tx.wit.vtxinwit[0].scriptWitness = CScriptWitness([scr, cb])
    tx.wit.vtxinwit[1].scriptWitness = CScriptWitness([scr, cb])

    while True:
        cur_timestamp = rpc.getblockchaininfo()['mediantime']
        say(f'waiting for timestamp {timestamp + synth_burn_delay} '
            f'(current {cur_timestamp}) to burn the synth')
        if cur_timestamp > timestamp + synth_burn_delay:
            break
        rpc = wait_one_block(rpc, elements_config_path)

    success_txid = rpc.sendrawtransaction(tx.serialize().hex())

    say(f"Successfully burned the synth, txid {success_txid}, "
        f"my loot amounts to {bond_amount-FIXED_FEE_SATOSHI*2} lbtc")


def rt_burn_process(elements_config_path, mint_tx: CElementsTransaction,
                    rei_script_tree: TaprootScriptTree,
                    rei_token: CAsset, rei_token_amount: int,
                    rei_token_blinding_key: CKey,
                    lbtc_asset: CAsset, synth_asset: CAsset,
                    treasury_key_for_rt_burn: CKey):
    """A function that simulates a treasury that burns the reissuance token"""
    rpc = RPCCaller(conf_file=elements_config_path)

    def say(msg):
        participant_says('rt_burn', msg)

    lbtc_utxo = find_utxo(
        rpc, lbtc_asset, FIXED_FEE_SATOSHI+1000)

    lbtc_tx = CElementsTransaction.deserialize(
        x(rpc.getrawtransaction(lbtc_utxo['txid']))
    )

    lbtc_amount = coins_to_satoshi(lbtc_utxo["amount"])

    change_address = CCoinConfidentialAddress(rpc.getnewaddress())

    tx = CElementsMutableTransaction(
        vin=[
            CElementsTxIn(prevout=CElementsOutPoint(
                hash=mint_tx.GetTxid(), n=0)),
            CElementsTxIn(prevout=CElementsOutPoint(
                hash=lx(lbtc_utxo['txid']), n=lbtc_utxo['vout']))
        ],
        vout=[
            CElementsTxOut(
                nValue=CConfidentialValue(rei_token_amount),
                nAsset=CConfidentialAsset(rei_token),
                scriptPubKey=CScript([OP_RETURN])),
            CElementsTxOut(
                nValue=CConfidentialValue(lbtc_amount-FIXED_FEE_SATOSHI),
                nAsset=CConfidentialAsset(lbtc_asset),
                scriptPubKey=change_address.to_scriptPubKey()),
            CElementsTxOut(nValue=CConfidentialValue(FIXED_FEE_SATOSHI),
                           nAsset=CConfidentialAsset(lbtc_asset))
        ]
    )

    unblind_result = mint_tx.vout[0].unblind_confidential_pair(
        rei_token_blinding_key,
        mint_tx.wit.vtxoutwit[0].rangeproof
    )
    assert isinstance(unblind_result, UnblindingSuccess)

    say(f"rei token unblinding result:\n"
        f"\tasset {unblind_result.asset}\n"
        f"\tamount {unblind_result.amount}\n"
        f"\tblinding_factor {unblind_result.blinding_factor}\n"
        f"\tasset blinding_factor {unblind_result.asset_blinding_factor}\n"
        )

    rei_token_blinding_factor = unblind_result.blinding_factor
    rei_token_asset_blinding_factor = unblind_result.asset_blinding_factor

    blind_result = tx.blind(
        input_descriptors=[
            BlindingInputDescriptor(
                amount=rei_token_amount,
                asset=rei_token,
                blinding_factor=rei_token_blinding_factor,
                asset_blinding_factor=rei_token_asset_blinding_factor),
            BlindingInputDescriptor(
                asset=CAsset.from_hex(lbtc_utxo['asset']),
                amount=coins_to_satoshi(lbtc_utxo['amount']),
                blinding_factor=Uint256.from_hex(lbtc_utxo['amountblinder']),
                asset_blinding_factor=Uint256.from_hex(lbtc_utxo['assetblinder']))
        ],
        output_pubkeys=[rei_token_blinding_key.pub])

    assert blind_result.ok, blind_result.error
    assert isinstance(blind_result, BlindingSuccess)

    # with unconfidential issuance, there's only one output to blind
    # NOTE: if we did confidential issuance, we would need to blind
    # CAssetIssuance, too (by suppliing blind_issuance_asset_keys to blind()),
    # and then num_successfully_blinded will be 2
    assert blind_result.num_successfully_blinded == 1

    swcb = rei_script_tree.get_script_with_control_block('rt_burn')
    assert swcb is not None
    scr, cb = swcb

    sig = treasury_key_for_rt_burn.sign_schnorr_no_tweak(
        scr.sighash_schnorr(tx, 0, [mint_tx.vout[0],
                                    lbtc_tx.vout[lbtc_utxo['vout']]],
                            genesis_block_hash=lx(rpc.getblockhash(0))))

    tx.wit.vtxinwit[0].scriptWitness = CScriptWitness([sig, scr, cb])

    semi_signed_tx_dict = rpc.signrawtransactionwithwallet(tx.serialize().hex())

    success_txid = rpc.sendrawtransaction(semi_signed_tx_dict['hex'])

    say(f"Successfully burned the reissuance token, txid {success_txid}")


# A function for a (non)-participant 'functionary' process
def functionary_process(elements_config_path):
    """A function that simulates a functionary for regtest chains"""

    def say(msg):
        participant_says('functionary', msg)

    rpc = RPCCaller(conf_file=elements_config_path)
    elt_mining_dst_addr = rpc.getnewaddress()
    while True:
        rpc.generatetoaddress(1, elt_mining_dst_addr)
        say("generated a block")
        rpc = wait_one_block(rpc, elements_config_path)


def synth_release_covenant_tail(
    *, synth_release_delay: int, spk_of_safe_covenant: CScript,
    lbtc_asset: CAsset, synth_asset: CAsset
):
    if synth_release_delay >= 512:
        synth_release_delay = (synth_release_delay // 512) | (1 << 22)

    # stack: collateral_amount_satoshi, minter_xpub
    return [
        synth_release_delay,
        OP_CHECKSEQUENCEVERIFY, OP_DROP,
    ] + inspect_output_code(
        asset=lbtc_asset,
        scriptPubKey=spk_of_safe_covenant, index=0
    ) + [
        0, OP_INSPECTOUTPUTVALUE,
        # Ensure that value is explicit
        1, OP_EQUALVERIFY,
        # Ensure that output 0 value equals collateral_amount_satoshi
        OP_EQUALVERIFY
    ] + inspect_output_code(
        asset=synth_asset, amount=minting_fee_satoshi,
        scriptPubKey=treasury_fee_address.to_scriptPubKey(), index=1
    ) + [
        # Ensure that the spend is authorized by original minter
        OP_CHECKSIG
    ]


def synth_burn_covenant_tail():
    # stack: timestamp_le64 synth_amount synth_asset
    return [
        OP_DUP,
        pack_le64(0x80000000),
        OP_GREATERTHANOREQUAL64,
        OP_IF,
        0, 5, OP_SUBSTR,
        OP_ELSE,
        OP_LE64TOSCRIPTNUM,
        OP_ENDIF,
        # stack: timestamp_scriptnum
        OP_CHECKLOCKTIMEVERIFY, OP_DROP,

        # Ensure that out 0 value is explicit
        0, OP_INSPECTOUTPUTVALUE, 1, OP_EQUALVERIFY,
        # Compare out 0 to synth_amount
        OP_EQUALVERIFY,

        # Ensure that out 0 asset is explicit
        0, OP_INSPECTOUTPUTASSET, 1, OP_EQUALVERIFY,
        # Compare out 0 to synth_asset
        OP_EQUALVERIFY,

        0, OP_INSPECTOUTPUTSCRIPTPUBKEY,
        # OP_RETURN is not a witness scriptPubKey, so its version will be -1
        -1, OP_EQUALVERIFY,
        # Check that output 0 is a burn output (0x6a is OP_RETURN)
        0x6a, OP_SHA256, OP_EQUAL
    ]


def inspect_output_code(
    *,
    asset: CAsset,
    index: int,
    amount: Optional[int] = None,
    scriptPubKey: Optional[CScript] = None
) -> List[ScriptElement_Type]:

    code: list[ScriptElement_Type] = [
        # stack:
        #    ...
        NUMBER(index),

        # stack:
        #    index
        #    ...
        OP_INSPECTOUTPUTASSET,

        # stack:
        #    output_asset_prefix
        #    output_asset_id
        #    ...
        1,  # check that the asset is explicit

        # stack:
        #    1
        #    output_asset_prefix
        #    output_asset_id
        #    ...
        OP_EQUALVERIFY,

        # stack:
        #    output_asset_id
        #    ...
        DATA(asset.data),

        # stack:
        #    synth_asset_id
        #    output_asset_id
        #    ...
        OP_EQUALVERIFY,

    ]

    if amount is not None:
        code += [
            # stack:
            #    ...
            index,

            # stack:
            #    index
            #    ...
            OP_INSPECTOUTPUTVALUE,

            # stack:
            #    output_value_prefix
            #    output_value
            #    ...
            1,  # check that the value is explicit

            # stack:
            #    1
            #    output_value_prefix
            #    output_value
            #    ...
            OP_EQUALVERIFY,

            # stack:
            #    output_value
            #    ...
            DATA(struct.pack(b"<q", amount)),   # amount as encoded in the output (8 bytes)

            # stack:
            #    amount_64bit
            #    output_value
            #    ...
            OP_EQUALVERIFY,

        ]

    if scriptPubKey is not None:

        witness_version = -1
        spk_cmp_data = hashlib.sha256(scriptPubKey).digest()
        if scriptPubKey.is_witness_scriptpubkey():
            witness_version = scriptPubKey.witness_version()
            spk_cmp_data = scriptPubKey.witness_program()

        code += [
            # stack:
            #    ...
            index,

            # stack:
            #    index
            #    ...
            OP_INSPECTOUTPUTSCRIPTPUBKEY,

            # stack:
            #    output_scriptPubKey_witVersion
            #    output_scriptPubKey_info
            #    ...
            witness_version,

            # stack:
            #    witness_version
            #    output_scriptPubKey_witVersion
            #    output_scriptPubKey_info
            #    ...
            OP_EQUALVERIFY,

            # stack:
            #    output_scriptPubKey_info
            #    ...
            DATA(spk_cmp_data),

            # stack:
            #    spk_cmp_data
            #    output_scriptPubKey_info
            #    ...
            OP_EQUALVERIFY,
        ]

    return code


def construct_covenant_for_rt_burn(
    *,
    rt_asset: CAsset,
    treasury_xpub: XOnlyPubKey,
    lbtc_asset: CAsset
):

    covenant_code: list[ScriptElement_Type] = []

    # Output 0 is burned
    covenant_code += [
        # Check that output 0 is a burn output
        0, OP_INSPECTOUTPUTSCRIPTPUBKEY,
        # OP_RETURN is not a witness scriptPubKey, so its version will be -1
        -1, OP_EQUALVERIFY,
        # 0x6a is OP_RETURN
        0x6a, OP_SHA256,

        OP_EQUALVERIFY,

        # Output 1 is unblinded L-BTC (eigher network fee, or change)

        # get output 1 asset
        1, OP_INSPECTOUTPUTASSET,
        # check that the asset is explicit
        1, OP_EQUALVERIFY,
        # check that the asset is equal to lbtc_asset
        DATA(lbtc_asset.data),
        OP_DUP,  # save lbtc_asset for later use
        OP_EQUALVERIFY,

        # Check that "Transaction contains two or three outputs"
        #
        # If there's 3 outputs, check that last output is L-BTC
        # Note that we don't check for `>= 2 outputs`, because previous
        # `inspect_output_code` chunk will fail if there's no output at idx 1
        OP_INSPECTNUMOUTPUTS,
        OP_DUP,
        3,
        OP_LESSTHANOREQUAL,
        OP_VERIFY,
        3,
        OP_NUMEQUAL,
        OP_IF,
        # get output 2 asset
        2, OP_INSPECTOUTPUTASSET,
        # check that the asset is explicit
        1, OP_EQUALVERIFY,
        # check that the asset is equal to lbtc_asset (saved earlier)
        OP_EQUALVERIFY,
        OP_ELSE,
        # drop the saved lbtc_asset
        OP_DROP,
        OP_ENDIF,

        treasury_xpub,
        OP_CHECKSIG
    ]

    return covenant_code


def construct_covenant_for_reissuance(
    *,
    lbtc_asset: CAsset,
    synth_asset: CAsset,
    bond_amount: int,
    oracle_xpubkeys: List[XOnlyPubKey],
    claim_covenant_internal_xpub: XOnlyPubKey,
    synth_burn_delay: int,
    synth_release_delay: int,
    spk_of_safe_covenant: CScript
) -> List[ScriptElement_Type]:

    shifted_precision = 10**(lbtc_precision+precision_shift)

    # Check static conditions of inputs

    # Note that we don't check input 0 at all, because if input 1 is
    # L-BTC, then input 0 can only be the token locked in the covenant

    covenant_code: list[ScriptElement_Type] = [
        # Transaction contains exactly two inputs
        OP_INSPECTNUMINPUTS,
        2, OP_NUMEQUALVERIFY,
        # Input 1 is unblined, and contains L-BTC
        1, OP_INSPECTINPUTASSET,
        1, OP_EQUALVERIFY,   # check that asset is explicit
        OP_DUP, OP_DUP, OP_DUP,  # save asset for next checks
        DATA(lbtc_asset.data),  # check that asset is equal to lbtc_asset
        OP_EQUALVERIFY,
    ]

    # Check static conditions of outputs

    #  Output 0 script the same as the output script of the input 0

    covenant_code += [
        0, OP_INSPECTINPUTSCRIPTPUBKEY,
        0, OP_INSPECTOUTPUTSCRIPTPUBKEY,
        OP_ROT,  # ver spk ver spk -> ver ver spk spk
        OP_EQUALVERIFY,  # compare witness versions
        OP_EQUALVERIFY   # compare scriptpubkeys
    ]

    # Output 1 is unblinded Synth

    # Script will be checked later, when we have constructed the Claim covenant

    # The amount is not checked, it will be used to calculate the collateral
    # amount for Claim/Release, and also will be passed as-is to Claim/Burn

    covenant_code += inspect_output_code(
        asset=synth_asset,
        index=1)

    # Output 2 is unblinded L-BTC with the amount required for the bond
    # script will be checked later, when we have constructed the claim covenant

    covenant_code += [
        2, OP_INSPECTOUTPUTASSET,
        1, OP_EQUALVERIFY,  # ensure that asset is explicit
        # lbtc_asset is on the stack (saved earlier)
        OP_EQUALVERIFY,

        2, OP_INSPECTOUTPUTVALUE,
        1, OP_EQUALVERIFY,  # ensure that value is explicit
        pack_le64(bond_amount),
        OP_EQUALVERIFY
    ]

    # Output 3 is unblinded L-BTC (eigher network fee, or change)
    covenant_code += [
        3, OP_INSPECTOUTPUTASSET,
        1, OP_EQUALVERIFY,  # ensure that asset is explicit
        # lbtc_asset is on the stack (saved earlier)
        OP_EQUALVERIFY
    ]

    # Check that "Transaction contains four or five outputs"
    #
    # If there's 5 outputs, check that last output is L-BTC
    # Note that we don't check for `>= 4 outputs`, because previous
    # `inspect_output_code` chunk will fail if there's no output at idx 3
    covenant_code += [
        OP_INSPECTNUMOUTPUTS,
        OP_DUP,
        5,
        OP_LESSTHANOREQUAL,
        OP_VERIFY,
        5,
        OP_NUMEQUAL,
        OP_IF,

        4, OP_INSPECTOUTPUTASSET,
        1, OP_EQUALVERIFY,  # ensure that asset is explicit
        # lbtc_asset is on the stack (saved earlier)
        OP_EQUALVERIFY,

        OP_ELSE,

        OP_DROP,  # drop unused lbtc_asset

        OP_ENDIF
    ]

    # stack: o_xpub_idx ts price osig minter_xpub swap? parity
    #  NOTE: parity is 0x02 or 0x03
    covenant_code += [  # noqa
        0, OP_ADD,  # make sure o_xpub_idx is minimally-encoded
        5, OP_LSHIFT,   # o_xpub_idx*32 ts price osig ...
        DATA(b''.join(oracle_xpubkeys)),
        OP_SWAP,        # o_xpub_idx*32 opubs_array ts price osig ...
        32, OP_SUBSTR,  # o_xpub ts price osig ...
        OP_ROT, OP_ROT,
                        # ts price o_xpub osig ...
        OP_2DUP,        # ts price ts price o_xpub osig ...
        OP_TOALTSTACK, OP_TOALTSTACK,
        OP_SWAP,
                        # price ts o_xpub osig ... | price ts
        OP_CAT,         # ts+price o_xpub osig ... | price ts
        DATA(CURRENCY_CODE), OP_CAT,
                        # oracle_data o_xpub osig ... | price ts
        DATA(ORACLE_MESSAGE_TAG), OP_SHA256, OP_DUP, OP_CAT,
                        # tag oracle_data o_xpub osig ... | price ts
        OP_SWAP, OP_CAT,
                        # tag+oracle_data o_xpub osig ... | price ts
        OP_SHA256,      # SHA2(tag+oracle_data) o_xpub osig ... | price ts
        OP_SWAP,        # o_xpub SHA2(tag+oracle_data) osig ... | price ts
        OP_CHECKSIGFROMSTACKVERIFY,
                        # minter_xpub ... | price ts

        1, OP_INSPECTOUTPUTVALUE,
        1, OP_EQUALVERIFY,  # -- Ensure that out 1 value is explicit
                        # o1_amount minter_xpub ... | price ts
        OP_DUP,         # o1_amount o1_amount minter_xpub ... | price ts
        # hard-coded 150% collateralization ratio:
        #   synth_amount_satoshi + synth_amount_satoshi//2
        OP_DUP, 2, OP_SCRIPTNUMTOLE64, OP_DIV64, OP_VERIFY, OP_SWAP, OP_DROP,
                        # o1_amount o1_amount/2 o1_amount minter_xpub ... | price ts
        OP_ADD64, OP_VERIFY,
                        # synth_coll_amount o1_amount minter_xpub ... | price ts
    ]

    if shifted_precision > 2**32-1:
        covenant_code += [pack_le64(shifted_precision)]
    else:
        covenant_code += [shifted_precision, OP_SCRIPTNUMTOLE64]

    covenant_code += [
        OP_MUL64, OP_VERIFY,
                        # synth_coll_amount_scaled o1_amount minter_xpub ... | price ts
        OP_FROMALTSTACK,
                        # price synth_coll_amount_scaled o1_amount minter_xpub ... | ts
        OP_ROT,         # o1_amount price synth_coll_amount_scaled minter_xpub ... | ts
        OP_TOALTSTACK,  # price synth_coll_amount_scaled minter_xpub ... | o1_amount ts
        OP_DIV64,       # ok quot64 rem64 minter_xpub ... | o1_amount ts
        OP_VERIFY,      # quot64 rem64 minter_xpub ... | o1_amount ts
        OP_SWAP,        # rem64 quot64 minter_xpub ... | o1_amount ts
        OP_DROP,        # Drop the remainder
                        # -- Quotient (quot64) is the collateral amount
                        # lbtc_coll_amount minter_xpub ... | o1_amount ts
        OP_SIZE, OP_SWAP, OP_CAT,
                        # DATA(lbtc_coll_amount) minter_xpub ... | o1_amount ts
        OP_SWAP,        # minter_xpub DATA(lbtc_coll_amount) ... | o1_amount ts
        OP_SIZE,        # size minter_xpub DATA(lbtc_coll_amount) ... | o1_amount ts
        OP_DUP, 32, OP_NUMEQUALVERIFY,  # check correct xpubkey size
                        # size minter_xpub DATA(lbtc_coll_amount) ... | o1_amount ts
        OP_SWAP, OP_CAT,
                        # DATA(minter_xpub) DATA(lbtc_coll_amount) ... | o1_amount ts
        OP_SWAP, OP_CAT,
                        # DATA(minter_xpub)+DATA(lbtc_coll_amount) ... | o1_amount ts

        # NOTE: there's a possibility for optimisation - we could have the release
        # covenant tail as two chunks, and insert synth_asset in between. We
        # can get synth_asset from output 1 easily. But this will obviously
        # increase the complexity of the script, so for now the release # covenant tail
        # comes as a single data chunk
        DATA(CScript(synth_release_covenant_tail(
            synth_release_delay=synth_release_delay,
            spk_of_safe_covenant=spk_of_safe_covenant,
            lbtc_asset=lbtc_asset, synth_asset=synth_asset))),
                        # sr_tail DATA(minter_xpub)+DATA(lbtc_coll_amount) ... | o1_amount ts
        OP_CAT,         # sr_covenant ... | o1_amount ts
        OP_SIZE,        # size sr_covenant ... | o1_amount ts

        # NOTE: in another place, we check that synth_release_script length is less than
        # 0xFD but greater or equal to 0x80, and will fit into 1-byte varint,
        # but will not fit into 1-byte scriptnum. Zero byte will be added
        # to the value so it will remain a positive scriptnum.
        # We need 1-byte value, so we should drop that zero byte
        0, 1, OP_SUBSTR,
        OP_SWAP, OP_CAT,
                        # DATA(sr_covenant) ... | o1_amount ts
        DATA(LEAF_VERSION),
                        # leaf_version DATA(sr_covenant) ... | o1_amount ts
        OP_SWAP, OP_CAT,
                        # lfver+DATA(sr_covenant) ... | o1_amount ts
        # We checked earlier that asset of output 1 is Synth, so we can get it with
        # INSPECTOUTPUTASSET, drop the prefix, and then prepend the size
        # to turn it into data chunk
        1, OP_INSPECTOUTPUTASSET, OP_DROP,
        OP_SIZE, OP_SWAP, OP_CAT,
                        # DATA(synth_asset) lfver+DATA(sr_covenant) ... | o1_amount ts
        OP_FROMALTSTACK,
                        # o1_amount DATA(synth_asset) lfver+DATA(sr_covenant) ... | ts
        OP_SIZE, OP_SWAP, OP_CAT,
                        # DATA(o1_amount) DATA(synth_asset) lfver+DATA(sr_covenant) ... | ts
        OP_FROMALTSTACK,
                        # ts DATA(o1_amount) DATA(synth_asset) lfver+DATA(sr_covenant) ...
        pack_le64(synth_burn_delay), OP_ADD64, OP_VERIFY,
        OP_SIZE, OP_SWAP, OP_CAT,
                        # DATA(burn_ts) DATA(o1_amount) DATA(synth_asset) lfver+DATA(sr_covenant) ...
        OP_CAT, OP_CAT,
                        # DATA(burn_cov_args) lfver+DATA(sr_covenant) ...
        DATA(CScript(synth_burn_covenant_tail())),
                        # sb_tail DATA(burn_cov_args) lfver+DATA(sr_covenant) ...
        OP_CAT,         # sb_covenant lfver+DATA(sr_covenant) ...
        # NOTE: in another place, we check that synth_burn script length
        # is less than 0x80, that will fit into 1-byte scriptnum, so
        # using OP_SIZE is OK here
        OP_SIZE, OP_SWAP, OP_CAT,
                        # DATA(sb_covenant) lfver+DATA(sr_covenant) ...
        DATA(LEAF_VERSION),
                        # leaf_version DATA(sb_covenant) lfver+DATA(sr_covenant) ...
        OP_SWAP, OP_CAT,
                        # lfver+DATA(sb_covenant) lfver+DATA(sr_covenant) ...
        DATA(b'TapLeaf/elements'), OP_SHA256,
        OP_DUP, OP_CAT, OP_DUP, OP_TOALTSTACK,
                        # tlh_x2 lver+DATA(sb_covenant) lfver+DATA(sr_covenant) ... | tlh_x2
        OP_SWAP, OP_CAT, OP_SHA256,
                        # leafhash(sb_covenant) lfver+DATA(sr_covenant) ... | tlh_x2
        OP_SWAP,        # lfver+DATA(sr_covenant) leafhash(sb_covenant) ... | tlh_x2
        OP_FROMALTSTACK,
                        # tlh_x2 lfver+DATA(sr_covenant) leafhash(sb_covenant) ...
        OP_SWAP, OP_CAT, OP_SHA256,
                        # leafhash(sr_covenant) leafhash(sb_covenant) swap? parity
        OP_ROT,         # swap? leafhash(sr_covenant) leafhash(sb_covenant) parity
        OP_IF, OP_SWAP, OP_ENDIF,
        OP_CAT,         # leafhash+leafhash parity
        DATA(b'TapBranch/elements'), OP_SHA256,
        OP_DUP, OP_CAT, OP_SWAP, OP_CAT, OP_SHA256,
                        # claim_merkle_root parity
        1, OP_INSPECTOUTPUTSCRIPTPUBKEY,
        1, OP_NUMEQUALVERIFY,  # check witver == 1
        OP_DUP,         # xpub1 xpub1 claim_merkle_root parity
        2, OP_INSPECTOUTPUTSCRIPTPUBKEY,
        1, OP_NUMEQUALVERIFY,  # check witver == 1
                        # xpub2 xpub1 xpub1 claim_merkle_root parity

        # Make sure that output 1 and 2 are sent to the same script
        OP_EQUALVERIFY,

                        # xpub1 claim_merkle_root parity
        OP_ROT,         # parity xpub1 claim_merkle_root
        OP_DUP, 2, 4, OP_WITHIN, OP_VERIFY,  # make sure partity byte is 2 or 3
        OP_SWAP,        # xpub1 parity claim_merkle_root
        OP_CAT,         # pub1 claim_merkle_root
        OP_SWAP,        # claim_merkle_root pub1
        DATA(claim_covenant_internal_xpub),
                        # int_xpub claim_mr pub1  # noqa
        OP_TUCK,        # int_xpub claim_mr int_xpub pub1
        OP_SWAP, OP_CAT,
                        # int_xpub+claim_mr int_xpub pub1  # noqa
        DATA(b'TapTweak/elements'), OP_SHA256,
        OP_DUP, OP_CAT, OP_SWAP, OP_CAT, OP_SHA256,
                        # tweak int_xpub pub1  # noqa
        OP_SWAP,        # int_xpub tweak pub1
        OP_TWEAKVERIFY,
        OP_TRUE
    ]

    return covenant_code


def main():  # noqa
    global console_lock

    if len(sys.argv) < 2:
        sys.stderr.write(f'usage: {sys.argv[0]} <path_to_elements_dir> [timestamp_offset]\n')

        sys.exit(-1)

    timestamp_offset = 0
    if len(sys.argv) > 2:
        timestamp_offset = int(sys.argv[2])

    elements_config_path = os.path.join(sys.argv[1], 'elements.conf')
    if not os.path.isfile(elements_config_path):
        sys.stderr.write(
            'config file {} not found or is not a regular file\n'
            .format(elements_config_path))
        sys.exit(-1)

    rpc = RPCCaller(conf_file=elements_config_path)

    mediantime = rpc.getblockchaininfo()['mediantime']
    timestamp = mediantime + timestamp_offset
    print("mediantime is", mediantime)
    print("timestamp for price is", timestamp)
    timestamp_le64 = struct.pack(b"<q", timestamp)

    # Do unconfidential issuance
    # NOTE: if we do confidential issuance, then on reissuance,
    # we will need to blind CAssetIssuance, too
    issue = rpc.issueasset(10000000, 1, False)

    synth_asset = CAsset.from_hex(issue['asset'])
    print(f'The asset is {synth_asset.to_hex()}')

    rei_token = CAsset.from_hex(issue['token'])
    print(f'The token is {rei_token.to_hex()}')

    asset_entropy = Uint256.from_hex(issue['entropy'])
    print(f'Asset entropy is {asset_entropy}')

    (rei_token_utxo, ) = rpc.listunspent(0, 0, [], False,
                                         {'asset': rei_token.to_hex()})

    rei_token_amount = coins_to_satoshi(rei_token_utxo['amount'])

    print(f'Unspent utxo for reissuance token {rei_token.to_hex()} is '
          f'{rei_token_utxo["txid"]}:{rei_token_utxo["vout"]}, '
          f'amount {coins_to_satoshi(rei_token_utxo["amount"])}')

    lbtc_asset = CAsset.from_hex(rpc.dumpassetlabels()['bitcoin'])

    print(f"L-BTC asset is {lbtc_asset.to_hex()}")

    # Use some random key for the internal pubkey, so that
    # the keypath is knowingly unspendable. BIP341 lists a way to construct
    # such a pubkey that is provably has no known associated privkey.
    #
    # If it is desireable for the covenants to be spendable via keypath,
    # the privkey for internal pubkey can saved and used later
    #
    # NOTE: this example uses the same internal key for both
    # Mint and Claim covenants - but this is not necessary a correct choice
    # for real-world scenario when real keys are used for internal keys
    int_key = CKey(os.urandom(32))
    int_xpub = XOnlyPubKey(int_key.pub)

    oracle_keys = [CKey(os.urandom(32)) for _ in range(3)]
    minter_key = CKey(os.urandom(32))
    treasury_key_for_rt_burn = CKey(os.urandom(32))

    reissuance_covenant_code = construct_covenant_for_reissuance(
        synth_asset=synth_asset, lbtc_asset=lbtc_asset,
        bond_amount=bond_amount, claim_covenant_internal_xpub=int_xpub,
        oracle_xpubkeys=[XOnlyPubKey(k.pub) for k in oracle_keys],
        synth_burn_delay=synth_burn_delay,
        synth_release_delay=synth_release_delay,
        spk_of_safe_covenant=spk_of_safe_covenant)

    rt_burn_covenant_code = construct_covenant_for_rt_burn(
        rt_asset=rei_token,
        treasury_xpub=XOnlyPubKey(treasury_key_for_rt_burn.pub),
        lbtc_asset=lbtc_asset)

    rt_burn_script = CElementsScript(rt_burn_covenant_code, name='rt_burn')

    rei_script = CElementsScript(reissuance_covenant_code, name='covenant')

    rei_script_tree = TaprootScriptTree([rei_script, rt_burn_script],
                                        internal_pubkey=int_xpub)

    rei_token_blinding_key = CKey(os.urandom(32))
    rei_cov_addr = P2TRElementsConfidentialAddress.from_unconfidential(
        P2TRElementsAddress.from_script_tree(rei_script_tree),
        rei_token_blinding_key.pub)

    print(f'Covenant address for reissuance: {rei_cov_addr}')

    # rpc.importaddress(rei_cov_addr.to_scriptPubKey().hex())
    # print(f"importing descriptor tr({int_xpub.hex()}, {rei_script.hex()})")
    # rpc.importdescriptors(
    #    [{"desc": f"tr({int_xpub.hex()}, {rei_script.hex()})",
    #     "timestamp": "now"}])

    rei_token_txid = rpc.sendtoaddress(
        str(rei_cov_addr), rei_token_utxo['amount'], "", "",
        False, False, 1, "conservative", False,
        rei_token.to_hex())

    print(f'sent {rei_token_utxo["amount"]} of reissuance token '
          f'{rei_token.to_hex()} in tx {rei_token_txid}')

    sent_tx_dict = rpc.getrawtransaction(rei_token_txid, 1)

    sent_tx = CElementsTransaction.deserialize(x(sent_tx_dict['hex']))

    for rei_token_vout_idx, rei_token_vout in enumerate(sent_tx.vout):
        if rei_token_vout.scriptPubKey == rei_cov_addr.to_scriptPubKey():
            break

    assert rei_token_vout is not None

    print(f'Locked utxo: {rei_token_txid}:{rei_token_vout_idx}')

    unblind_result = rei_token_vout.unblind_confidential_pair(
        rei_token_blinding_key,
        sent_tx.wit.vtxoutwit[rei_token_vout_idx].rangeproof
    )
    assert isinstance(unblind_result, UnblindingSuccess)

    print(f"rei token unblinding result:\n"
          f"\tasset {unblind_result.asset}\n"
          f"\tamount {unblind_result.amount}\n"
          f"\tblinding_factor {unblind_result.blinding_factor}\n"
          f"\tasset blinding_factor {unblind_result.asset_blinding_factor}\n"
          )

    rei_token_blinding_factor = unblind_result.blinding_factor
    rei_token_asset_blinding_factor = unblind_result.asset_blinding_factor

    lbtc_change_addr = CCoinConfidentialAddress(rpc.getnewaddress())

    synth_release_script = CScript(
        [
            DATA(XOnlyPubKey(minter_key.pub)),
            DATA(pack_le64(collateral_amount_satoshi)),
        ] + synth_release_covenant_tail(
            synth_release_delay=synth_release_delay,
            spk_of_safe_covenant=spk_of_safe_covenant,
            lbtc_asset=lbtc_asset, synth_asset=synth_asset),
        name='release')

    synth_burn_script = CScript(
        [
            DATA(synth_asset.data),
            DATA(pack_le64(synth_amount_satoshi)),
            DATA(pack_le64(synth_burn_delay+timestamp)),
        ] + synth_burn_covenant_tail(),
        name='burn')

    # the covenant code is based on these assumptions
    assert len(synth_release_script) >= 0x80, \
        "synth_release_script is expected to not fit into 1-byte scriptnum"
    assert len(synth_release_script) < 0xFD, \
        "synth_release_script must fit into 1-byte varint"
    assert len(synth_burn_script) < 0x80, \
        "synth_burn_script must fit into 1-byte scriptnum"

    left_h = CoreElementsParams.tapleaf_hasher(
        LEAF_VERSION + BytesSerializer.serialize(synth_release_script))
    right_h = CoreElementsParams.tapleaf_hasher(
        LEAF_VERSION + BytesSerializer.serialize(synth_burn_script))

    if right_h < left_h:
        merkle_root = CoreElementsParams.tapbranch_hasher(right_h + left_h)
        swap_flag = 0
    else:
        merkle_root = CoreElementsParams.tapbranch_hasher(left_h + right_h)
        swap_flag = 1

    tt_res = tap_tweak_pubkey(int_xpub, merkle_root=merkle_root)
    assert tt_res is not None

    claim_output_xpub, parity = tt_res

    claim_cov_addr = P2TRElementsAddress.from_xonly_output_pubkey(
        claim_output_xpub)

    lbtc_utxo = find_utxo(rpc, lbtc_asset, bond_amount + FIXED_FEE_SATOSHI)

    print(f'Unspent utxo for L-BTC {lbtc_asset.to_hex()} is '
          f'{lbtc_utxo["txid"]}:{lbtc_utxo["vout"]}, '
          f'amount {coins_to_satoshi(lbtc_utxo["amount"])}')

    lbtc_amount = coins_to_satoshi(lbtc_utxo["amount"])

    assert lbtc_amount > FIXED_FEE_SATOSHI + bond_amount

    tx = CElementsMutableTransaction(
        vin=[
            CElementsTxIn(prevout=CElementsOutPoint(
                hash=lx(rei_token_txid), n=rei_token_vout_idx),
                assetIssuance=CAssetIssuance(
                    assetBlindingNonce=rei_token_asset_blinding_factor,
                    assetEntropy=asset_entropy,
                    nAmount=CConfidentialValue(synth_amount_satoshi))),
            CElementsTxIn(prevout=CElementsOutPoint(
                hash=lx(lbtc_utxo['txid']), n=lbtc_utxo['vout']))
        ],
        vout=[
            CElementsTxOut(nValue=CConfidentialValue(rei_token_amount),
                           nAsset=CConfidentialAsset(rei_token),
                           scriptPubKey=rei_cov_addr.to_scriptPubKey()),
            CElementsTxOut(nValue=CConfidentialValue(synth_amount_satoshi),
                           nAsset=CConfidentialAsset(synth_asset),
                           scriptPubKey=claim_cov_addr.to_scriptPubKey()),
            CElementsTxOut(
                nValue=CConfidentialValue(bond_amount),
                nAsset=CConfidentialAsset(lbtc_asset),
                scriptPubKey=claim_cov_addr.to_scriptPubKey()),
            CElementsTxOut(
                nValue=CConfidentialValue(lbtc_amount - bond_amount - FIXED_FEE_SATOSHI),
                nAsset=CConfidentialAsset(lbtc_asset),
                scriptPubKey=lbtc_change_addr.to_scriptPubKey(),
            ),
            CElementsTxOut(nValue=CConfidentialValue(FIXED_FEE_SATOSHI),
                           nAsset=CConfidentialAsset(lbtc_asset))
        ]
    )

    blind_result = tx.blind(
        input_descriptors=[
            BlindingInputDescriptor(
                amount=rei_token_amount,
                asset=rei_token,
                blinding_factor=rei_token_blinding_factor,
                asset_blinding_factor=rei_token_asset_blinding_factor),
            BlindingInputDescriptor(
                asset=CAsset.from_hex(lbtc_utxo['asset']),
                amount=coins_to_satoshi(lbtc_utxo['amount']),
                blinding_factor=Uint256.from_hex(lbtc_utxo['amountblinder']),
                asset_blinding_factor=Uint256.from_hex(lbtc_utxo['assetblinder']))
        ],
        output_pubkeys=[rei_token_blinding_key.pub])

    assert blind_result.ok, blind_result.error
    assert isinstance(blind_result, BlindingSuccess)

    # with unconfidential issuance, there's only one output to blind
    # NOTE: if we did confidential issuance, we would need to blind
    # CAssetIssuance, too (by suppliing blind_issuance_asset_keys to blind()),
    # and then num_successfully_blinded will be 2
    assert blind_result.num_successfully_blinded == 1

    oracle_idx = random.randrange(len(oracle_keys))

    # witness: opub_idx ts price osig minter_xpub swap? parity

    oracle_sig = oracle_keys[oracle_idx].sign_schnorr_no_tweak(
        price_message_hasher(timestamp_le64 + lbtc_price_le64 + CURRENCY_CODE)
    )

    swcb = rei_script_tree.get_script_with_control_block('covenant')
    assert swcb is not None
    scr, cb = swcb

    tx.wit.vtxinwit[0].scriptWitness = CScriptWitness(
            [0x3 if parity else 0x2, swap_flag, XOnlyPubKey(minter_key.pub), oracle_sig,
             lbtc_price_le64, timestamp_le64, oracle_idx, scr, cb])

    semi_signed_tx_dict = rpc.signrawtransactionwithwallet(tx.serialize().hex())

    success_txid = rpc.sendrawtransaction(semi_signed_tx_dict['hex'])

    print(f"Successfully spent mint covenant, txid {success_txid}")

    # Initialize console lock
    console_lock = Lock()

    p_fnc = Process(target=functionary_process, name='functionary',
                    args=(elements_config_path,))

    p_fnc.start()

    if synth_release_delay >= 512:
        time.sleep(3)

    while True:
        send_tx_dict = rpc.getrawtransaction(success_txid, 1)
        if int(send_tx_dict.get('confirmations', 0)) > 0:
            break
        print(f'waiting for {success_txid} confirmation')
        rpc = wait_one_block(rpc, elements_config_path)

    mint_mediantime = rpc.getblockchaininfo()['mediantime']

    claim_cov_tree = TaprootScriptTree(
        [synth_release_script, synth_burn_script], internal_pubkey=int_xpub)

    # Create process to run 'alice' participant function
    # and pass it one end of a pipe, and path to config file
    # for Elements daemon
    p1 = Process(target=minter_process, name='minter',
                 args=(elements_config_path, tx, minter_key,
                       claim_cov_tree, mint_mediantime,
                       lbtc_asset, synth_asset))

    p2 = Process(target=burner_process, name='burner',
                 args=(elements_config_path, tx, claim_cov_tree, timestamp,
                       lbtc_asset, synth_asset))

    p3 = Process(target=rt_burn_process, name='rt_burn',
                 args=(elements_config_path, tx, rei_script_tree,
                       rei_token, rei_token_amount,
                       rei_token_blinding_key,
                       lbtc_asset, synth_asset,
                       treasury_key_for_rt_burn))

    # Start both processes
    p1.start()
    p2.start()
    p3.start()

    # The childs are on their own now. We just wait for them to finish.
    try:
        p1.join()
        p2.join()
        p3.join()
    except KeyboardInterrupt:
        print()
        print("=============================================================")
        print("Interrupted from keyboard, terminating participant processes.")
        print("-------------------------------------------------------------")
        for p in (p1, p2, p3):
            if p.is_alive():
                print('terminating', p.name)
                p.terminate()
            else:
                print(p.name, 'is not alive')
            p.join()
        print('Exiting.')
        print("=============================================================")

    print('Terminating the "functionary" process')
    p_fnc.terminate()
    p_fnc.join()


if __name__ == '__main__':  # noqa
    main()
