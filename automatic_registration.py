#!/usr/bin/env python3

from decimal import Decimal
import json
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# Based on Namecoin Core's Python tests
def rawtx_output_index(txhex, addr):
    """
    Returns the index of the tx output in the given raw transaction that
    is sent to the given address.
    This is useful for building raw transactions with namerawtransaction.
    """

    tx = rpc_connection.decoderawtransaction(txhex)
    for i, vout in enumerate(tx['vout']):
        if addr in vout['scriptPubKey']['addresses']:
            return i

    return None

# This would be replaced by the Qt GUI widget for choosing the name to register.
def get_name_to_register():
    return input("Enter name to register: ")

# This would be replaced by the Qt GUI widget for choosing the value to assign to the newly registered name.
def get_value_to_register():
    return input("Enter value to assign to name: ")

# This would be replaced by the Qt GUI widget for Coin Control inputs.
# Returns (coin_control_enabled, coin_control_inputs)
def get_coin_control_inputs():
    vin = input("Enter Coin Control inputs (JSON array, or blank to disable Coin Control): ")
    if vin == "":
        return False, []
    return True, json.loads(vin)

# This would be replaced by the Qt GUI widget for Coin Control change address.
def get_change_address():
    address = input("Enter change address (or blank to automatically choose one): ")
    if address == "":
        return False, None
    return True, address

# This would be replaced by the Qt GUI widget for Fee Control fee type.
def get_fee_type():
    result = input("Enter fee type (feeRate or conf_target): ")
    if result not in ["feeRate", "conf_target"]:
        print("Invalid fee type!")
        quit()
    return result

# This would be replaced by the Qt GUI widget for Fee Control fee rate.
def get_fee_rate():
    return Decimal(input("Enter fee rate (in NMC / kB): "))

# This would be replaced by the Qt GUI widget for Fee Control conf target.
def get_conf_target():
    return int(input("Enter confirmation target (in blocks): "))

# This would be replaced by the Qt GUI widget for unlocking the wallet.
def wallet_unlock():
    wallet_passphrase = input("Enter wallet passphrase: ")
    rpc_connection.walletpassphrase(wallet_passphrase, 60)

# This would be replaced by the Qt GUI widget for locking the wallet.
def wallet_lock():
    rpc_connection.walletlock()

# This would be replaced by whatever mechanism Namecoin-Qt uses to check if a name is available.
# TODO: maybe make this a dedicated RPC call in the API?
def verify_name_available(name):
    try:
        current_name_data = rpc_connection.name_show(name)
        if not current_name_data["expired"]:
            print("Someone already owns that name!")
            quit()
        print("The name is expired and currently available.")
    except JSONRPCException as e:
        if e.code == -4:
            print("The name has never been registered and is currently available.")
        else:
            raise e

# This would be replaced by whatever mechanism Namecoin-Qt uses to queue transactions in the wallet.
# TODO: can we use nLockTime instead of "minBlockHeight"?
def queue_transaction(min_input_confirmations, min_block_height, tx):
    print("Send the following transaction when all inputs have at least", min_input_confirmations, "confirmations, and the block height is at least", min_block_height, ":", tx)

# rpc_user and rpc_password are set in the namecoin.conf file
rpc_user = input("Enter RPC username: ")
rpc_password = input("Enter RPC password: ")

# Connect to Namecoin Core
# 8336 = mainnet
# 18443 = regtest
rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:18443"%(rpc_user, rpc_password))

name_to_register = get_name_to_register()

verify_name_available(name_to_register)

fee_type = get_fee_type()

if fee_type == "feeRate":
    fee_rate = get_fee_rate()
elif fee_type == "conf_target":
    conf_target = get_conf_target()

# TODO: use a higher amount for pure name transactions?
name_amount = Decimal("0.01")
print("Name amount is ", name_amount, "NMC")

coin_control_enabled, name_new_vin = get_coin_control_inputs()

# TODO: find another way to set the label that doesn't use deprecated "account" field?
name_new_address = rpc_connection.getnewaddress("Name: " + name_to_register)
name_new_vout = {name_new_address: name_amount}

# TODO: set locktime and/or replaceable?
name_new_create = rpc_connection.createrawtransaction(name_new_vin, name_new_vout)

print("name_new create:", rpc_connection.decoderawtransaction(name_new_create))

name_new_name_index = rawtx_output_index(name_new_create, name_new_address)

print("name_new_name_index:", name_new_name_index)

name_new_op = {
    "op": "name_new",
    "name": name_to_register,
}

name_new_with_name = rpc_connection.namerawtransaction(name_new_create, name_new_name_index, name_new_op)
name_firstupdate_salt = name_new_with_name["rand"]
print("Salt is", name_firstupdate_salt)

print("name_new_with_name:", rpc_connection.decoderawtransaction(name_new_with_name["hex"]))

# TODO: set subtractFeeFromOutputs for fee control?
# TODO: set replaceable?
# TODO: look into lockUnspents?  Only stored in memory, so probably not useful for persistent locking.
name_new_fund_options = {
}

# Get the fee for name_new
if fee_type == "feeRate":
    name_new_fund_options["feeRate"] = fee_rate
    print("name_new will cost", name_new_fund_options["feeRate"], "NMC / kB")
elif fee_type == "conf_target":
    name_new_fund_options["conf_target"] = conf_target
    print("name_new will confirm approximately", name_new_fund_options["conf_target"], "after broadcast")

# Get the change address for name_new
name_new_custom_change_enabled, name_new_change_address = get_change_address()
if name_new_custom_change_enabled:
    name_new_fund_options["changeAddress"] = name_new_change_address

# Fund the transaction and add change output.
name_new_funded = rpc_connection.fundrawtransaction(name_new_with_name["hex"], name_new_fund_options)

# If Coin Control is enabled, make sure that fundrawtransaction didn't add extra inputs.
if coin_control_enabled and len(rpc_connection.decoderawtransaction(name_new_funded["hex"])["vin"]) != len(rpc_connection.decoderawtransaction(name_new_with_name["hex"])["vin"]):
    print("Insufficient funds in Coin Control selection for name_new")
    quit()

wallet_unlock()

name_new_signed = rpc_connection.signrawtransaction(name_new_funded["hex"])
print("name_new has been signed")

name_new_sent = rpc_connection.sendrawtransaction(name_new_signed["hex"])
print("name_new has been broadcasted")

if coin_control_enabled:
    # If coin control is enabled, then we make the name_firstupdate transaction inputs equal to the name_new transaction outputs.
    name_firstupdate_vin = []
    name_new_signed_vout_size = len(rpc_connection.decoderawtransaction(name_new_signed["hex"])["vout"])
    for name_new_signed_vout_i in range(name_new_signed_vout_size):
        name_firstupdate_vin.append({
            "txid": name_new_sent,
            "vout": name_new_signed_vout_i,
        })
else:
    # If coin control is disabled, then the only input is the name_new output.
    name_firstupdate_vin = [
        {
            "txid": name_new_sent,
            "vout": rawtx_output_index(name_new_signed["hex"], name_new_address),
        }
    ]

# TODO: find another way to set the label that doesn't use deprecated "account" field?
name_firstupdate_address = rpc_connection.getnewaddress("Name: " + name_to_register)
name_firstupdate_vout = {name_firstupdate_address: name_amount}

# TODO: set locktime and/or replaceable?
name_firstupdate_create = rpc_connection.createrawtransaction(name_firstupdate_vin, name_firstupdate_vout)

name_firstupdate_name_index = rawtx_output_index(name_firstupdate_create, name_firstupdate_address)

name_firstupdate_value = get_value_to_register()

name_firstupdate_op = {
    "op": "name_firstupdate",
    "rand": name_firstupdate_salt,
    "name": name_to_register,
    "value": name_firstupdate_value,
}

name_firstupdate_with_name = rpc_connection.namerawtransaction(name_firstupdate_create, name_firstupdate_name_index, name_firstupdate_op)

# TODO: set subtractFeeFromOutputs for fee control?
# TODO: set replaceable?
# TODO: look into lockUnspents?  Only stored in memory, so probably not useful for persistent locking.
name_firstupdate_fund_options = {
}

# Get the fee for name_firstupdate
if fee_type == "feeRate":
    name_firstupdate_fund_options["feeRate"] = fee_rate
    print("name_firstupdate will cost", name_firstupdate_fund_options["feeRate"], "NMC / kB")
elif fee_type == "conf_target":
    name_firstupdate_fund_options["conf_target"] = conf_target
    print("name_firstupdate will confirm approximately", name_firstupdate_fund_options["conf_target"], "after broadcast")

# Get the change address for name_firstupdate
name_firstupdate_custom_change_enabled, name_firstupdate_change_address = get_change_address()
if name_firstupdate_custom_change_enabled:
    name_firstupdate_fund_options["changeAddress"] = name_firstupdate_change_address

# Fund the transaction and add change output.
# TODO: maybe make fundrawtransaction insert the name input?
name_firstupdate_funded = rpc_connection.fundrawtransaction(name_firstupdate_with_name["hex"], name_firstupdate_fund_options)

# If Coin Control is enabled, make sure that fundrawtransaction didn't add extra inputs.
if coin_control_enabled and len(rpc_connection.decoderawtransaction(name_firstupdate_funded["hex"])["vin"]) != len(rpc_connection.decoderawtransaction(name_firstupdate_funded["hex"])["vin"]):
    print("Insufficient funds in Coin Control selection for name_firstupdate")
    quit()

name_firstupdate_signed = rpc_connection.signrawtransaction(name_firstupdate_funded["hex"])
print("name_firstupdate has been signed")

wallet_lock()

queue_transaction(12, 0, name_firstupdate_signed["hex"])

# TODO: lock the inputs of all queued transactions.
print("WARNING: You must use the 'lockunspent false' RPC call against ALL inputs used by queued transactions.  This must be done each time Namecoin Core boots, and also each time a new transaction is queued or broadcast from queue.  If you fail to do this, Namecoin Core is likely to try to double-spend some inputs, which will cause your queued transactions to get rejected by the network.")

quit()
