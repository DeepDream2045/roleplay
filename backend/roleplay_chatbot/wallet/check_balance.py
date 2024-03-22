from substrateinterface import SubstrateInterface

# Specify the account address for which you want to fetch the balance
account_address = "5FnywVmQro8M1vRNBnebL4JcWkHhYwnKcPk35DmcgxX8uWoJ"

# Connect to the Polkadot Node
# substrate = SubstrateInterface(url="wss://rpc.polkadot.io")
substrate = SubstrateInterface(url="wss://rococo-rpc.polkadot.io")

# Get the current block hash
block_hash = substrate.get_block_hash()

# Query the balance for the specified account
balance_info = substrate.query('System', 'Account', [account_address], block_hash=block_hash)

# Extract and print the free balance of the account
free_balance = balance_info.value['data']['free']
print(f"Free balance of account '{account_address}': {free_balance}", balance_info.value['data'])