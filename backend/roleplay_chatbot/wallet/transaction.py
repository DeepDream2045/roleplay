from substrateinterface import SubstrateInterface, Keypair

# Step 1: Connect to the Polkadot Node
substrate = SubstrateInterface(
    url="wss://rpc.polkadot.io",
    address_type=42,
    type_registry_preset='polkadot',
    type_registry={
        # "Address": "AccountId",
        # "LookupSource": "AccountId"
        "Address": "5FnywVmQro8M1vRNBnebL4JcWkHhYwnKcPk35DmcgxX8uWoJ",
        "LookupSource": "5FnywVmQro8M1vRNBnebL4JcWkHhYwnKcPk35DmcgxX8uWoJ"
    }
)

# Step 2: Define Sender Account and Recipient Address
sender = Keypair.create_from_uri("5FnywVmQro8M1vRNBnebL4JcWkHhYwnKcPk35DmcgxX8uWoJ")
recipient_address = "5Fpxt57v6Ri46ypU1UUSppyNdGaZBMqAsUvzF9paW9a7YUAy"

# Step 3: Create and Submit Transaction
call = substrate.compose_call(
    call_module='Balances',
    call_function='transfer',
    call_params={
        'dest': recipient_address,
        'value': 1 * 10**12  # Amount in Planck (12 zeros for DOT)
    }
)

extrinsic = substrate.create_signed_extrinsic(call=call, keypair=sender)
result = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)

print("Transaction Hash:", result)