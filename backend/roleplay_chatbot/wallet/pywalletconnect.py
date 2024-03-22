from pywalletconnect import WCClient, WCClientInvalidOption

# Replace with your WalletConnect project ID and other metadata
WALLETCONNECT_PROJECT_ID = 'your_project_id'
WALLETCONNECT_ORIGIN_DOMAIN = 'your_origin_domain'
WALLET_METADATA = {
    'name': 'Your Wallet Name',
    'description': 'Your Wallet Description',
    'url': 'https://yourwallet.com',
    'icons': ['https://yourwallet.com/icon.png']
}

# Input the WalletConnect URI
string_uri = input("Input the WalletConnect URI: ")

# Set wallet metadata and project details
WCClient.set_wallet_metadata(WALLET_METADATA)
WCClient.set_project_id(WALLETCONNECT_PROJECT_ID)
WCClient.set_origin(WALLETCONNECT_ORIGIN_DOMAIN)

try:
# Create a WalletConnect client instance from the URI
    wallet_dapp = WCClient.from_wc_uri(string_uri)
except WCClientInvalidOption as exc:
    # Handle error in the provided URI
    if hasattr(wallet_dapp, "wc_client"):
        wallet_dapp.close()
        raise exc

# Wait for the session request info
try:
    req_id, chain_ids, request_info = wallet_dapp.open_session()
except Exception as e:
    # Handle session request timeout or other exceptions
    wallet_dapp.close()
    raise e

# Check if the chain ID matches
account_chain_id = 'polkadot_chain_id'  # Replace with the actual chain ID
if account_chain_id not in chain_ids:
    wallet_dapp.close()
    raise Exception("Chain ID mismatch.")

# Display the request details to the user
user_ok = input(f"WalletConnect link request from: {request_info['name']}. Approve? [y/N]")

if user_ok.lower() == 'y':
    # User approved the connection
    account_address = 'your_account_address'  # Replace with the actual account address
    wallet_dapp.reply_session_request(req_id, account_chain_id, account_address)
    print("Session with the Dapp is now opened.")
else:
    # User rejected the connection
    wallet_dapp.reject_session_request(req_id)
    wallet_dapp.close()
    print("User rejected the Dapp connection request.")
