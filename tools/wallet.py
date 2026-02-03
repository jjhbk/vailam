from mcp.server import Server

server = Server("wallet")

WALLET_ADDRESS = "0xABC123..."


@server.tool(name="wallet.address", description="Get wallet address")
def get_address():
    return WALLET_ADDRESS


@server.tool(name="wallet.sign_message", description="Sign a message (no key exposure)")
def sign_message(message: str):
    return f"signed({message})"


server.run()
