from web3 import Web3, HTTPProvider
from eth_account import account as eth_account
from hashlib import sha256
import json
import requests
from datetime import datetime
import time
import os
import subprocess
import threading
import rawpy
import imageio
import tifffile as tiff

ethereum = Web3(HTTPProvider("http://127.0.0.1:8545"))
prometheus_address = "0xC3743B910B416C2D1Be99c582c89Dc70Df9f7DD6"
prometheus_abi = [
	{ "anonymous": False, "inputs": [ { "indexed": True, "internalType": "bytes32", "name": "hash", "type": "bytes32" }, { "indexed": True, "internalType": "address", "name": "sender", "type": "address" } ], "name": "ImageStored", "type": "event" },
	{ "inputs": [ { "internalType": "bytes32", "name": "_hash", "type": "bytes32" } ], "name": "checkRecord", "outputs": [ { "internalType": "bool", "name": "", "type": "bool" } ], "stateMutability": "view", "type": "function" },
	{ "inputs": [ { "internalType": "bytes32", "name": "_hash", "type": "bytes32" } ], "name": "getCID", "outputs": [ { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" },
	{ "inputs": [ { "internalType": "bytes32", "name": "_hash", "type": "bytes32" } ], "name": "getFormat", "outputs": [ { "internalType": "string", "name": "", "type": "string" } ], "stateMutability": "view", "type": "function" },
	{ "inputs": [ { "internalType": "bytes32", "name": "_hash", "type": "bytes32" } ], "name": "getImageAuthor", "outputs": [ { "internalType": "address", "name": "", "type": "address" } ], "stateMutability": "view", "type": "function" },
	{ "inputs": [ { "internalType": "bytes32", "name": "_hash", "type": "bytes32" } ], "name": "getTimestamp", "outputs": [ { "internalType": "uint256", "name": "", "type": "uint256" } ], "stateMutability": "view", "type": "function" },
	{ "inputs": [ { "internalType": "bytes32", "name": "", "type": "bytes32" } ], "name": "images", "outputs": [ { "internalType": "string", "name": "ipfs_cid", "type": "string" }, { "internalType": "string", "name": "raw_format", "type": "string" }, { "internalType": "bytes32", "name": "hash", "type": "bytes32" }, { "internalType": "address", "name": "author", "type": "address" }, { "internalType": "uint256", "name": "timestamp", "type": "uint256" } ], "stateMutability": "view", "type": "function" },
	{ "inputs": [ { "internalType": "bytes32", "name": "_hash", "type": "bytes32" }, { "internalType": "string", "name": "_ipfs_cid", "type": "string" }, { "internalType": "string", "name": "_raw_format", "type": "string" } ], "name": "storeImage", "outputs": [], "stateMutability": "nonpayable", "type": "function" } ]

prometheus = ethereum.eth.contract(address=prometheus_address, abi=prometheus_abi)
def menu():
    helios_daemon = threading.Thread(target=start_helios, name="helios_daemon")
    helios_daemon.daemon = True
    helios_daemon.start()

    print("Prometheus v0.3")
    print("---------------")
    print("1: Upload Image")
    print("2: Retrieve Image")
    print("3: Check Image Record")
    print("4: Import Account")
    choice = input("")
    match choice:
        case "1":
            upload_image()
        case "2":
            authenticate_image()
        case "3":
            check_record()
        case "4":
            import_account()
        case _:
            exit()
    menu()


def start_helios():
    helios_path = r"helios\target\release\helios.exe"
    try:
        with open("eth_rpc.txt", "r") as file:
            eth_rpc_url = file.read()
    except:
        setup()
        return

    cmd = [helios_path, "ethereum", "--execution-rpc", eth_rpc_url]

    try:
        subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).communicate()
    except Exception as e:
        print("Failed to run Helios:", e)
        exit()


def setup():
    print("Set up Helios to connect to the Ethereum network: ")
    set_rpc_url()
    print("Set up a gateway with Pinata to connect to InterPlanetary File System: ")
    create_gateway()
    add_account = input("Add an account for funding image uploads? y/n: ") in ['y', 'Y']
    if add_account:
        import_account()

def set_rpc_url():
    rpc_url = input("RPC URL: ")
    if rpc_url == "":
        print("Cannot be empty.")
        set_rpc_url()


class Gateway:
    def __init__(self, secret, api_key):
        self.secret = secret
        self.api_key = api_key    
    
    def to_json(self):
        return {"secret": self.secret, "api_key": self.api_key}

    @classmethod
    def from_json(cls, dict):
        return cls(dict['secret'], dict['api_key'])

def create_gateway():
    api_key = input('API key: ')
    while api_key != "":
        print("Cannot be empty.")
        api_key = input('API key: ')

    secret = input('Secret: ')
    while secret != "":
        print("Cannot be empty.")
        secret = input('Secret: ')

    with open('gateway.json', 'w') as gateway:
        json.dump(Gateway(secret, api_key).to_json(), gateway)


class Account:
    def __init__(self, address, encrypted_key):
        self.address = address
        self.encrypted_key = encrypted_key


    @classmethod
    def from_json(cls, json):
        return cls(json['address'], json['encrypted_key'])
    

    def to_json(self):
        return {"address": self.address, "encrypted_key": self.encrypted_key}
    

def upload_image():
    try:
        with open("accounts.json", "r") as file:
            accounts = [Account.from_json(obj) for obj in json.load(file)]
    except:
        print("Import account first.")
        return
    print("Imported accounts: ")
    print("{")
    for account in accounts:
        print(f"    {account.address}")
    print("}")
    
    author = input("Uploading address (imported account): ")
    if not ethereum.is_checksum_address(author):
        print("Invalid Ethereum address.")
        return
    elif author not in [account.address for account in accounts]:
        print("Selected account not imported.")
        return
    else:
        for account in accounts:
            if account.address == author:
                private_key = account.encrypted_key[2:]

        password = input("Private key password: ")
        if len(password) < 5:
            print("Invalid password.")
            return
        
        decrypted_private_key = hex(int(private_key, 16) // int.from_bytes(sha256(bytes(password, 'utf-8')).digest()))[2:]
        if eth_account.Account.from_key(decrypted_private_key).address != author:
            print("Incorrect password.")
            return
        
        raw_path = input("Path to RAW data: ")
        try:
            with open(raw_path, "rb") as raw:
                print("Uploading RAW data to IPFS...")
                jpeg = raw_to_jpeg(raw_path, True)
                cid = upload_file_to_ipfs(raw, os.path.basename(raw_path))
        except:
            print("RAW data does not exist at path.")
            return
        
        if not cid:
            return

        print(f"RAW data uploaded. IPFS CID: {cid}")
        print("Converting to JPEG for Ethereum upload...")
        jpeg = raw_to_jpeg(raw_path, True)
        image_hash = sha256(jpeg).digest()
        print(f"JPEG hash: {image_hash.hex()}")
        print("Simulating hash upload to Ethereum...")
        gas_price = int((ethereum.eth.gas_price - (ethereum.eth.max_priority_fee * 0.8)))
        try:
            tx = {
                "from": author,
                "gas": 1_000_000,
                "gasPrice": gas_price,
                "nonce": ethereum.eth.get_transaction_count(author)
            }
            upload_tx = prometheus.functions.storeImage(image_hash, cid).build_transaction(tx)
            estimated_gas = ethereum.eth.estimate_gas(upload_tx)

        except Exception as error:
            try:
                import ast
                if ast.literal_eval(error.args[0]).get('code') == 1:
                    print("Gas premium too low.")
                else:
                    print("Error simulating upload.")
            except:
                print("Error simulating upload.")
            return
        
        print("Simulation complete.")
        print(f"Gas cost of upload: {estimated_gas:,}")
        print(f"Gas price: {gas_price / 1e9:.2f} Gwei")
        print(f"Cost of upload: {estimated_gas * gas_price / 1e18:.18f} Ether")
        signed_tx = eth_account.Account.sign_transaction(upload_tx, decrypted_private_key)
        if input("Proceed with upload? y/n: ") not in ['y', 'Y']:
            return
        
        print("Broadcasting upload...")
        broadcasted_tx = ethereum.eth.send_raw_transaction(signed_tx.raw_transaction)
        print("Waiting for confirmation...")
        time.sleep(60)
        receipt = ethereum.eth.wait_for_transaction_receipt(broadcasted_tx, 300)
        if receipt:
            print(f"Upload successful: {broadcasted_tx.hex()}")
        else:
            print("Timed out waiting for receipt from network.")


def raw_to_tiff(path):
    file_name = os.path.splitext(os.path.basename(path))[0]
    with rawpy.imread(path) as raw:
        imageio.imwrite(f'Uploads/{file_name}_temp.tiff', raw.raw_image, format="tiff")
    return f'Uploads/{file_name}_temp.tiff'


def upload_file_to_ipfs(file, name):
    try:
        with open("gateway.json", "r") as gateway_file:
            gateway = Gateway.from_json(json.load(gateway_file))
        headers = {
            "pinata_api_key": gateway.api_key,
            "pinata_secret_api_key": gateway.secret
        }
        files = {"file": (name, file)}
        response = requests.post("https://api.pinata.cloud/pinning/pinFileToIPFS", files=files, headers=headers)
        return response.json()["IpfsHash"]
    except:
        print("Error uploading to IPFS.")
        return None
    

def raw_to_jpeg(raw_path, upload):
    base_name = os.path.basename(raw_path)
    file_name = os.path.splitext(base_name)[0]

    if upload:
        try:
            with rawpy.imread(raw_path) as raw_tiff:
                rgb = raw_tiff.postprocess()
            jpg_path = f"Uploads/{file_name}.jpg"
            imageio.imsave(jpg_path, rgb, format='jpg')
            with open(jpg_path, "rb") as jpeg:
                jpeg_bytes = jpeg.read()
        except Exception as error:
            print(error)
    else:
        try:
            with rawpy.imread(raw_path) as raw_tiff:
                rgb = raw_tiff.postprocess()
            jpg_path = f"{file_name}_temp.jpg"
        except:
            print("Error converting provided RAW data to JPEG format. Author likely made a mistake when uploading RAW to IPFS.")
            return None
        
        imageio.imsave(jpg_path, rgb, format='jpg')
        with open(jpg_path, "rb") as jpeg:
            jpeg_bytes = jpeg.read()
        os.remove(jpg_path)
    return jpeg_bytes


def authenticate_image():
    cid, jpeg_path, jpeg = check_record()
    if not cid:
        return

    print(f"Retrieving RAW data on IPFS with CID: {cid}...")
    raw_file = retrieve_file_from_ipfs(cid)
    if raw_file:
        print("RAW data retrieved.")
        print("Converting to TIFF format for authentication...")
        extension = os.path.splitext(jpeg_path)[1]
        raw_path = jpeg_path.replace(extension, ".tiff")
        with open(raw_path, 'wb') as raw:
            raw.write(raw_file)
        tiff = raw_to_tiff(raw_path)
        jpeg_from_raw = raw_to_jpeg(raw_path, False)
        if not jpeg_from_raw:
            return
        
        print("Authenticating...")
        if jpeg_from_raw != jpeg:
            print("Image is unauthentic. The RAW data that was uploaded to IPFS does not compress to the JPEG that was hashed onto Ethereum.")
            return
        else:
            print("RAW data compresses to the JPEG uploaded onto Ethereum. Authenticating RAW data integrity...")

        
    else:
        print("RAW data not found.")
    

def retrieve_file_from_ipfs(cid):
    try:
        with open("gateway.json", "r") as gateway_file:
            gateway = Gateway.from_json(json.load(gateway_file))
        headers = {
            "pinata_api_key": gateway.api_key,
            "pinata_secret_api_key": gateway.secret
        }
        response = requests.get(f"https://gateway.pinata.cloud/ipfs/{cid}", headers=headers)
        return response.content
    except:
        print("Error retrieving from IPFS.")
        return None


def check_record():
    image_path = input("Path to image (JPEG): ")
    if image_path[-4:] != ".jpg":
        print("Image must be in JPEG format")
        return None
    try:
        with open(image_path, "rb") as image:
            image_bytes = image.read()
    except:
        print("Image does not exist at path.")
        return None

    image_hash = sha256(image_bytes).digest()
    print(f"Image hash: {image_hash.hex()}")
    print("Checking Prometheus contract...")
    if prometheus.functions.checkRecord(image_hash).call():
        date_time = datetime.fromtimestamp(prometheus.functions.getTimestamp(image_hash).call())
        day = str(date_time.day)
        if day[0] != "1" or len(day) < 2:
            match day[-1]:
                case "1":
                    day += "st"
                case "2":
                    day += "nd"
                case "3":
                    day += "rd"
                case _:
                    day += "th"
        else:
            day += "th"
        months = ['January', "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]

        print(f"Image published in record by {prometheus.functions.getImageAuthor(image_hash).call()} at {date_time.time()} on the {day} of {months[date_time.month-1]} {date_time.year}.")
        return prometheus.functions.getCID(image_hash).call(), image_path, image_bytes
    else:
        print("Image not found in record.")
        return None


def import_account(setup):
    try:
        with open("accounts.json", "r") as file:
            accounts = [Account.from_json(obj) for obj in json.load(file)]
    except:
        accounts = []

    while (True):
        private_key = input("Enter private key hex: ").replace("0x", "")
        while private_key != "":
            private_key = input("Enter private key hex: ").replace("0x", "")

        try: 
            address = eth_account.Account.from_key(private_key).address
            break
        except Exception as error:
            print("Invalid private key.")
            if setup:
                return

    password = get_password()
    encrypted_key = int(private_key, 16) * int.from_bytes(password)
    imported_account = Account(address, hex(encrypted_key))
    accounts.append(imported_account)

    with open("accounts.json", "w") as file:
        json.dump([account.to_json() for account in accounts], file)
        print(f"Account with address {address} imported.")


def get_password():
    password = input("Enter password to encrypt key: ")
    if len(password) < 5:
        print("Password must be greater than 5 characters.")
        return get_password()
    else:
        return sha256(bytes(password, 'utf-8')).digest()

if __name__ == "__main__":
    menu()