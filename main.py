import os
import hashlib
import json
import time
import random
import logging
import openai
import base64
import requests
import jwt  # Pentru generarea și validarea JWT
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Welcome to the HumaniChain API!"}



load_dotenv()

# Configurări JWT
JWT_SECRET = os.getenv("JWT_SECRET", "default_secret")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 30

# Instanțiere FastAPI
app = FastAPI(title="Blockchain API", description="O aplicație blockchain cu smart contracts, identitate și multe altele.")

# Configurare OAuth2 pentru JWT
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Logging setup
logging.basicConfig(level=logging.INFO)
AUDIT_LOG_FILE = "audit.log"

def audit_log(message: str):
    """
    Înregistrează mesajele de audit într-un fișier și în consola de logare.
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    try:
        with open(AUDIT_LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        logging.error(f"Eroare la scrierea logului: {e}")
    logging.info(f"Audit: {message}")

# Configurarea cheii OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")

DEFAULT_DIFFICULTY = 2

def compute_merkle_root(transactions: List[Dict[str, Any]]) -> str:
    """
    Calculează Merkle Root pe baza tranzacțiilor.
    """
    if not transactions:
        return ""
    def hash_pair(a: str, b: str) -> str:
        return hashlib.sha256((a + b).encode()).hexdigest()
    hashes_list = [hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest() for tx in transactions]
    while len(hashes_list) > 1:
        if len(hashes_list) % 2 != 0:
            hashes_list.append(hashes_list[-1])
        new_level = []
        for i in range(0, len(hashes_list), 2):
            new_level.append(hash_pair(hashes_list[i], hashes_list[i + 1]))
        hashes_list = new_level
    return hashes_list[0]

class DigitalSignature:
    """Clasă pentru generarea și verificarea semnăturilor digitale."""
    @staticmethod
    def generate_keys():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def sign_data(data: str, private_key) -> str:
        signature = private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    @staticmethod
    def verify_signature(data: str, signature: str, public_key) -> bool:
        try:
            decoded_sig = base64.b64decode(signature.encode())
            public_key.verify(
                decoded_sig,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logging.error(f"Verificarea semnăturii digitale a eșuat: {e}")
            return False

USER_KEYS = {
    "Alice": DigitalSignature.generate_keys(),
    "Bob": DigitalSignature.generate_keys(),
    "Charlie": DigitalSignature.generate_keys(),
}

USER_AUTH_DATA = {
    "Alice": {"password": "alice_pwd", "biometric": "alice_face_hash", "otp": "123456"},
    "Bob": {"password": "bob_pwd", "biometric": "bob_face_hash", "otp": "654321"},
    "Charlie": {"password": "charlie_pwd", "biometric": "charlie_face_hash", "otp": "111222"},
}

class Block:
    """
    Reprezintă un bloc din blockchain.
    """
    def __init__(self, index, previous_hash, transactions, timestamp, validator, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.timestamp = timestamp
        self.validator = validator
        self.nonce = nonce
        self.merkle_root = compute_merkle_root(transactions)
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """
        Calculează hash-ul blocului pe baza conținutului acestuia.
        """
        block_contents = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "validator": self.validator,
            "nonce": self.nonce,
            "merkle_root": self.merkle_root
        }
        block_string = json.dumps(block_contents, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def mine_block(self, difficulty: int):
        """
        Procesează blocul (mining) până când hash-ul îndeplinește condiția de dificultate.
        """
        target = "0" * difficulty
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
        audit_log(f"Block mined: {self.hash}")

class Consensus:
    """
    Clasă care definește mecanismul de consens și validarea blocurilor.
    """
    def __init__(self, mechanism="PoW", block_time=10, difficulty=DEFAULT_DIFFICULTY, reward=50):
        self.mechanism = mechanism
        self.block_time = block_time
        self.difficulty = difficulty
        self.reward = reward

    def validate_block(self, block: Block) -> bool:
        if self.mechanism == "PoW":
            target = "0" * self.difficulty
            return block.hash.startswith(target)
        elif self.mechanism == "PoS":
            return block.hash[-1] in "01234"
        elif self.mechanism == "hybrid":
            target = "0" * (self.difficulty // 2)
            return block.hash.startswith(target) and block.hash[-1] in "01234"
        else:
            return False

    def get_reward(self) -> int:
        return self.reward

class SmartContractEngine:
    """
    Motor pentru implementarea și execuția smart contractelor.
    """
    def __init__(self):
        self.contracts = {}

    def deploy_contract(self, contract_id: str, contract_code: str) -> bool:
        self.contracts[contract_id] = contract_code
        audit_log(f"Contract {contract_id} deployed.")
        return True

    def execute_contract(self, contract_id: str, context: Dict[str, Any]) -> str:
        contract = self.contracts.get(contract_id)
        if not contract:
            return "Contract not found."
        result = f"Executed contract {contract_id} with context {context}."
        audit_log(result)
        return result

smart_contract_engine = SmartContractEngine()

# Clasă auxiliară pentru controlul emisiilor (ex: pentru UBI)
class EmissionControl:
    def adjust_emission(self, factor: float) -> float:
        # Ajustează emisia pe baza unui factor (exemplu simplificat)
        return 100 * factor

class BlockchainNetwork:
    """
    Clasă ce implementează logica rețelei blockchain.
    """
    def __init__(self, consensus: Consensus, network_type="public"):
        self.chain = []
        self.pending_transactions = []
        self.consensus = consensus
        self.coins = {"UBITokens": []}
        self.coin_rules = {}
        self.network_type = network_type
        self.authorized_nodes = []
        self.identities = {}
        self.devices = {}
        self.governance_proposals = {}
        self.social_initiatives = {}
        self.feedback = []
        self.official_documents = {}
        self.multi_currency_balances = {}
        self.peer_nodes = []
        self.emission_control = EmissionControl()
        # Încercăm încărcarea stării blockchain-ului la pornire
        self.load_chain()

    def create_genesis_block(self):
        """
        Creează blocul genesis și îl adaugă în lanț.
        """
        genesis_block = Block(0, "0", [], time.time(), "Genesis")
        self.chain.append(genesis_block)
        audit_log("Genesis block created.")

    def set_authorized_nodes(self, nodes: List[str]):
        """
        Setează nodurile autorizate pentru rețelele de tip corporate.
        """
        if self.network_type == "corporate":
            self.authorized_nodes = nodes
            audit_log(f"Authorized nodes set: {nodes}")

    def validate_node_access(self, node_id: str) -> bool:
        if self.network_type != "corporate":
            return True
        return node_id in self.authorized_nodes

    def encrypt_transaction(self, transaction: dict) -> dict:
        """
        Criptează tranzacția folosind Base64 (simulare).
        """
        transaction_str = json.dumps(transaction, sort_keys=True)
        encrypted = base64.b64encode(transaction_str.encode()).decode()
        return {"encrypted_data": encrypted}

    def decrypt_transaction(self, encrypted_transaction: dict) -> dict:
        encrypted = encrypted_transaction.get("encrypted_data")
        if not encrypted:
            return {}
        try:
            decrypted_str = base64.b64decode(encrypted.encode()).decode()
            return json.loads(decrypted_str)
        except Exception as e:
            logging.error(f"Eroare la decriptarea tranzacției: {e}")
            return {}

    def create_coin(self, coin_name: str, growth_factor=1.01):
        if coin_name not in self.coins:
            self.coins[coin_name] = []
            self.coin_rules[coin_name] = {"growth_factor": growth_factor}
            audit_log(f"Coin {coin_name} created with growth factor {growth_factor}")

    def coin_growth_effect(self, coin: str):
        if coin in self.coin_rules:
            growth = self.coin_rules[coin]["growth_factor"]
            bonus = 10 * growth
            self.coins["UBITokens"].append({
                "sender": "System",
                "receiver": "UBITokens",
                "amount": bonus,
                "coin": "UBITokens"
            })
            audit_log(f"Growth effect for {coin}: bonus {bonus}")

    def compute_transaction_fee(self, transaction: dict) -> float:
        return 0.01 * transaction.get("amount", 0)

    def update_balance(self, sender: str, receiver: str, amount: float, coin: str):
        if sender not in self.multi_currency_balances:
            self.multi_currency_balances[sender] = {}
        if receiver not in self.multi_currency_balances:
            self.multi_currency_balances[receiver] = {}
        self.multi_currency_balances[sender][coin] = self.multi_currency_balances[sender].get(coin, 0) - amount
        self.multi_currency_balances[receiver][coin] = self.multi_currency_balances[receiver].get(coin, 0) + amount
        audit_log(f"Balances updated: {sender} -> {receiver} {amount} {coin}")

    def add_transaction(self, sender: str, receiver: str, amount: float, coin="UBITokens", signature=None):
        transaction_data = {
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "coin": coin
        }
        data_str = json.dumps(transaction_data, sort_keys=True)
        if sender in USER_KEYS and signature:
            public_key = USER_KEYS[sender][1]
            if not DigitalSignature.verify_signature(data_str, signature, public_key):
                raise HTTPException(status_code=400, detail="Invalid digital signature.")
        else:
            raise HTTPException(status_code=400, detail="Digital signature missing.")
        if self.network_type == "corporate":
            if not self.validate_node_access(sender):
                raise HTTPException(status_code=403, detail="Sender not authorized in corporate network.")
            transaction_data = self.encrypt_transaction(transaction_data)
        fee = self.compute_transaction_fee({"amount": amount})
        transaction = {
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "fee": fee,
            "coin": coin,
            "signature": signature
        }
        if self.network_type == "corporate":
            transaction["encrypted"] = transaction_data
        self.pending_transactions.append(transaction)
        audit_log(f"Transaction added: {transaction}")
        self.update_balance(sender, receiver, amount, coin)
        return True

    def distribute_ubi(self):
        ubi_amount = self.emission_control.adjust_emission(random.random())
        transaction = {
            "sender": "HumaniChain",
            "receiver": "All_Users",
            "amount": ubi_amount,
            "fee": 0,
            "coin": "UBITokens",
            "signature": "system-signature"
        }
        self.pending_transactions.append(transaction)
        audit_log(f"UBI distribution transaction added: {transaction}")

    def add_block(self, validator="AI_Node"):
        new_block = Block(len(self.chain), self.chain[-1].hash, self.pending_transactions, time.time(), validator)
        if self.consensus.mechanism == "PoW":
            new_block.mine_block(self.consensus.difficulty)
        elif self.consensus.mechanism in ["PoS", "hybrid"]:
            new_block.nonce = 0
            new_block.hash = new_block.calculate_hash()
            audit_log(f"Block validated via {self.consensus.mechanism}: {new_block.hash}")
        else:
            raise Exception("Unknown consensus mechanism.")
        if not self.consensus.validate_block(new_block):
            raise HTTPException(status_code=400, detail="Block validation failed.")
        self.chain.append(new_block)
        for tx in self.pending_transactions:
            self.coins[tx["coin"]].append(tx)
            if tx["coin"] in self.coin_rules and self.coin_rules[tx["coin"]]["growth_factor"] > 1:
                self.coin_growth_effect(tx["coin"])
        self.pending_transactions = []
        audit_log("Block added to blockchain.")
        self.broadcast_block(new_block)
        # Salvăm starea blockchain-ului după adăugarea blocului
        self.save_chain()

    def broadcast_block(self, block: Block):
        block_data = {
            "index": block.index,
            "previous_hash": block.previous_hash,
            "transactions": block.transactions,
            "timestamp": block.timestamp,
            "validator": block.validator,
            "nonce": block.nonce,
            "merkle_root": block.merkle_root,
            "hash": block.hash
        }
        for peer in self.peer_nodes:
            try:
                response = requests.post(peer + "/receive_block", json=block_data, timeout=5)
                audit_log(f"Broadcast block to {peer}: {response.json()}")
            except Exception as e:
                audit_log(f"Error broadcasting block to {peer}: {e}")

    def resolve_forks(self):
        audit_log("Forks resolved.")
        return self.chain

    def save_chain(self, filename="blockchain.json"):
        try:
            with open(filename, "w") as f:
                chain_data = [block.__dict__ for block in self.chain]
                json.dump(chain_data, f, indent=4)
            audit_log("Blockchain saved.")
        except Exception as e:
            logging.error(f"Error saving blockchain: {e}")

    def load_chain(self, filename="blockchain.json"):
        try:
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    chain_data = json.load(f)
                    self.chain = []
                    for block_info in chain_data:
                        block = Block(
                            block_info["index"],
                            block_info["previous_hash"],
                            block_info["transactions"],
                            block_info["timestamp"],
                            block_info["validator"],
                            block_info.get("nonce", 0)
                        )
                        block.hash = block_info["hash"]
                        block.merkle_root = block_info.get("merkle_root", compute_merkle_root(block_info["transactions"]))
                        self.chain.append(block)
                audit_log("Blockchain loaded.")
            else:
                self.create_genesis_block()
        except Exception as e:
            logging.error(f"Error loading blockchain: {e}")

    def execute_smart_contract(self, contract_id: str, context: Dict[str, Any]):
        result = smart_contract_engine.execute_contract(contract_id, context)
        return result

    # Governance functions
    def update_governance(self, proposal: str):
        proposal_id = len(self.governance_proposals) + 1
        self.governance_proposals[proposal_id] = {"proposal": proposal, "votes": {}}
        audit_log(f"Governance proposal added: {proposal_id} - {proposal}")
        return proposal_id

    def vote_on_proposal(self, proposal_id: int, voter: str, vote: bool):
        if proposal_id in self.governance_proposals:
            self.governance_proposals[proposal_id]["votes"][voter] = vote
            audit_log(f"Vote on proposal {proposal_id} by {voter}: {vote}")
            return True
        else:
            logging.error("Nonexistent governance proposal.")
            return False

    def register_identity(self, user: str, identity_data: Dict[str, Any]):
        # Verificăm existența câmpului obligatoriu 'biometric_hash'
        if "biometric_hash" not in identity_data:
            raise HTTPException(status_code=400, detail="Identity data must include a 'biometric_hash'.")
        self.identities[user] = identity_data
        audit_log(f"Identity registered for {user}: {identity_data}")
        return True

    def register_device(self, device_id: str, metadata: Dict[str, Any]):
        self.devices[device_id] = metadata
        audit_log(f"IoT device registered: {device_id} with metadata: {metadata}")
        return True

    def register_official_document(self, user: str, doc_type: str, document_hash: str, metadata: Dict[str, Any]):
        if user not in self.official_documents:
            self.official_documents[user] = []
        document_entry = {
            "doc_type": doc_type,
            "document_hash": document_hash,
            "metadata": metadata,
            "timestamp": time.time()
        }
        self.official_documents[user].append(document_entry)
        audit_log(f"Official document registered for {user}: {document_entry}")
        return document_entry

    def get_official_documents(self, user: str):
        return self.official_documents.get(user, {})

    # Interoperability functions
    def connect_to_interoperability(self, other_chain_data: dict) -> bool:
        audit_log("Connected to external blockchain network.")
        return True

    def send_data_to_blockchain(self, data: dict) -> bool:
        audit_log(f"Data sent to external blockchain: {data}")
        return True

    def receive_data_from_blockchain(self) -> dict:
        received_data = {"external_data": random.random()}
        audit_log(f"Data received from external blockchain: {received_data}")
        return received_data

    def simulate_layer2_scaling(self):
        audit_log("Simulating Layer 2 scaling solution.")
        return True

    def fetch_oracle_data(self):
        dummy_data = {"price": random.uniform(1, 100)}
        audit_log(f"Oracle data: {dummy_data}")
        return dummy_data

    def anomaly_detection(self):
        audit_log("Anomaly detection: no significant anomalies.")
        return False

    def electronic_voting(self, votes: Dict[str, bool]):
        audit_log(f"Electronic voting processed: {votes}")
        return "Vote processed."

    def certify_document(self, document: Dict[str, Any]):
        certificate = {"document": document, "certificate": "Valid", "timestamp": time.time()}
        audit_log(f"Document certified: {certificate}")
        return certificate

    def report_environmental_impact(self):
        report = {"energy_consumption": random.uniform(1000, 5000), "carbon_footprint": random.uniform(100, 500)}
        audit_log(f"Environmental impact report: {report}")
        return report

    def experiment_new_consensus(self):
        audit_log("Experimenting with a new consensus model.")
        return "Experimental consensus applied."

    def soft_fork_update(self, new_parameters: Dict[str, Any]):
        audit_log(f"Soft fork updated with parameters: {new_parameters}")
        return True

    def cybersecurity_monitor(self):
        audit_log("Cybersecurity monitoring activated.")
        return True

    def register_social_initiative(self, initiative_type: str, description: str, required_funds: float):
        initiative_id = len(self.social_initiatives) + 1
        self.social_initiatives[initiative_id] = {
            "type": initiative_type,
            "description": description,
            "required_funds": required_funds,
            "votes": {},
            "status": "pending"
        }
        audit_log(f"Social initiative registered: {initiative_id} - {initiative_type}: {description}, requires funds: {required_funds}")
        return initiative_id

    def vote_social_initiative(self, initiative_id: int, voter: str, vote: bool):
        if initiative_id in self.social_initiatives:
            self.social_initiatives[initiative_id]["votes"][voter] = vote
            audit_log(f"Vote on social initiative {initiative_id} by {voter}: {vote}")
            return True
        else:
            logging.error("Nonexistent social initiative.")
            return False

    def execute_social_initiative(self, initiative_id: int):
        if initiative_id in self.social_initiatives:
            initiative = self.social_initiatives[initiative_id]
            votes = initiative["votes"]
            if len(votes) == 0:
                logging.error("No votes for initiative.")
                return "No votes."
            positive_votes = sum(1 for v in votes.values() if v)
            if positive_votes > len(votes) / 2:
                initiative["status"] = "approved"
                audit_log(f"Social initiative {initiative_id} approved and executed.")
                return f"Social initiative {initiative_id} executed: {initiative['type']}."
            else:
                initiative["status"] = "rejected"
                audit_log(f"Social initiative {initiative_id} rejected.")
                return f"Social initiative {initiative_id} rejected."
        else:
            return "Initiative does not exist."

    def launch_basic_income_program(self):
        income_amount = 100
        for user in self.identities.keys():
            transaction = {
                "sender": "HumaniChain",
                "receiver": user,
                "amount": income_amount,
                "fee": 0,
                "coin": "UBITokens",
                "signature": "system-signature"
            }
            self.pending_transactions.append(transaction)
            audit_log(f"Basic income distributed for {user}: {income_amount} UBITokens")
        self.add_block(validator="System_Basic_Income")
        return "Basic income program launched."

    def fund_education_program(self, program_name: str, required_funds: float):
        audit_log(f"Education program: {program_name} requires {required_funds} funds.")
        return f"Education program '{program_name}' received simulated funding of {required_funds} units."

    def fund_healthcare_program(self, program_name: str, required_funds: float):
        audit_log(f"Healthcare program: {program_name} requires {required_funds} funds.")
        return f"Healthcare program '{program_name}' received simulated funding of {required_funds} units."

    def social_audit(self):
        audit_report = {
            "num_initiatives": len(self.social_initiatives),
            "initiatives": self.social_initiatives,
            "registered_identities": list(self.identities.keys())
        }
        audit_log(f"Social audit report: {audit_report}")
        return audit_report

    def report_social_metrics(self):
        metrics = {
            "inequality_index": random.uniform(0, 1),
            "education_index": random.uniform(0, 1),
            "health_index": random.uniform(0, 1),
            "social_cohesion": random.uniform(0, 1)
        }
        audit_log(f"Social metrics: {metrics}")
        return metrics

    def submit_feedback(self, user: str, feedback_text: str):
        feedback_id = len(self.feedback) + 1
        feedback_entry = {
            "id": feedback_id,
            "user": user,
            "feedback": feedback_text,
            "timestamp": time.time()
        }
        self.feedback.append(feedback_entry)
        audit_log(f"Feedback received from {user}: {feedback_text}")
        return feedback_id

    def get_feedback(self):
        return self.feedback

    def simulate_bank_integration(self) -> dict:
        bank_info = {
            "bank_name": "Demo Bank",
            "account_number": "1234567890",
            "balance": random.uniform(1000, 10000)
        }
        audit_log(f"Simulated bank info: {bank_info}")
        return bank_info

    def simulate_bank_transfer(self, account_number: str, amount: float) -> bool:
        audit_log(f"Simulated bank transfer: {amount} transferred from account {account_number}")
        return True

# Virtual Assistant
class VirtualAssistant:
    def __init__(self):
        self.conversations = {}

    def chat(self, user: str, message: str) -> str:
        if user not in self.conversations:
            self.conversations[user] = []
        self.conversations[user].append({"role": "user", "content": message})
        messages = [{"role": "system", "content": "You are a personal virtual assistant."}] + self.conversations[user]
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=messages,
                max_tokens=150
            )
            assistant_response = response.choices[0].message.content.strip()
            self.conversations[user].append({"role": "assistant", "content": assistant_response})
            return assistant_response
        except Exception as e:
            logging.error(f"VirtualAssistant error: {e}")
            return "There was an error processing your request."

# Authenticator pentru multi-factor authentication
class Authenticator:
    def verify_password(self, username: str, password: str) -> bool:
        stored = USER_AUTH_DATA.get(username)
        return stored is not None and stored["password"] == password

    def verify_biometric(self, username: str, biometric_data: str) -> bool:
        stored = USER_AUTH_DATA.get(username)
        return stored is not None and stored["biometric"] == biometric_data

    def verify_otp(self, username: str, otp: str) -> bool:
        stored = USER_AUTH_DATA.get(username)
        return stored is not None and stored["otp"] == otp

    def login(self, username: str, password: str, biometric_data: str, otp: str) -> str:
        if not self.verify_password(username, password):
            raise HTTPException(status_code=401, detail="Incorrect password.")
        if not self.verify_biometric(username, biometric_data):
            raise HTTPException(status_code=401, detail="Biometric authentication failed.")
        if not self.verify_otp(username, otp):
            raise HTTPException(status_code=401, detail="Incorrect OTP.")
        # Generăm un token JWT
        expiration = datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
        payload = {"sub": username, "exp": expiration}
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        audit_log(f"User {username} logged in successfully. Token issued.")
        return token

# Funcție pentru validarea token-urilor JWT
def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# Instanțiere VirtualAssistant și Authenticator
virtual_assistant = VirtualAssistant()
authenticator = Authenticator()

# Instanțiere BlockchainNetwork cu consens personalizat și modul corporate activat
consensus = Consensus(mechanism="PoS", block_time=10, difficulty=DEFAULT_DIFFICULTY, reward=50)
blockchain = BlockchainNetwork(consensus=consensus, network_type="corporate")

# Funcție helper pentru semnarea tranzacțiilor
def sign_transaction(sender: str, receiver: str, amount: float, coin="UBITokens") -> str:
    transaction_data = json.dumps({
        "sender": sender,
        "receiver": receiver,
        "amount": amount,
        "coin": coin
    }, sort_keys=True)
    if sender in USER_KEYS:
        private_key = USER_KEYS[sender][0]
        return DigitalSignature.sign_data(transaction_data, private_key)
    else:
        raise Exception("Private key for the specified user was not found.")

# MODELE Pydantic pentru validarea datelor de intrare

class LoginRequest(BaseModel):
    username: str
    password: str
    biometric: str
    otp: str

class IdentityData(BaseModel):
    biometric_hash: str
    full_name: Optional[str] = None
    email: Optional[str] = None

class RegisterIdentityRequest(BaseModel):
    user: str
    identity_data: IdentityData

class PurchaseRequest(BaseModel):
    username: str
    merchant: str
    amount: float = Field(gt=0, description="Suma trebuie să fie pozitivă.")
    biometric: str
    coin: Optional[str] = "UBITokens"

class RegisterDocumentRequest(BaseModel):
    user: str
    doc_type: str
    document_hash: str
    metadata: Dict[str, Any]

class DeployContractRequest(BaseModel):
    contract_id: str
    contract_code: str

class ExecuteContractRequest(BaseModel):
    contract_id: str
    context: Dict[str, Any]

# API Endpoints

@app.post("/login")
def login(request: LoginRequest):
    """
    Endpoint pentru autentificare multi-factor.
    Returnează un token JWT la autentificarea reușită.
    """
    token = authenticator.login(request.username, request.password, request.biometric, request.otp)
    return {"message": "Login successful.", "token": token}

@app.post("/register_identity")
def register_identity(request: RegisterIdentityRequest, current_user: str = Depends(get_current_user)):
    """
    Înregistrează identitatea unui utilizator.
    Verifică dacă identity_data conține câmpul obligatoriu 'biometric_hash'.
    """
    blockchain.register_identity(request.user, request.identity_data.dict())
    return {"message": f"Identity registered for {request.user}."}

@app.post("/purchase")
def purchase(request: PurchaseRequest, current_user: str = Depends(get_current_user)):
    """
    Endpoint pentru efectuarea unei achiziții, cu verificare biometrică.
    """
    if not authenticator.verify_biometric(request.username, request.biometric):
        raise HTTPException(status_code=401, detail="Biometric authentication failed.")
    signature = sign_transaction(request.username, request.merchant, request.amount, request.coin)
    blockchain.add_transaction(request.username, request.merchant, request.amount, request.coin, signature=signature)
    return {"message": f"Purchase of {request.amount} {request.coin} completed from {request.username} to {request.merchant}."}

@app.post("/register_document")
def register_document(request: RegisterDocumentRequest, current_user: str = Depends(get_current_user)):
    """
    Înregistrează un document oficial.
    """
    document_entry = blockchain.register_official_document(request.user, request.doc_type, request.document_hash, request.metadata)
    return {"message": "Official document registered.", "document": document_entry}

@app.get("/get_documents")
def get_documents(user: str, current_user: str = Depends(get_current_user)):
    """
    Returnează documentele oficiale ale unui utilizator.
    """
    docs = blockchain.get_official_documents(user)
    return {"documents": docs}

@app.post("/deploy_contract")
def deploy_contract(request: DeployContractRequest, current_user: str = Depends(get_current_user)):
    """
    Deployează un smart contract.
    """
    success = smart_contract_engine.deploy_contract(request.contract_id, request.contract_code)
    return {"message": "Contract deployed." if success else "Deployment failed."}

@app.post("/execute_contract")
def execute_contract(request: ExecuteContractRequest, current_user: str = Depends(get_current_user)):
    """
    Execută un smart contract existent cu contextul specificat.
    """
    result = blockchain.execute_smart_contract(request.contract_id, request.context)
    return {"message": result}

@app.post("/interoperability/send")
def interoperability_send(data: Dict[str, Any], current_user: str = Depends(get_current_user)):
    success = blockchain.send_data_to_blockchain(data)
    return {"message": "Data sent to external blockchain." if success else "Data transmission failed."}

@app.get("/interoperability/receive")
def interoperability_receive(current_user: str = Depends(get_current_user)):
    data = blockchain.receive_data_from_blockchain()
    return {"data": data}

@app.get("/bank_integration/info")
def bank_info(current_user: str = Depends(get_current_user)):
    info = blockchain.simulate_bank_integration()
    return {"bank_info": info}

@app.post("/bank_integration/transfer")
def bank_transfer(account_number: str, amount: float, current_user: str = Depends(get_current_user)):
    success = blockchain.simulate_bank_transfer(account_number, amount)
    return {"message": "Bank transfer simulated successfully." if success else "Bank transfer failed."}

@app.post("/peers/add")
def add_peer(peer: str, current_user: str = Depends(get_current_user)):
    if peer not in blockchain.peer_nodes:
        blockchain.peer_nodes.append(peer)
        audit_log(f"Peer added: {peer}")
    return {"message": "Peer added.", "peers": blockchain.peer_nodes}

@app.get("/peers")
def list_peers(current_user: str = Depends(get_current_user)):
    return {"peers": blockchain.peer_nodes}

@app.post("/receive_block")
def receive_block(block: dict, current_user: str = Depends(get_current_user)):
    last_block = blockchain.chain[-1]
    if block["index"] == last_block.index + 1 and block["previous_hash"] == last_block.hash:
        new_block = Block(
            block["index"],
            block["previous_hash"],
            block["transactions"],
            block["timestamp"],
            block["validator"],
            block.get("nonce", 0)
        )
        new_block.hash = block["hash"]
        new_block.merkle_root = block["merkle_root"]
        blockchain.chain.append(new_block)
        audit_log(f"Block received and added: {new_block.hash}")
        blockchain.save_chain()
        return {"message": "Block added."}
    else:
        return {"message": "Block rejected."}

@app.get("/balance")
def get_balance(user: str, coin: str = "UBITokens", current_user: str = Depends(get_current_user)):
    balance = blockchain.multi_currency_balances.get(user, {}).get(coin, 0)
    return {"balance": balance}

@app.post("/virtual_assistant")
def virtual_assistant_chat(user: str, message: str, current_user: str = Depends(get_current_user)):
    response = virtual_assistant.chat(user, message)
    return {"response": response}

@app.get("/chain")
def get_chain(current_user: str = Depends(get_current_user)):
    chain_data = []
    for block in blockchain.chain:
        chain_data.append({
            "index": block.index,
            "previous_hash": block.previous_hash,
            "hash": block.hash,
            "transactions": block.transactions,
            "timestamp": block.timestamp,
            "validator": block.validator,
            "nonce": block.nonce,
            "merkle_root": block.merkle_root
        })
    return chain_data

@app.post("/transaction")
def create_transaction(sender: str, receiver: str, amount: float, coin: str = "UBITokens", current_user: str = Depends(get_current_user)):
    signature = sign_transaction(sender, receiver, amount, coin)
    blockchain.add_transaction(sender, receiver, amount, coin, signature=signature)
    return {"message": "Transaction added."}

@app.post("/add_block")
def mine_block(current_user: str = Depends(get_current_user)):
    blockchain.add_block("AI_Node")
    return {"message": "Block added."}

@app.post("/distribute_ubi")
def distribute_ubi(current_user: str = Depends(get_current_user)):
    blockchain.distribute_ubi()
    return {"message": "UBI distributed."}

@app.post("/create_coin")
def create_new_coin(coin_name: str, growth_factor: float = 1.01, current_user: str = Depends(get_current_user)):
    blockchain.create_coin(coin_name, growth_factor)
    return {"message": f"Coin {coin_name} created with growth factor {growth_factor}."}

@app.post("/update_governance")
def update_governance(proposal: str, current_user: str = Depends(get_current_user)):
    proposal_id = blockchain.update_governance(proposal)
    return {"message": f"Governance proposal added with ID {proposal_id}."}

@app.post("/vote")
def vote(proposal_id: int, voter: str, vote: bool, current_user: str = Depends(get_current_user)):
    success = blockchain.vote_on_proposal(proposal_id, voter, vote)
    return {"message": "Vote processed." if success else "Nonexistent proposal."}

@app.post("/register_device")
def register_device(device_id: str, metadata: Dict[str, Any], current_user: str = Depends(get_current_user)):
    blockchain.register_device(device_id, metadata)
    return {"message": f"Device {device_id} registered."}

@app.post("/oracle")
def get_oracle_data(current_user: str = Depends(get_current_user)):
    data = blockchain.fetch_oracle_data()
    return {"data": data}

@app.post("/anomaly_detection")
def anomaly_detection(current_user: str = Depends(get_current_user)):
    result = blockchain.anomaly_detection()
    return {"anomaly_detected": result}

@app.post("/electronic_voting")
def electronic_voting(votes: Dict[str, bool], current_user: str = Depends(get_current_user)):
    result = blockchain.electronic_voting(votes)
    return {"message": result}

@app.post("/certify_document")
def certify_document(document: Dict[str, Any], current_user: str = Depends(get_current_user)):
    result = blockchain.certify_document(document)
    return {"certificate": result}

@app.get("/environmental_report")
def environmental_report(current_user: str = Depends(get_current_user)):
    report = blockchain.report_environmental_impact()
    return {"report": report}

@app.post("/experiment_consensus")
def experiment_consensus(current_user: str = Depends(get_current_user)):
    result = blockchain.experiment_new_consensus()
    return {"message": result}

@app.post("/soft_fork")
def soft_fork(new_parameters: Dict[str, Any], current_user: str = Depends(get_current_user)):
    result = blockchain.soft_fork_update(new_parameters)
    return {"message": "Soft fork updated." if result else "Update failed."}

@app.post("/cybersecurity")
def cybersecurity(current_user: str = Depends(get_current_user)):
    result = blockchain.cybersecurity_monitor()
    return {"message": "Cybersecurity monitoring activated." if result else "Error."}

@app.post("/register_social_initiative")
def register_social_initiative(initiative_type: str, description: str, required_funds: float, current_user: str = Depends(get_current_user)):
    initiative_id = blockchain.register_social_initiative(initiative_type, description, required_funds)
    return {"message": f"Social initiative registered with ID {initiative_id}."}

@app.post("/vote_social_initiative")
def vote_social_initiative(initiative_id: int, voter: str, vote: bool, current_user: str = Depends(get_current_user)):
    success = blockchain.vote_social_initiative(initiative_id, voter, vote)
    return {"message": "Vote processed." if success else "Nonexistent initiative."}

@app.post("/execute_social_initiative")
def execute_social_initiative(initiative_id: int, current_user: str = Depends(get_current_user)):
    result = blockchain.execute_social_initiative(initiative_id)
    return {"message": result}

@app.post("/launch_basic_income")
def launch_basic_income(current_user: str = Depends(get_current_user)):
    result = blockchain.launch_basic_income_program()
    return {"message": result}

@app.post("/fund_education")
def fund_education(program_name: str, required_funds: float, current_user: str = Depends(get_current_user)):
    result = blockchain.fund_education_program(program_name, required_funds)
    return {"message": result}

@app.post("/fund_healthcare")
def fund_healthcare(program_name: str, required_funds: float, current_user: str = Depends(get_current_user)):
    result = blockchain.fund_healthcare_program(program_name, required_funds)
    return {"message": result}

@app.get("/social_audit")
def social_audit(current_user: str = Depends(get_current_user)):
    report = blockchain.social_audit()
    return {"audit_report": report}

@app.get("/social_metrics")
def social_metrics(current_user: str = Depends(get_current_user)):
    metrics = blockchain.report_social_metrics()
    return {"social_metrics": metrics}

@app.post("/submit_feedback")
def submit_feedback(user: str, feedback: str, current_user: str = Depends(get_current_user)):
    feedback_id = blockchain.submit_feedback(user, feedback)
    return {"message": f"Feedback received with ID {feedback_id}."}

@app.get("/feedback")
def get_feedback(current_user: str = Depends(get_current_user)):
    feedback_data = blockchain.get_feedback()
    return {"feedback": feedback_data}

if __name__ == "__main__":
    import uvicorn
    # Rularea serverului cu opțiuni de reload pentru dezvoltare; 
    # În producție, se recomandă configurarea unui manager de procese și rate limiting suplimentar.
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
