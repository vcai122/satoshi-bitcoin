import datetime
from typing import List
import uuid
from asymmetric_key_cryptography import generate_keys, sign_message, verify_signature, RSAPrivateKey, RSAPublicKey
from random import randint, sample, choice
import threading
from copy import deepcopy

TransactionsDict = dict[uuid.UUID, "Transaction"]


class Coin:
    def __init__(self, owner: RSAPublicKey, amount: int):
        self.owner = owner
        self.amount = amount
        self.exists = True
    
    def spend(self):
        self.exists = False
    
    def __hash__(self):
        return hash((self.owner, self.amount))
    


class CoinReference:
    def __init__(self, transaction_id: uuid.UUID, output_index: int):
        self.transaction_id = transaction_id
        self.output_index = output_index

    def get_coin(self, transactions: TransactionsDict):
        return transactions[self.transaction_id].output[self.output_index]
    
    def __hash__(self):
        return hash((self.transaction_id, self.output_index))

class Transaction:
    def __init__(self, private_key: RSAPrivateKey, input: List[CoinReference], output: List[Coin]):
        self.input = input
        self.output = output
        self.transaction_id = uuid.uuid4()
        self.signature = sign_message(private_key, self.transaction_id)
    
    def validate(self, transactions: TransactionsDict):
        input_coins = [coin_ref.get_coin(transactions) for coin_ref in self.input]
        if sum([coin.amount for coin in input_coins]) != sum([coin.amount for coin in self.output]):
            return False
        if not all([verify_signature(coin.owner, self.transaction_id, self.signature) for coin in input_coins]):
            return False
        if not all([coin.exists for coin in input_coins]):
            return False

        return True
    
    def __hash__(self):
        return hash((self.input, self.output))
    

class BlockHeader:
    def __init__(self, prev_hash, timestamp, merkle_root_hash):
        self.prev_hash = prev_hash
        self.timestamp = timestamp
        self.nonce = 0
        self.merkle_root_hash = merkle_root_hash
    
    def try_nonce(self, nonce):
        self.nonce = nonce
        return hash(self)
    
    def __hash__(self):
        return hash((self.prev_hash, self.timestamp, self.nonce, self.merkle_root_hash))
        
class Block:
    def __init__(self, transactions: List[Transaction], block_header: BlockHeader):
        self.transactions = transactions
        self.block_header = block_header

class MerkleTree:
    def __init__(self, transactions: List[Transaction]):
        self.root_hash = self.build_tree(transactions)
        
    def build_tree(self, transactions: List[Transaction]):
        if (len(transactions) == 0):
            return 0
        if (len(transactions) == 1):
            return hash(transactions[0])
        else:
            split_idx = len(transactions) // 2
            first_half, second_half = transactions[:split_idx], transactions[split_idx:]
            return hash(self.build_tree(first_half), self.build_tree(second_half))
        


class Miner: 
    TWO_TO_THE_THIRTY_TWO = 2**32
    TRANSACTIONS_PER_BLOCK = 4
    
    @staticmethod
    def generate_nonce():
        return randint(0, Miner.TWO_TO_THE_THIRTY_TWO)
    
    @staticmethod
    def check_proof_of_work(hash):
        return hash % 256 == 0

    def __init__(self):
        self.transactions: TransactionsDict = {}
        self.prev_hash = 0
        self.lock = threading.Lock()
        self.active_transactions: TransactionsDict = {}

        self.recieved_new_block = True

    def recieve_transaction(self, transactions: List[Transaction]):
        with self.lock:
            if not all([transaction.validate(self.transactions) for transaction in transactions]):
                return
            self.active_transactions.update({transaction.transaction_id: transaction for transaction in transactions})

    def recieve_block(self, block: Block):
        with self.lock:
            if block.block_header.prev_hash != self.prev_hash:
                return
            if not self.check_proof_of_work(hash(block.block_header)):
                return
            if not all([transaction.validate(self.transactions) for transaction in block.transactions]):
                return
            self.transactions.update({transaction.transaction_id: transaction for transaction in block.transactions})
            self.prev_hash = hash(block)
            self.recieved_new_block = True
            for transaction in block.transactions:
                self.active_transactions.pop(transaction.transaction_id, None)
            
            for transaction in block.transactions:
                for coin_ref in transaction.input:
                    coin_ref.get_coin(self.transactions).spend()

    def broadcast_block(self, block, miners):
        for miner in miners:
            miner.recieve_block(deepcopy(block))
    
    def run(self, miners):
        def mine(transactions):
            header = BlockHeader(self.prev_hash, datetime.datetime.now(), 0, MerkleTree(transactions).root_hash)
            while not self.check_proof_of_work(header.try_nonce(self.generate_nonce())):
                if self.recieved_new_block:
                    return
            block = Block(transactions, header)
            self.broadcast_block(block, miners)
        
        while True:
            sample_transactions = sample(self.active_transactions.values(), Miner.TRANSACTIONS_PER_BLOCK)
            mine(sample_transactions)
    
    def get_transactions(self):
        with self.lock:
            return self.transactions
    
class User:
    def __init__(self, miners: List[Miner]):
        self.private_key, self.public_key = generate_keys()
        self.coins: List[CoinReference] = []
        self.miners = miners
    
    def get_public_key(self):
        return self.public_key
    
    def gather_coins(self, amount):
        coins: List[CoinReference] = []
        sum = 0
        for coin in self.coins:
            coins.append(coin)
            sum += coin.get_coin().amount
            if sum >= amount:
                break
        if sum < amount:
            raise Exception("Not enough coins")
        return coins, sum
    
    def send_money(self, other: "User", amount: int):
        coins, sum = self.gather_coins(amount)
        output_coins = [Coin(other.get_public_key(), amount), Coin(self.public_key, sum - amount)]
        transaction = Transaction(self.private_key, coins, output_coins)
        for miner in self.miners:
            miner.recieve_transaction([deepcopy(transaction)])
    
    def poll_coins(self):
        self.coins = []
        transactions = choice(self.miners).get_transactions()
        for transaction in transactions.values():
            for i, coin in enumerate(transaction.output):
                if coin.owner == self.public_key:
                    self.coins.append(CoinReference(transaction.transaction_id, i))
