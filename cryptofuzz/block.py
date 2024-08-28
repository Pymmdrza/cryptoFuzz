# cryptofuzz : Local Block File Reader (bitcoin core sync data)
import struct
import hashlib


class tools:
    def __init__(self):
        pass

    def extract_address_from_script_sig(self, script_sig):
        if len(script_sig) >= 33:
            pubkey = script_sig[-33:] if script_sig[-33] in (0x02, 0x03) else script_sig[-65:]
            if len(pubkey) in (33, 65):
                pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey).digest()).digest()
                return self.hash160_to_p2pkh_address(pubkey_hash.hex())
        return None

    def extract_address(self, script):
        if len(script) == 25 and script[0] == 0x76 and script[1] == 0xa9 and script[-2] == 0x88 and script[-1] == 0xac:
            pubkey_hash = script[3:-2]
            return self.hash160_to_p2pkh_address(pubkey_hash.hex())

        elif len(script) == 23 and script[0] == 0xa9 and script[-1] == 0x87:
            script_hash = script[2:-1]
            return self.hash160_to_p2sh_address(script_hash.hex())

        elif len(script) >= 22 and script[0] == 0x00 and (script[1] == 0x14 or script[1] == 0x20):
            witness_hash = script[2:]
            return self.hash_to_bech32(witness_hash, len(witness_hash) == 20)

        return None

    def hash160_to_p2pkh_address(self, hash160):
        prefix = b'\x00'
        return self.base58_encode_with_checksum(prefix + bytes.fromhex(hash160))

    def hash160_to_p2sh_address(self, hash160):
        prefix = b'\x05'
        return self.base58_encode_with_checksum(prefix + bytes.fromhex(hash160))

    def base58_encode_with_checksum(self, data):
        checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
        return self.base58_encode(data + checksum)

    def base58_encode(self, data):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        num = int.from_bytes(data, 'big')
        encoded = ''
        while num > 0:
            num, rem = divmod(num, 58)
            encoded = alphabet[rem] + encoded
        for byte in data:
            if byte == 0:
                encoded = '1' + encoded
            else:
                break
        return encoded

    def hash_to_bech32(self, hash_data, is_p2wpkh):
        version = 0 if is_p2wpkh else 0
        return self.bech32_encode("bc", self.convertbits([version] + list(hash_data), 8, 5))

    def bech32_polymod(self, values):
        gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            b = (chk >> 25)
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                if (b >> i) & 1:
                    chk ^= gen[i]
        return chk

    def bech32_hrp_expand(self, hrp):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    def bech32_verify_checksum(self, hrp, data):
        return self.bech32_polymod(self.bech32_hrp_expand(hrp) + data) == 1

    def bech32_create_checksum(self, hrp, data):
        values = self.bech32_hrp_expand(hrp) + data
        polymod = self.bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

    def bech32_encode(self, hrp, data):
        combined = data + self.bech32_create_checksum(hrp, data)
        return hrp + '1' + ''.join(['qpzry9x8gf2tvdw0s3jn54khce6mua7l'[(x)] for x in combined])

    def convertbits(self, data, frombits, tobits, pad=True):
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        for value in data:
            if value < 0 or value >> frombits:
                return None
            acc = (acc << frombits) | value
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        return ret


class txs:
    def __init__(self):
        self.tools = tools()

    def read_varint(self, data):
        prefix = data[0]
        if prefix < 0xfd:
            return prefix, 1
        elif prefix == 0xfd:
            return struct.unpack('<H', data[1:3])[0], 3
        elif prefix == 0xfe:
            return struct.unpack('<I', data[1:5])[0], 5
        elif prefix == 0xff:
            return struct.unpack('<Q', data[1:9])[0], 9

    def parse_transaction(self, data):
        tx_data = {}
        tx_start = 0

        tx_data['version'] = struct.unpack('<I', data[tx_start:tx_start + 4])[0]
        tx_start += 4

        tx_in_count, varint_size = self.read_varint(data[tx_start:])
        tx_start += varint_size

        input_addresses = []
        for _ in range(tx_in_count):
            prev_txid = data[tx_start:tx_start + 32][::-1].hex()
            vout = struct.unpack('<I', data[tx_start + 32:tx_start + 36])[0]
            tx_start += 36

            script_length, varint_size = self.read_varint(data[tx_start:])
            tx_start += varint_size

            script_sig = data[tx_start:tx_start + script_length]
            tx_start += script_length

            address = self.tools.extract_address_from_script_sig(script_sig)
            if address:
                input_addresses.append(address)
            else:
                input_addresses.append(f"Could not parse address from scriptSig (txid: {prev_txid}, vout: {vout})")

            tx_start += 4

        tx_out_count, varint_size = self.read_varint(data[tx_start:])
        tx_start += varint_size

        output_addresses = []
        for _ in range(tx_out_count):
            tx_start += 8

            script_length, varint_size = self.read_varint(data[tx_start:])
            tx_start += varint_size

            script_pubkey = data[tx_start:tx_start + script_length]
            address = self.tools.extract_address(script_pubkey)
            if address:
                output_addresses.append(address)
            tx_start += script_length

        tx_data['locktime'] = struct.unpack('<I', data[tx_start:tx_start + 4])[0]
        tx_start += 4

        tx_data['txid'] = hashlib.sha256(hashlib.sha256(data[:tx_start]).digest()).digest()[::-1].hex()
        tx_data['input_addresses'] = input_addresses
        tx_data['output_addresses'] = output_addresses

        return tx_data, tx_start


def reader(file_path) -> list | dict:
    """
    Read a block from Block File for bitcoin core .
    @param file_path:
    @return:
    """
    _tools = tools()
    _txs = txs()
    block_info = []
    with open(file_path, 'rb') as f:
        while True:
            magic = f.read(4)
            if len(magic) < 4:
                break

            if magic != b'\xf9\xbe\xb4\xd9':  # Bitcoin's magic number
                print("Magic number invalid.")
                break

            block_size = struct.unpack('<I', f.read(4))[0]
            block_data = f.read(block_size)
            if len(block_data) < block_size:
                print("Incomplete block.")
                break

            block_header = block_data[:80]
            version, prev_hash, merkle_root, timestamp, bits, nonce = struct.unpack('<L32s32sLLL', block_header)
            block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()[::-1].hex()
            tx_count, varint_size = _txs.read_varint(block_data[80:])
            tx_offset = 80 + varint_size

            block_info.append({
                'block_hash': block_hash,
                'tx_count': tx_count,
                'transactions': []
            })

            transactions = []
            for _ in range(tx_count):
                tx_data, tx_size = _txs.parse_transaction(block_data[tx_offset:])
                transactions.append(tx_data)
                tx_offset += tx_size

            block_info[-1]['transactions'] = transactions

    return block_info
