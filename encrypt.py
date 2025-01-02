"""提供用于 mirouter 组件的加密功能."""

from binascii import unhexlify
import hashlib
import random
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class Encrypt:
    """类用于加密操作."""

    def __init__(self) -> None:
        """初始化加密所需的 key 和 iv."""
        self.key = "a2ffa5c9be07488bbb04a3a47d3c5f6a"
        self.iv = "64175472480004614961023454661220"
        self.nonce = None

    def init(self):
        """初始化 nonce 值，并返回生成的 nonce."""
        self.nonce = self.nonce_create()
        return self.nonce

    def nonce_create(self):
        """生成并返回一个新的 nonce 值."""
        device_id = "bc:24:11:f5:44:58"  # 替换为实际的设备ID
        ntime = int(time.time())
        random_num = random.randint(0, 9999)
        return f"0_{device_id}_{ntime}_{random_num}"

    def old_pwd(self, pwd):
        """计算旧密码的哈希值."""
        inner_hash = hashlib.sha256((pwd + self.key).encode()).hexdigest()
        return hashlib.sha256((self.nonce + inner_hash).encode()).hexdigest()

    def new_pwd(self, pwd, newpwd):
        """计算新密码的加密值."""
        key = hashlib.sha1((pwd + self.key).encode()).hexdigest()
        password = hashlib.sha1((newpwd + self.key).encode()).hexdigest()
        key = unhexlify(key)[:32]
        iv = unhexlify(self.iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(password.encode(), AES.block_size))
        return ciphertext.hex()

    def new_pwd256(self, pwd, newpwd):
        """计算新密码的 SHA-256 加密值."""
        key = hashlib.sha256((pwd + self.key).encode()).hexdigest()
        password = hashlib.sha256((newpwd + self.key).encode()).hexdigest()
        key = unhexlify(key)[:32]
        iv = unhexlify(self.iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(password.encode(), AES.block_size))
        return ciphertext.hex()
