import uuid
import time
import base64
import rsa

import Crypto.Cipher.AES
import Crypto.Random


def gen_key():
    key = uuid.uuid4().hex.encode()
    return key


def word_complete(x):
    m = len(x) % 32
    if m != 0:
        x += b" " * (32 - m)
    return x


def encrypt_file(key, filename, new_filename):
    x = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)
    with open(filename, 'rb') as read_file:
        with open(new_filename, 'wb') as write_file:
            while True:
                content = read_file.read(1024)
                if content:
                    content = x.encrypt(word_complete(content))
                    write_file.write(content)
                else:
                    break


def decrypt_file(key, filename, new_filename):
    x = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)
    with open(new_filename, 'rb') as read_file:
        with open(filename, 'wb') as write_file:
            while True:
                content = read_file.read(1024)
                if content:
                    content = x.decrypt(content)
                    write_file.write(content)
                else:
                    break


# 使用rsa生成新的文件名，包含ase密钥和源文件名
def gen_new_filename(filename, public_key):
    if len(filename) > 76:
        filename = filename[len(filename) - 76:]
    key = gen_key()
    new_filename = key + b'____' + filename.encode()
    new_filename = base64.b64encode(rsa.encrypt(new_filename, public_key))
    new_filename = new_filename.decode().replace('/', '-')
    return new_filename, key


def get_origin_name(new_filename, private_key):
    bs_name = base64.b64decode(new_filename.replace('-', '/'))
    origin = rsa.decrypt(bs_name, private_key).decode()
    name_list = origin.split('____')
    key = name_list[0]
    name = name_list[1]
    return key, name


def load_key():
    with open('public.pem', 'rb') as f:
        p = f.read()
    public_key = rsa.PublicKey.load_pkcs1(p)
    with open('private.pem', 'rb') as f:
        p = f.read()
    private_key = rsa.PrivateKey.load_pkcs1(p)
    return public_key, private_key


def encrypt(filename, public_key):
    new_filename, ase_key = gen_new_filename(filename, public_key)
    encrypt_file(ase_key, filename, new_filename)
    return new_filename


def decrypt(new_filename, private_key):
    ase_key, filename = get_origin_name(new_filename, private_key)
    decrypt_file(ase_key.encode(), filename, new_filename)


if __name__ == '__main__':
    file_name = '一个很随便的图片.jpg'
    public, private = load_key()

    start = time.time()     # 加密文件
    new_file_name = encrypt(file_name, public)
    print('encrypt time:', time.time() - start)

    start = time.time()     # 解密文件
    decrypt(new_file_name, private)
    print('decrypt time:', time.time() - start)

