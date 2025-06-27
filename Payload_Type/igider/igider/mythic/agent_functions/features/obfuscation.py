import base64
import hashlib
import os
import random
import string
from itertools import cycle

def generate_random_identifier(length: int = 8) -> str:
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def basic_obfuscate(code: str) -> str:
    key = hashlib.md5(os.urandom(128)).hexdigest().encode()
    encrypted_content = ''.join(chr(c ^ k) for c, k in zip(code.encode(), cycle(key))).encode()
    b64_enc_content = base64.b64encode(encrypted_content)

    var_b64 = generate_random_identifier()
    var_key = generate_random_identifier()
    var_iter = generate_random_identifier()

    return f"""import base64, itertools
{var_b64} = {b64_enc_content}
{var_key} = {key}
{var_iter} = itertools.cycle({var_key})
exec(''.join(chr(c ^ k) for c, k in zip(base64.b64decode({var_b64}), {var_iter})).encode())
"""

def advanced_obfuscate(code: str) -> str:
    key1 = hashlib.md5(os.urandom(64)).hexdigest().encode()
    layer1 = ''.join(chr(c ^ k) for c, k in zip(code.encode(), cycle(key1)))
    rotation = random.randint(1, 255)
    layer2 = ''.join(chr((ord(c) + rotation) % 256) for c in layer1)
    encoded = base64.b64encode(layer2.encode())

    var_data = generate_random_identifier()
    var_key = generate_random_identifier()
    var_rot = generate_random_identifier()
    var_result = generate_random_identifier()
    var_char = generate_random_identifier()
    var_k = generate_random_identifier()
    var_c = generate_random_identifier()

    return f"""
import base64, itertools
{var_data} = {encoded}
{var_key} = {key1}
{var_rot} = {rotation}
{var_result} = ''
for {var_c}, {var_k} in zip(
    ''.join(chr((ord({var_char}) - {var_rot}) % 256) for {var_char} in base64.b64decode({var_data}).decode()),
    itertools.cycle({var_key})
):
    {var_result} += chr(ord({var_c}) ^ {var_k})
exec({var_result})
"""