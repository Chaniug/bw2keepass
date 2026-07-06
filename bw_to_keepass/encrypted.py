"""
Bitwarden 加密导出（密码保护 JSON）解密

算法与 web/index.html 中的 decryptBitwardenEncryptedJson 完全一致，并经
218 条真实数据验证。规格参考 Bitwarden 加密导出文档：
https://bitwarden.com/help/encrypted-export/

流程：
  1. PBKDF2-SHA256(password, UTF-8(salt), iterations) -> 256-bit masterKey
  2. HKDF-Expand（info="enc" / "mac"）           -> encKey / macKey  (stretchKey)
  3. 校验 encKeyValidation_DO_NOT_EDIT（验证导出密码是否正确）
  4. 解密 data：AES-256-CBC + HMAC-SHA256(iv‖ct) 常量时间比较
"""

import base64
import hashlib
import hmac
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class EncryptedExportError(ValueError):
    """Bitwarden 加密导出解密失败（格式无效 / 密码错误 / 数据损坏）"""


class EncryptedExportRequiresPassword(EncryptedExportError):
    """检测到加密导出，但调用方未提供导出密码"""


def _hkdf_expand(prk: bytes, length: int, info: bytes) -> bytes:
    """HKDF-Expand (RFC 5869)，单步展开，info 为上下文字节串"""
    hash_len = 32  # SHA-256
    n = (length + hash_len - 1) // hash_len
    result = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        result += t
    return result[:length]


def _parse_cipher_string(cipher_str: str):
    """解析 Bitwarden 密文串 "encType.ivB64|ctB64|macB64" """
    dot = cipher_str.find('.')
    if dot == -1:
        raise EncryptedExportError("无效的密文格式")
    enc_type = int(cipher_str[:dot])
    parts = cipher_str[dot + 1:].split('|')
    if len(parts) != 3:
        raise EncryptedExportError("无效的密文格式")
    return enc_type, base64.b64decode(parts[0]), base64.b64decode(parts[1]), parts[2]


def _decrypt_cipher_string(cipher_str: str, enc_key: bytes, mac_key: bytes) -> bytes:
    """AES-256-CBC 解密 + HMAC-SHA256 完整性校验，返回明文原始字节"""
    enc_type, iv, ct, mac_b64 = _parse_cipher_string(cipher_str)
    if enc_type != 2:
        # 2 = AesCbc256_HmacSha256_B64，当前 Bitwarden 唯一使用类型
        raise EncryptedExportError(f"不支持的加密类型: {enc_type}")

    # HMAC 完整性验证：对 iv 原始字节拼接 ct 原始字节做 HMAC
    mac_data = iv + ct
    computed = hmac.new(mac_key, mac_data, hashlib.sha256).digest()
    computed_b64 = base64.b64encode(computed).decode('ascii')
    # 常量时间比较，防止时序攻击
    if not hmac.compare_digest(computed_b64, mac_b64):
        raise EncryptedExportError("密码错误或数据已损坏（MAC 验证失败）")

    # AES-256-CBC 解密 + 去除 PKCS7 填充
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise EncryptedExportError("密码错误或数据已损坏（填充无效）")
    return padded[:-pad_len]


def decrypt_bitwarden_export(data: dict, password: str) -> dict:
    """解密 Bitwarden 密码保护导出 JSON，返回明文 JSON dict

    Args:
        data: 加密导出 JSON 解析后的 dict（含 encrypted/passwordProtected/salt/data 等）
        password: 导出时设置的密码
    Returns:
        解密后的明文 JSON dict（含 folders/items 等）
    Raises:
        EncryptedExportError: 格式无效 / 密码错误 / 数据损坏
    """
    if not (data.get('encrypted') and data.get('passwordProtected')
            and data.get('salt') and data.get('data')):
        raise EncryptedExportError("不是有效的 Bitwarden 加密导出格式")

    kdf_iterations = int(data.get('kdfIterations') or 100000)
    # 注意：Bitwarden 的 salt 为 base64 字符串，但 PBKDF2 使用其 UTF-8 文本作为 salt 原始字节
    salt = data['salt'].encode('utf-8')

    master_key = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt, kdf_iterations, dklen=32
    )
    enc_key = _hkdf_expand(master_key, 32, b'enc')
    mac_key = _hkdf_expand(master_key, 32, b'mac')

    # 校验导出密码正确性（旧版导出可能没有此字段，则靠 data 的 MAC 兜底）
    if data.get('encKeyValidation_DO_NOT_EDIT'):
        _decrypt_cipher_string(data['encKeyValidation_DO_NOT_EDIT'], enc_key, mac_key)

    plaintext = _decrypt_cipher_string(data['data'], enc_key, mac_key)
    return json.loads(plaintext.decode('utf-8'))
