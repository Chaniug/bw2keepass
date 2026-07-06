"""
Bitwarden 加密导出（密码保护 JSON）解密

算法与 web/index.html 中的 decryptBitwardenEncryptedJson 完全一致。规格参考
Bitwarden 加密导出文档：https://bitwarden.com/help/encrypted-export/

Bitwarden 导出里的 salt 字段是 Base64 字符串。官方 bitwarden_crypto 采用 Base64
解码得到原始字节参与 KDF（与 C# Convert.FromBase64String 一致）；个别旧路径曾使用
UTF-8 文本。本模块两种都尝试，并以 encKeyValidation / data 的 MAC 校验为准选择正确者。

流程：
  1. 按账户 KDF 派生主密钥
       - PBKDF2-SHA256(password, salt, iterations)          -> 256-bit masterKey
       - Argon2id(password, salt, t, m, p)                  -> 256-bit masterKey
  2. HKDF-Expand（info="enc" / "mac"）           -> encKey / macKey  (stretchKey)
  3. 校验 encKeyValidation_DO_NOT_EDIT（验证导出密码是否正确）
  4. 解密 data：AES-CBC + HMAC-SHA256(iv‖ct) 常量时间比较
     支持 Bitwarden 全部加密类型：encType 0(AesCbc256 无 MAC) /
     1(AesCbc128+HMAC) / 2(AesCbc256+HMAC，默认)
"""

import base64
import hashlib
import hmac
import json
import secrets

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
    """解析 Bitwarden 密文串 "encType.ivB64|ctB64|macB64"

    旧式 encType=0（AesCbc256 无 MAC）格式为 "0.ivB64|ctB64"（仅 2 段）。
    """
    dot = cipher_str.find('.')
    if dot == -1:
        raise EncryptedExportError("无效的密文格式")
    enc_type = int(cipher_str[:dot])
    parts = cipher_str[dot + 1:].split('|')
    if len(parts) not in (2, 3):
        raise EncryptedExportError("无效的密文格式")
    mac_b64 = parts[2] if len(parts) == 3 else ''
    return enc_type, base64.b64decode(parts[0]), base64.b64decode(parts[1]), mac_b64


def _decrypt_cipher_string(cipher_str: str, enc_key: bytes, mac_key: bytes) -> bytes:
    """AES-CBC 解密 + HMAC-SHA256 完整性校验，返回明文原始字节

    Bitwarden 加密类型（core/Enums::EncryptionType）:
      0 = AesCbc256 (无 MAC，旧式)        -> 256 位密钥，跳过 MAC
      1 = AesCbc128_HmacSha256_B64        -> 128 位密钥 + HMAC
      2 = AesCbc256_HmacSha256_B64 (默认) -> 256 位密钥 + HMAC
    """
    enc_type, iv, ct, mac_b64 = _parse_cipher_string(cipher_str)
    if enc_type == 2:
        key_len, need_mac = 32, True
    elif enc_type == 1:
        key_len, need_mac = 16, True
    elif enc_type == 0:
        key_len, need_mac = 32, False
    else:
        raise EncryptedExportError(f"不支持的加密类型: {enc_type}")

    # HMAC 完整性验证（encType 0 为旧式无 MAC，跳过）
    if need_mac:
        mac_data = iv + ct
        computed = hmac.new(mac_key, mac_data, hashlib.sha256).digest()
        computed_b64 = base64.b64encode(computed).decode('ascii')
        # 常量时间比较，防止时序攻击
        if not hmac.compare_digest(computed_b64, mac_b64):
            raise EncryptedExportError("密码错误或数据已损坏（MAC 验证失败）")

    # AES-CBC 解密 + 去除 PKCS7 填充
    # encType 1 用 encKey 前 16 字节作为 128 位密钥，其余用 32 字节 256 位密钥
    cipher = Cipher(algorithms.AES(enc_key[:key_len]), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise EncryptedExportError("密码错误或数据已损坏（填充无效）")
    return padded[:-pad_len]


def _derive_master_key(kdf_type: int, password: str, salt: bytes,
                       kdf_iterations: int, kdf_memory: int, kdf_parallelism: int) -> bytes:
    """按 KDF 类型派生主密钥。Argon2 的 memory 单位在不同来源表述不一（MiB vs KiB），
    由调用方在循环中尝试两种候选值。"""
    if kdf_type == 0:
        # PBKDF2-SHA256
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, kdf_iterations, dklen=32)
    if kdf_type == 1:
        # Argon2id
        try:
            from argon2.low_level import hash_secret_raw, Type
        except ImportError as e:  # pragma: no cover - 依赖缺失提示
            raise EncryptedExportError(
                "解密 Argon2 加密导出需要 argon2-cffi，请执行 `pip install argon2-cffi`"
            ) from e
        return hash_secret_raw(
            password.encode('utf-8'), salt,
            time_cost=kdf_iterations, memory_cost=kdf_memory,
            parallelism=kdf_parallelism, hash_len=32, type=Type.ID, version=19,
        )
    raise EncryptedExportError(
        f"不支持的 KDF 类型: {kdf_type}（当前仅支持 PBKDF2 与 Argon2id）"
    )


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

    kdf_type = int(data.get('kdfType') or 0)
    kdf_iterations = int(data.get('kdfIterations') or 100000)
    kdf_memory = int(data.get('kdfMemory') or 64)        # Bitwarden 以 MiB 存储
    kdf_parallelism = int(data.get('kdfParallelism') or 4)

    # salt 候选：官方 Base64 解码优先，UTF-8 文本兜底
    salt_candidates = [
        base64.b64decode(data['salt']),
        data['salt'].encode('utf-8'),
    ]
    # Argon2 memory 候选：MiB->KiB（×1024）优先，原始值兜底
    argon_memory_candidates = [kdf_memory * 1024, kdf_memory]

    last_err = None
    fatal_err = None  # 结构性错误（不支持的加密/KDF 类型），换 salt/memory 候选无意义
    for salt in salt_candidates:
        try:
            if kdf_type == 1:
                master_key = None
                for mem in argon_memory_candidates:
                    try:
                        master_key = _derive_master_key(
                            1, password, salt, kdf_iterations, mem, kdf_parallelism
                        )
                        break
                    except EncryptedExportError:
                        # 单次 Argon2 派生失败（如内存参数非法），尝试下一个 memory 候选
                        continue
                if master_key is None:
                    raise EncryptedExportError("Argon2 派生失败")
            else:
                master_key = _derive_master_key(
                    0, password, salt, kdf_iterations, kdf_memory, kdf_parallelism
                )

            enc_key = _hkdf_expand(master_key, 32, b'enc')
            mac_key = _hkdf_expand(master_key, 32, b'mac')

            # 校验导出密码正确性（旧版导出可能没有此字段，则靠 data 的 MAC 兜底）
            if data.get('encKeyValidation_DO_NOT_EDIT'):
                _decrypt_cipher_string(data['encKeyValidation_DO_NOT_EDIT'], enc_key, mac_key)
            else:
                _decrypt_cipher_string(data['data'], enc_key, mac_key)

            plaintext = _decrypt_cipher_string(data['data'], enc_key, mac_key)
            return json.loads(plaintext.decode('utf-8'))
        except EncryptedExportError as e:
            # 结构性错误（不支持的加密/KDF 类型）换 salt/memory 候选无意义，直接透传
            if str(e).startswith('不支持'):
                last_err = e
                fatal_err = e
                break
            # 该 salt/参数组合不通过 MAC 校验，尝试下一种候选
            last_err = e

    if fatal_err is not None:
        raise fatal_err  # 透传真实的结构性错误（避免被伪装成 MAC 失败）

    # 所有候选组合均失败
    raise EncryptedExportError("密码错误或数据已损坏（MAC 验证失败）")


# ============================================================================
# 加密（KDBX 等明文 -> Bitwarden 密码保护加密导出 JSON）
# 与 decrypt_bitwarden_export 完全对称，遵循 Bitwarden 加密导出规范。
# ============================================================================

_BLOCK = 16  # AES 块大小


def _pkcs7_pad(data: bytes, block: int = _BLOCK) -> bytes:
    """PKCS7 填充"""
    pad_len = block - (len(data) % block)
    return data + bytes([pad_len]) * pad_len


def _encrypt_cipher_string(plaintext: bytes, enc_key: bytes, mac_key: bytes,
                           enc_type: int = 2) -> str:
    """AES-CBC 加密 + HMAC-SHA256，返回 Bitwarden 密文串 "encType.ivB64|ctB64|macB64"

    encType: 2 = AesCbc256_HmacSha256（256 位密钥 + MAC，默认）
    """
    if enc_type == 2:
        key_len, need_mac = 32, True
    elif enc_type == 1:
        key_len, need_mac = 16, True
    elif enc_type == 0:
        key_len, need_mac = 32, False
    else:
        raise EncryptedExportError(f"不支持的加密类型: {enc_type}")

    iv = secrets.token_bytes(_BLOCK)
    cipher = Cipher(algorithms.AES(enc_key[:key_len]), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(_pkcs7_pad(plaintext)) + encryptor.finalize()

    if need_mac:
        mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
        mac_b64 = base64.b64encode(mac).decode('ascii')
    else:
        mac_b64 = ''

    return f"{enc_type}.{base64.b64encode(iv).decode('ascii')}|{base64.b64encode(ct).decode('ascii')}|{mac_b64}"


def encrypt_bitwarden_export(
    plaintext: dict,
    password: str,
    *,
    kdf_type: int = 0,
    kdf_iterations: int = 600000,
    kdf_memory: int = 64,          # MiB（仅 Argon2 使用）
    kdf_parallelism: int = 4,      # 仅 Argon2 使用
    salt_mode: str = 'utf8',       # 'utf8' = 用 salt 字符串的 UTF-8 字节做 KDF（对齐真实导出）；
                                   # 'base64' = 用 salt 的 base64 解码字节（Bitwarden 文档标准）
    validation_plaintext: str = 'Bitwarden',
) -> dict:
    """将明文 Bitwarden 导出（含 folders/items 的 dict）加密为密码保护导出信封

    Args:
        plaintext: 明文 Bitwarden 导出 dict（会被 json 序列化后整体加密进 data 字段）
        password: 加密（导出）密码
        kdf_type: 0=PBKDF2-SHA256, 1=Argon2id
        kdf_iterations: KDF 迭代次数（PBKDF2）或时间成本（Argon2）
        kdf_memory: Argon2 内存成本（MiB）
        kdf_parallelism: Argon2 并行度
        salt_mode: 'utf8' 或 'base64'，见上
        validation_plaintext: encKeyValidation_DO_NOT_EDIT 的明文（默认 "Bitwarden"）

    Returns:
        Bitwarden 密码保护加密导出 JSON dict，可直接 json.dump 落盘，可被 Bitwarden
        或本工具 decrypt_bitwarden_export 解密。
    """
    if kdf_type not in (0, 1):
        raise EncryptedExportError(f"不支持的 KDF 类型: {kdf_type}")

    # 生成随机 salt（16 字节），以 base64 字符串形式存储
    salt_bytes = secrets.token_bytes(_BLOCK)
    salt_field = base64.b64encode(salt_bytes).decode('ascii')
    if salt_mode == 'utf8':
        kdf_salt = salt_field.encode('utf-8')
    elif salt_mode == 'base64':
        kdf_salt = base64.b64decode(salt_field)
    else:
        raise EncryptedExportError(f"不支持的 salt_mode: {salt_mode}")

    # KDF 派生主密钥
    master_key = _derive_master_key(
        kdf_type, password, kdf_salt, kdf_iterations, kdf_memory * 1024, kdf_parallelism
    )

    # HKDF-Expand 拉伸出 encKey / macKey
    enc_key = _hkdf_expand(master_key, 32, b'enc')
    mac_key = _hkdf_expand(master_key, 32, b'mac')

    # data 字段：整个明文导出 JSON 加密
    data_plain = json.dumps(plaintext, ensure_ascii=False).encode('utf-8')
    data_cs = _encrypt_cipher_string(data_plain, enc_key, mac_key, enc_type=2)

    # encKeyValidation_DO_NOT_EDIT：校验明文加密（用于导入时验证密码）
    val_cs = _encrypt_cipher_string(
        validation_plaintext.encode('utf-8'), enc_key, mac_key, enc_type=2
    )

    envelope = {
        'encrypted': True,
        'passwordProtected': True,
        'salt': salt_field,
        'kdfType': kdf_type,
        'kdfIterations': kdf_iterations,
        'encKeyValidation_DO_NOT_EDIT': val_cs,
        'data': data_cs,
    }
    # PBKDF2 不填 memory/parallelism（与真实导出一致）；Argon2 填实际值
    if kdf_type == 1:
        envelope['kdfMemory'] = kdf_memory
        envelope['kdfParallelism'] = kdf_parallelism
    else:
        envelope['kdfMemory'] = None
        envelope['kdfParallelism'] = None

    return envelope
