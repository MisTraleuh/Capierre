from utils.messages import msg_error
from Crypto.Cipher import AES
from hashlib import sha256
from base64 import b64encode, b64decode


class CapierreCipher:
    """
    This class is the cipher module that provides encryption/decryption.
    At its core, it uses AES 256 CBC encryption method (that can be changed).
    """

    @staticmethod
    def cipher(input: bytes, password: str, *, decrypt: bool) -> str:
        """
        This method encrypt or decrypt the content of the `input` and returns the ciphered message.
        If `decrypt` is True, then the cipher will attempt to decrypt `input`.
        This function can raise

        @param input: Message input (`bytes`).
        @param password: Password input (`bytes`).
        @param decrypt: Enable decryption mode if `True` (`bool`).

        @return Returns the encrypted/decrypted message (encrypted message encoded in base64).
        """
        password_hash = sha256(bytes(password, "utf-8")).digest()

        try:
            cipher = AES.new(password_hash, mode=AES.MODE_CBC)

            if decrypt:
                output: bytes = cipher.decrypt(b64decode(input))[16:]
                return str(output[:-output[-1] - 1], "utf-8")
            padding: int = 16 - len(input) % 16
            input = b'\x00' * 16 + input + b''.join([i.to_bytes(1, 'big') for i in range(padding)])
            return str(b64encode(cipher.encrypt(input)), 'ascii')
        except Exception as e:
            msg_error(f"Cipher error: {e}")
            raise e
