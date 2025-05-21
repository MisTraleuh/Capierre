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
    def cipher(inputBytes: bytes, password: str, *, decrypt: bool) -> bytes:
        """
        This method encrypt or decrypt the content of the `inputBytes` and returns the ciphered message.
        If `decrypt` is True, then the cipher will attempt to decrypt `inputBytes`.
        This function can raise

        @param inputBytes: Message inputBytes (`bytes`).
        @param password: Password inputBytes (`bytes`).
        @param decrypt: Enable decryption mode if `True` (`bool`).

        @return Returns the encrypted/decrypted message (encrypted message encoded in base64).
        """
        password_hash = sha256(bytes(password, "utf-8")).digest()

        try:
            cipher = AES.new(password_hash, mode=AES.MODE_CBC)

            if decrypt:
                # https://stackoverflow.com/questions/40729276/base64-incorrect-padding-error-using-python
                value: str = inputBytes.decode()
                if (len(value) % 4) != 0:
                    value += b'=' * (4 - (len(value) % 4))
                print(value)
                inputBytes = b64decode(value)
                output: bytes = cipher.decrypt(inputBytes)[16:] # Remove padding
                return output[:-output[-1] - 1]
            padding: int = 16 - len(inputBytes) % 16
            inputBytes = b'\x00' * 16 + inputBytes + b''.join([i.to_bytes(1, 'big') for i in range(padding)])
            return b64encode(cipher.encrypt(inputBytes))
        except Exception as e:
            msg_error(f"Cipher error: {e}")
            raise e
