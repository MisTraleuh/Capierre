from utils.messages import msg_error
from Crypto.Cipher import AES
from hashlib import sha256

class CapierreCipher:
    """
    This class is the cipher module that provides encryption/decryption.
    At its core, it uses AES 256 CBC encryption method (that can be changed).
    """

    def cipher(self, input: bytes, password: bytes, *, decrypt: bool) -> bytes:
        """
        This method encrypt or decrypt the content of the `input` and returns the ciphered message.
        If `decrypt` is True, then the cipher will attempt to decrypt `input`.
        This function can raise 

        @param input: Message input (`bytes`).
        @param password: Password input (`bytes`).
        @param decrypt: Enable decryption mode if `True` (`bool`).

        @return Returns the encrypted/decrypted message.
        """
        password_hash = sha256(password).digest()

        try:
            cipher = AES.new(password_hash, mode="MODE_CBC")

            if decrypt:
                return cipher.decrypt(input)
            return cipher.encrypt(input)
        except Exception as e:
            msg_error(f"Cipher error: {e}")
            raise e
