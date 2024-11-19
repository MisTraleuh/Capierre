from utils.messages import msg_error
from Crypto.Cipher import AES

class CapierreCipher:
    """
    This class is the cypher module that provides encryption/decryption.
    At its core, it uses AES 256 CBC encryption method (that can be changed).
    """

    # TODO: Used for performance, attributes must be added here before declaration.
    __slots__ = (
        "input",
        "output"
    )

    def __init__(self, input: bytes) -> None:
        """
        The constructor accepts one argument: `input` (`bytes`).
        In order to perform encryption or decryption, you need to call the `cipher` method of the object.

        @param input: The input bytes to be ciphered (`bytes`).
        """
        self.input: bytes = input
        self.output: bytes = b''

    def cipher(self, password: bytes, *, decrypt: bool) -> bool:
        """
        This method encrypt or decrypt the content of the `input` attribute and store the result in the `output` attribute.
        If `decrypt` is True, then the cipher will attempt to decrypt `input`.
        The `password` must be a sequence of bytes and will need to be 32 bytes long, filled with zero's otherwise.

        @param password: Password input (`bytes`).
        @param decrypt: Enable decryption mode if `True` (`bool`).

        @return Returns `True` if successful, `False` otherwire (with error messages printed out) (`bool`).
        """
        password_length = len(password)

        if password_length != 32:
            password += b'\0' * (32 - password_length)
        try:
            cipher = AES.new(password, mode="MODE_CBC")
            if decrypt:
                self.output = cipher.decrypt(self.input)
            else:
                self.output = cipher.encrypt(self.input)
        except Exception as e:
            msg_error(f"Cipher error: {e}")
            return False
        return True
