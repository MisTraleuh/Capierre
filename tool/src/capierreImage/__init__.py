import random
import struct
from PIL import Image
from capierreParsing import msg_error
from itertools import chain
from math import ceil


class CapierreImage:
    """
    This class is responsible for hiding content within images.

    It uses the LSB (Least Significan Bit) method using a custom implementation
    with as pseudo-random generator for frequency detection (using builtin
    `random()` function).

    @param image: `PIL.Image.Image` - The image to hide or extract the message.
    @param seed: `int` - The seed to be used for encryption and decryption.
    (default: `0`)
    """

    HEADER_FORMAT = '>I'
    HEADER_SIZE = 4
    BYTE_SIZE = 8

    def __init__(self, image: Image.Image, seed=0):
        self.image = image
        self.seed = seed
        self.image_size = self.image.width + self.image.height
        self.nb_channels = len(self.image.mode)
        self.image_data = list(map(list, self.image.getdata()))

    def __del__(self):
        self.image.close()

    def check_size(self) -> bool:
        if len(self.image_data) < self.image.size[0] + self.image.size[1]:
            msg_error(
                "[!][CapierreImage] data must be smaller than the image file."
            )
            return False
        return True

    def set_bit(self, value: int, position: int) -> int:
        return (value | 1 << position) % 256

    def clear_bit(self, value: int, position: int) -> int:
        return (value & ~(1 << position)) % 256

    def get_new_position(self):
        random_stack: list[int] = []

        random.seed(self.seed)
        for _ in range(self.image_size):
            value = random.randint(self.HEADER_SIZE, self.image_size)

            while value in random_stack:
                value = random.randint(self.HEADER_SIZE, self.image_size)

            random_stack.append(value)
            yield value

    def hide(self, message: bytes):
        if not (self.check_size() and self.image_data is not None):
            return

        bit_pos = 0
        message_length = len(message)
        message_length_encoded = struct.pack(
            self.HEADER_FORMAT,
            message_length
        )
        random_position = self.get_new_position()

        for i in range(self.HEADER_SIZE):
            self.image_data[i // self.nb_channels][i % self.nb_channels] = (
                message_length_encoded[i]
            )
        for i in range(message_length * self.BYTE_SIZE):
            position = next(random_position)

            if message[i // self.BYTE_SIZE] & (1 << bit_pos):
                self.image_data[position][i % self.nb_channels] = self.set_bit(
                    self.image_data[position][i % self.nb_channels],
                    0
                )
            else:
                self.image_data[position][i % self.nb_channels] = self.clear_bit(
                    self.image_data[position][i % self.nb_channels],
                    0
                )
            print(f'i : {i}')
            bit_pos = (bit_pos + 1) % self.BYTE_SIZE
        self.image.putdata(list(map(tuple, self.image_data)))

    def extract(self) -> bytes:
        bit_pos = 0
        random_position = self.get_new_position()
        message_length_decoded: int = struct.unpack(
            self.HEADER_FORMAT,
            bytes((self.image_data[i // self.nb_channels][i % self.nb_channels] for i in range(self.HEADER_SIZE)))
        )[0]
        message = bytearray(message_length_decoded)

        for i in range(message_length_decoded * self.BYTE_SIZE):
            position = next(random_position)

            if self.image_data[position][i % self.nb_channels] & 1:
                message[i // self.BYTE_SIZE] = self.set_bit(
                    message[i // self.BYTE_SIZE],
                    bit_pos
                )
            print(f'{message[i // self.BYTE_SIZE]:08b}')
            bit_pos = (bit_pos + 1) % 8
        return bytes(message)
