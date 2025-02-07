import random
import struct
from PIL import Image
from capierreParsing import msg_error
from itertools import chain
from math import ceil


class CapierreImage:
    """
    This class is responsible for hiding content within images.

    It uses the LSB (Least Significan Bit) method using a custom implementation with as pseudo-random generator for frequency detection (using builtin `random()` function).

    @param image: `PIL.Image.Image` - The image to hide or extract the message.
    @param seed: `int` - The seed to be used for encryption and decryption. (default: `0`)
    """

    HEADER_FORMAT = '>I'

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
            msg_error("[!][CapierreImage] data must be smaller than the image file.")
            return False
        return True

    def get_new_position(self):
        random_stack: list[int] = []

        random.seed(self.seed)
        for _ in range(self.image_size):
            value = random.randint(4, self.image_size)

            while value in random_stack:
                value = random.randint(4, self.image_size)

            random_stack.append(value)
            print(f'[*] Random stack: {random_stack}')
            yield value

    def hide(self, message: bytes):
        if not (self.check_size() and self.image_data is not None):
            return

        bit_pos = 0
        message_length = len(message)
        message_length_offset = message_length // self.nb_channels
        message_length_encoded = struct.pack(self.HEADER_FORMAT, message_length)
        random_position = self.get_new_position()

        for i in range(4):
            self.image_data[i // self.nb_channels][i % self.nb_channels] = message_length_encoded[i]
        for i in range(4 // self.nb_channels, message_length_offset):
            position = next(random_position)

            for j in range(self.nb_channels):
                if message[i * message_length_offset + j] & (1 << bit_pos):
                    self.image_data[position][j] |=  1
                else:
                    self.image_data[position][j] &=  0
                bit_pos = (bit_pos + 1) % 8
        self.image.putdata(list(map(tuple, self.image_data)))

    def extract(self) -> bytes:
        bit_pos = 0
        random_position = self.get_new_position()
        message_length_decoded: int = struct.unpack(
            self.HEADER_FORMAT,
            bytes(chain(*self.image_data[:ceil(4 / self.nb_channels)]))
        )[0]
        message_length_offset = message_length_decoded // self.nb_channels
        message = bytearray(message_length_decoded)

        for i in range(4 // self.nb_channels, message_length_offset):
            position = next(random_position)

            for j in range(self.nb_channels):
                message[(i * message_length_offset + j) // 8] |= (
                    (self.image_data[position][j] & 1) << bit_pos
                )
                bit_pos = (bit_pos + 1) % 8

        return bytes(message)
