from PIL import Image
from dataclasses import dataclass
from capierreParsing import msg_error
import random


class CapierreImage:
    """
    This class is responsible for steganography inside a image.

    It uses the LSB (Least Significan Bit) method using a custom implementation using pseudo-random generator for frequency detection (using builtin `random()` function).

    @param image: `PIL.Image.Image` - The image to hide/extract the message.
    @param seed: `int` - The seed to be used for encryption/decryption. (default: `0`)
    """

    def __init__(self, image: Image.Image, seed=0):
        self.image = image
        self.seed = seed
        self.image_size = self.image.width + self.image.height
        self.nb_channels = len(self.image.mode)
        self.image_data = tuple(self.image.getdata())

    def check_size(self) -> bool:
        if len(self.data) < self.image.size[0] + self.image.size[1]:
            msg_error("[!][CapierreImage] data must be smaller than the image file.")
            return False
        return True

    def get_new_position(self):
        random_stack = []

        random.seed(self.seed)
        for _ in range(self.image_size):
            value = random.randint(0, self.image_size)
            while value in random_stack:
                value = random.randint(0, self.image_size)
            random_stack.append(value)
            yield value

    def hide(self, message: bytes):
        if not (self.check_size() and self.data is not None):
            return

        bit_pos = 0
        random_position = self.get_new_position()

        for i in range(self.image_size):
            position = random_position()

            for j in range(self.nb_channels):
                if message[i * self.image_size + j] & (1 << bit_pos):
                    self.image_data[position][j] |=  1
                else:
                    self.image_data[position][j] &=  0
                bit_pos = (bit_pos + 1) % 8

    def extract(self) -> bytes:
        bit_pos = 0
        random_position = self.get_new_position()
        message = bytearray(self.image_size * self.nb_channels)

        for i in range(self.image_size):
            position = random_position()

            for j in range(self.nb_channels):
                message[(i * self.image_size + j) // 8] |= (self.image_data[position][j] & 1) << bit_pos
                bit_pos = (bit_pos + 1) % 8
