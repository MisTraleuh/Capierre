from PIL import Image
from dataclasses import dataclass
from capierreParsing import msg_error
import random


@dataclass(slots=True)
class CapierreImage:
    """
    This class is responsible for steganography inside a image.

    It uses the LSB (Least Significan Bit) method using a custom implementation using pseudo-random generator for frequency detection (using builtin `random()` function).

    @param image: `PIL.Image.Image` - The image to hide/extract the message.
    @param seed: `int` - The seed to be used for encryption/decryption. (default: `0`)
    @param nb_bits: `int` - The number of LSB bits to use. (default: `1`)
    """

    image: Image.Image
    seed: int = 0
    nb_bit: int = 1

    def check_nbits(self) -> bool:
        if self.nb_bit < 1 or self.nb_bit > 2:
            msg_error("[!][CapierreImage] nb_bit must be between 1 and 2.")
            return False
        return True

    def check_size(self) -> bool:
        if len(self.data) < self.image.size[0] + self.image.size[1]:
            msg_error("[!][CapierreImage] data must be smaller than the image file.")
            return False
        return True

    def check_imagetype(self) -> bool:
        if self.image.mode != "RGBA":
            msg_error("[!][CapierreImage] image must be in PNG format (with alpha).")
            return False
        return True

    # TODO: LSB Using pseudo-random seeding for byte frequency
    def hide(self):
        if not (self.check_nbits() and self.check_size() and self.data is not None):
            return

        nb_pixels = 2 // self.nb_bit
        for i in range((self.image.size[0] + self.image.size[1]) // nb_pixels):
            pixels = self.image[i * nb_pixels : (i + 1) * nb_pixels]

    # TODO: Extract LSB using the same seed
    def extract(self):
        if not (self.check_nbits() and self.check_imagetype()):
            return

        nb_pixels = 2 // self.nb_bit
        for i in range((self.image.size[0] + self.image.size[1]) // nb_pixels):
            pixels = self.image[i * nb_pixels : (i + 1) * nb_pixels]
