import sys
from PIL import Image

sys.path.append('../')

from capierreImage import CapierreImage

def run_tests():
    payload = b'test1234'
    seed = 42
    good = Image.open('test.png')
#    small = Image.open('invalid.png')
#    jpeg = Image.open('test.jpg')
    
    cpImgGood = CapierreImage(good, seed)
#    cpImgSmall = CapierreImage(small, seed)
#    cpImgJpeg = CapierreImage(jpeg, seed)

    cpImgGood.hide(payload)
#    cpImgJpeg.hide(payload)

    assert cpImgGood.extract() == payload, '[!] The payload is not the same.'
#    assert cpImgJpeg.extract() == payload, '[!] The payload is not the same.'

run_tests()
