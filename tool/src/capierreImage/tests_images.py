import sys
from PIL import Image

sys.path.append('../')

from capierreImage import CapierreImage

def run_tests():
    payload = b'test12345'
    seed = 42
    good = Image.open('test.png')
#    small = Image.open('invalid.png')
#    jpeg = Image.open('test.jpg')
    
    cpImgGood = CapierreImage(good, seed)
#    cpImgSmall = CapierreImage(small, seed)
#    cpImgJpeg = CapierreImage(jpeg, seed)

    print(payload)
    cpImgGood.hide(payload)
#    cpImgJpeg.hide(payload)

    extracted = cpImgGood.extract()
    print(extracted)
    assert cpImgGood.extract() == payload, '[!] The payload is not the same.'
#    assert cpImgJpeg.extract() == payload, '[!] The payload is not the same.'

run_tests()
