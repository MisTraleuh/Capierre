import sys
from PIL import Image

sys.path.append('../')

from capierreImage import CapierreImage

def run_tests():
    payload = b'test1234'
    big_payload = b'this phrase is too big to be hidden in a small png file.'
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
    assert extracted is not None, '[!] The payload cannot be returned.'
    print(extracted)
    assert cpImgGood.extract() == payload, '[!] The payload is not the same.'
    good.close()
#    assert cpImgJpeg.extract() == payload, '[!] The payload is not the same.'

run_tests()
