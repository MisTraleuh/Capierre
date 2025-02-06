from . import CapierreImage

def run_tests():
    payload = b'test1234'
    seed = 42
    good_fp = 'test.png'
    invalid_fp = 'blabla'
    small_fp = 'small.png'
    jpeg_fp = 'test.jpg'
    
    cpImgGood = CapierreImage(good_fp, seed)
    cpImgInvalid = CapierreImage(invalid_fp, seed)
    cpImgSmall = CapierreImage(small_fp, seed)

    cpImgGood.hide(payload)

    assert cpImgGood.extract() == payload, '[!] The payload is not the same.'
