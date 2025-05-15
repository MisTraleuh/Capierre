from __future__ import annotations
import sys
import logging
from PIL import Image

logging.getLogger("angr").setLevel("CRITICAL")
logging.getLogger("cle").setLevel("CRITICAL")
from capierre.__init__ import Capierre
from capierreImage.__init__ import CapierreImage
from capierreParsing.__init__ import CapierreParsing
from capierreAnalyzer.__init__ import CapierreAnalyzer
from utils.messages import msg_error, msg_success, msg_warning

def conceal_image(capierreParsing: CapierreParsing):
    image = Image.open(capierreParsing.file)
    if (capierreParsing.output_file_retreive == ""):
        capierreParsing.output_file_retreive = "Modified Image." + capierreParsing.type_file
    capierreObject = CapierreImage(
        image,
        capierreParsing.output_file_retreive,
        capierreParsing.seed
    )
    capierreObject.hide(capierreParsing.sentence.encode())
    image.close()

def retrieve_image(capierreParsing: CapierreParsing):
    image = Image.open(capierreParsing.file)
    capierreObject = CapierreImage(
        image,
        capierreParsing.output_file_retreive,
        capierreParsing.seed
    )
    msg_success(f'Message: {capierreObject.extract().decode('utf-8')}')
    image.close()

def conceal_binary(capierreParsing: CapierreParsing):
    capierreObject = Capierre(
        capierreParsing.file,
        capierreParsing.type_file,
        capierreParsing.sentence,
        capierreParsing.password,
        capierreParsing.binary_file,
    )
    capierreObject.hide_information()

def retrieve_binary(capierreParsing: CapierreParsing):
    capierreAnalyzer = CapierreAnalyzer(
        capierreParsing.file,
        capierreParsing.output_file_retreive,
        capierreParsing.password,
    )
    if (capierreParsing.mode == False):
        capierreAnalyzer.retrieve_message_from_binary()
    else:
        capierreAnalyzer.read_in_compiled_binaries()


def main():

    capierreParsing = CapierreParsing()
    statement, status = capierreParsing.check_args()

    if statement == False:
        sys.exit(status)
    if capierreParsing.conceal == True:
        if capierreParsing.image == False:
            conceal_binary(capierreParsing)
        else:
            conceal_image(capierreParsing)
    else:
        if capierreParsing.image == False:
            retrieve_binary(capierreParsing)
        else:
            retrieve_image(capierreParsing)

if __name__ == "__main__":
    main()
