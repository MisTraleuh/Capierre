from __future__ import annotations
import sys
import logging

logging.getLogger("angr").setLevel("CRITICAL")
logging.getLogger("cle").setLevel("CRITICAL")
from capierre.__init__ import Capierre
from capierreParsing.__init__ import CapierreParsing
from capierreAnalyzer.__init__ import CapierreAnalyzer


def main():

    capierreParsing = CapierreParsing()
    statement, status = capierreParsing.check_args()

    if statement == False:
        sys.exit(status)
    if capierreParsing.conceal == True:
        capierreObject = Capierre(
            capierreParsing.file,
            capierreParsing.type_file,
            capierreParsing.sentence,
            capierreParsing.password,
            capierreParsing.binary_file,
        )
        capierreObject.hide_information()
    else:
        capierreAnalyzer = CapierreAnalyzer(
            capierreParsing.file,
            capierreParsing.output_file_retreive,
            capierreParsing.password,
        )
        capierreAnalyzer.retrieve_message_from_binary()


if __name__ == "__main__":
    main()
