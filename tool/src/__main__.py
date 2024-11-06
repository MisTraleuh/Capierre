import sys
from capierre.__init__ import Capierre
from capierreParsing.__init__ import CapierreParsing
from capierreAnalyzer.__init__ import CapierreAnalyzer

def main():

    capierreObject: object = None
    capierreAnalyzer: object = None
    capierreParsing: object  = CapierreParsing()
    statement, status = capierreParsing.check_args()

    if (statement == False):
        sys.exit(status)
    if (status == 0):
        capierreObject = Capierre(capierreParsing.file_to_hide,
                                  capierreParsing.type_file,
                                  capierreParsing.sentence,
                                  capierreParsing.binary_file
                                  )
        capierreObject.hide_information()
    else:
        capierreAnalyzer = CapierreAnalyzer(capierreParsing.file)
        capierreAnalyzer.retrieve_message_from_binary()

if __name__ == '__main__':
    main()
