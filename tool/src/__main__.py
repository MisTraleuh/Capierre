import sys
from capierre.__init__ import Capierre
from capierreParsing.__init__ import CapierreParsing

def main():
    capierreParsing  = CapierreParsing()
    statement, exit_status = capierreParsing.check_args()
    if (statement == False):
        sys.exit(exit_status)
    capierreObject = Capierre(capierreParsing.file, capierreParsing.type_file, capierreParsing.sentence)
    capierreObject.hide_information()

if __name__ == '__main__':
    main()
