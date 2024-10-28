import sys

class Tool():
    def __init__(self):
        self.name = 'Capierre'

    def start(self):
        print(f'{self.name} started')

def main():
    tool = Tool()
    tool.start()

if __name__ == '__main__':
    main()
