from PyQt6.QtWidgets import QApplication, QWidget, QMainWindow
from PyQt6.QtCore import QSize, Qt

import sys

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Capierre")
        self.setFixedSize(QSize(1200, 800))

app = QApplication(sys.argv)

window = MainWindow()
window.show()

app.exec()
