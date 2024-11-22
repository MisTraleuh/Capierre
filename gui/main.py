import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton
from PyQt5.QtCore import pyqtSlot, QFile, QTextStream

from sidebar_ui import Ui_MainWindow

class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.sidebar_full.hide()
        self.ui.stackedWidget.setCurrentIndex(0)

    def on_retrieve_btn_1_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(0)

    def on_retrieve_btn_2_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(0)

    def on_hide_btn_1_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(1)

    def on_hide_btn_2_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(1)

    def on_challenges_btn_1_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(2)

    def on_challenges_btn_2_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(2)
        

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())