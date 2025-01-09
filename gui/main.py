import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog
from sidebar_ui import Ui_MainWindow


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        self.ui.sidebar_full.hide()

        self.ui.stackedWidget.setCurrentIndex(0)

        self.ui.open_button_2.clicked.connect(self.clicker_2)
        self.ui.open_button.clicked.connect(self.clicker_1)


    def clicker_1(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*);;Python Files (*.py)")
        if fname:
            self.ui.lineEdit.setText(fname)

    def clicker_2(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*);;Python Files (*.py)")
        if fname:
            self.ui.lineEdit_4.setText(fname)

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

    try:
        with open('style.qss', 'r') as style_files:
            style_str = style_files.read()
        app.setStyleSheet(style_str)
    except FileNotFoundError:
        print("Style file not found. Proceeding without stylesheet.")

    window = MainWindow()
    window.show()
    sys.exit(app.exec())
