import sys
import os
import json
import shutil
from PIL import Image
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QListWidgetItem, QWidget, QVBoxLayout, QLabel, QFrame, QHBoxLayout, QLineEdit, QPushButton, QMessageBox, QGridLayout
from sidebar_ui import Ui_MainWindow
sys.path.append('../tool/src/')
from capierre import Capierre
from capierreAnalyzer import CapierreAnalyzer
from capierreImage import CapierreImage
from capierreParsing import CapierreParsing
from utils.messages import msg_success, msg_error, msg_info, msg_warning


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setFixedSize(1200, 800) 

        self.ui.sidebar_full.hide()

        self.ui.stackedWidget.setCurrentIndex(0)

        self.ui.confirm_btn.clicked.connect(self.hide_action)
        self.ui.confirm_btn_2.clicked.connect(self.retrieve_action)
        self.ui.checkBox_file.toggled.connect(self.update_on_file_select)
        self.ui.open_button_2.clicked.connect(self.clicker_2)
        self.ui.open_button.clicked.connect(self.clicker_1)
        self.ui.challenge_list.setSpacing(10) 
        
        self.ui.retrieve_btn_2.toggled.connect(self.on_retrieve_btn_2_toggled)
        self.ui.retrieve_btn_3.toggled.connect(self.on_retrieve_btn_1_toggled)
        self.ui.hide_btn_1.toggled.connect(self.on_hide_btn_1_toggled)
        self.ui.hide_btn_2.toggled.connect(self.on_hide_btn_2_toggled)
        self.ui.home_btn.toggled.connect(lambda checked: self.ui.stackedWidget.setCurrentIndex(0) if checked else None)
        self.ui.home_btn_2.toggled.connect(lambda checked: self.ui.stackedWidget.setCurrentIndex(0) if checked else None)
        
        self.ui.challenges_btn_1.toggled.connect(self.on_challenges_btn_1_toggled)
        self.ui.challenges_btn_2.toggled.connect(self.on_challenges_btn_2_toggled)

    def clicker_1(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*);;Python Files (*.py)")
        if fname:
            self.ui.lineEdit.setText(fname)

    def clicker_2(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*);;Python Files (*.py)")
        if fname:
            self.ui.lineEdit_4.setText(fname)

    def clicker_3(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*);;Python Files (*.py)")
        if fname:
            self.ui.lineEdit_2.setText(fname)


    def update_on_file_select(self):

        if (self.ui.checkBox_file.isChecked() == True):
            icon6 = QtGui.QIcon()
            icon6.addPixmap(QtGui.QPixmap(":/icon/icon/cil-folder-open.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
            open_button = QtWidgets.QPushButton(self.ui.widget_2)
            open_button.clicked.connect(self.clicker_3)
            open_button.setMinimumSize(QtCore.QSize(100, 30))
            open_button.setIcon(icon6)
            open_button.setText("Open")
            open_button.setObjectName("open_button")
            self.ui.horizontalLayout_5.addWidget(open_button, 0)
        else:
            self.ui.horizontalLayout_5.itemAt(2).widget().deleteLater()

    def show_info_messagebox(self): 
        msg = QtWidgets.QMessageBox() 
        msg.setIcon(QtWidgets.QMessageBox.Information) 
        msg.setText("SUCCESS: Binary compiled successfully.")
        msg.setWindowTitle("Information MessageBox") 
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msg.exec_()

    def show_info_messagebox_retrieve(self): 
        msg = QtWidgets.QMessageBox() 
        msg.setIcon(QtWidgets.QMessageBox.Information) 
        msg.setText("SUCCESS: Content extracted successfully.")
        msg.setWindowTitle("Information MessageBox") 
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msg.exec_()

    def show_info_messagebox_retrieve_failure(self): 
        msg = QtWidgets.QMessageBox() 
        msg.setIcon(QtWidgets.QMessageBox.Information) 
        msg.setText("FAILURE: An error occured.\nIt means that you haven't selected the correct retrieval or conceal method.\nYou may try again.")
        msg.setWindowTitle("Information MessageBox") 
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msg.exec_()

    def show_info_failure(self): 
        msg = QtWidgets.QMessageBox() 
        msg.setIcon(QtWidgets.QMessageBox.Information) 
        msg.setText("FAILURE: Unsupported file.")
        msg.setWindowTitle("Information MessageBox") 
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msg.exec_()

    def detect_correct_type(self, box_value_file: str) -> str:

        magic_numbers = {
            "png": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            "elf": bytes([0x7F, 0x45, 0x4C, 0x46]),
            "mach-o": bytes([0xCF, 0xFA, 0xED, 0xFE]),
            "macho-o-universal": bytes([0xCA, 0xFE, 0xBA, 0xBE]),
            "pe": bytes([0x4D, 0x5A])
        }

        extension_files = {
            "c": ".c",
            "cpp": ".cpp",
            "png": ".png"
        }

        value: str = str()


        if os.path.exists(box_value_file) == False:
            return ""
        with open(box_value_file, "rb") as fd:
            file_head = fd.read()

        for name, magic in magic_numbers.items():
            if file_head.startswith(magic):
                value = name
                break

        if value == "":
            for name, end in extension_files.items():
                if box_value_file.endswith(end):
                    value = name
                    break

            if value == "":
                self.show_info_failure()

        return value


    def hide_action(self):

        box_value_file: str = self.ui.lineEdit.text()
        box_value_sentence: str = self.ui.lineEdit_2.text()
        box_value_password: str = self.ui.lineEdit_3.text()
        box_value_bytes: bytes = box_value_sentence.encode()
        value: str = self.detect_correct_type(box_value_file)

        if (self.ui.checkBox_file.isChecked() == True):
            if os.path.exists(box_value_sentence) == False:
                msg_warning(f"WARNING: File not found.")
                return
            with open(box_value_sentence, "rb") as file:
                box_value_bytes = file.read()

        if value == "":
            return
        elif value != "png":
            capierreObject = Capierre(
                box_value_file,
                value,
                box_value_bytes,
                box_value_password,
                "result_binary.bin",
            )
            capierreObject.hide_information()
        else:
            image = Image.open(box_value_file)
            capierreObject = CapierreImage(
                image,
                "Modified Picture.png",
                42
            )
            capierreObject.hide(box_value_bytes)
            image.close()
        self.show_info_messagebox()
        self.ui.lineEdit.setText("")
        self.ui.lineEdit_2.setText("")
        self.ui.lineEdit_3.setText("")

    def retrieve_action(self):

        try:
            box_value_file: str = self.ui.lineEdit_4.text()
            box_value_password: str = self.ui.lineEdit_5.text()
            value: str = self.detect_correct_type(box_value_file)

            if value == "":
                return
            elif value != "png":
                capierreObject = CapierreAnalyzer(
                    box_value_file,
                    "MESSAGE",
                    box_value_password,
                )
                if (self.ui.checkBox_mode.isChecked() == False):
                    capierreObject.retrieve_message_from_binary()
                else:
                    capierreObject.read_in_compiled_binaries()
            else:
                image = Image.open(box_value_file)
                capierreObject = CapierreImage(
                    image,
                    "MESSAGE",
                    42
                )
                capierreObject.extract()
                image.close()
            self.show_info_messagebox_retrieve()
            self.ui.lineEdit_4.setText("")
            self.ui.lineEdit_5.setText("")
        except Exception as e:
            self.show_info_messagebox_retrieve_failure()

    def on_retrieve_btn_1_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(1)  # Retrieve page is at index 1

    def on_retrieve_btn_2_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(1)  # Retrieve page is at index 1

    def on_hide_btn_1_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(2)  # Hide page is at index 2

    def on_hide_btn_2_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(2)  # Hide page is at index 2

    def on_challenges_btn_1_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(3)  # Challenges page is at index 3
        self.load_challenges()

    def on_challenges_btn_2_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(3)  # Challenges page is at index 3
        self.load_challenges()

    def load_challenges(self, folder_path='./challenges'):
        self.ui.challenge_list.clear()

        if not os.path.exists(folder_path):
            print(f"Challenge folder {folder_path} not found.")
            return

        for filename in os.listdir(folder_path):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join(folder_path, filename), 'r', encoding='utf-8') as f:
                        challenge = json.load(f)
                        item_widget = ChallengeWidget(challenge)

                        item = QListWidgetItem()
                        item.setSizeHint(item_widget.sizeHint())

                        self.ui.challenge_list.addItem(item)
                        self.ui.challenge_list.setItemWidget(item, item_widget)
                except Exception as e:
                    print(f"Error loading {filename}: {e}")


class ChallengeWidget(QWidget):
    def __init__(self, challenge):
        super().__init__()
        self.challenge = challenge

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(5, 5, 5, 5)

        # Cadre principal
        self.frame = QFrame()
        self.frame.setObjectName("challenge_frame")
        main_layout = QHBoxLayout(self.frame)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(20)

        # === COLONNE DE GAUCHE ===
        left_layout = QVBoxLayout()
        left_layout.setSpacing(8)

        title_label = QLabel(f"<b>{challenge['title']}</b>")
        description_label = QLabel(challenge['description'])
        description_label.setWordWrap(True)

        left_layout.addWidget(title_label)
        left_layout.addWidget(description_label)
        description_label.setMinimumWidth(400) 

        # FLAG challenge
        if 'flag' in challenge:
            flag_line = QHBoxLayout()
            flag_label = QLabel("Flag")
            flag_label.setFixedWidth(50)
            self.flag_input = QLineEdit()
            self.flag_input.setPlaceholderText("Enter flag...")
            self.flag_input.setFixedWidth(200)
            self.submit_button = QPushButton("Submit")
            self.submit_button.setFixedWidth(100)
            self.submit_button.clicked.connect(self.check_flag)

            flag_line.addWidget(flag_label)
            flag_line.addWidget(self.flag_input)
            flag_line.addWidget(self.submit_button)
            left_layout.addLayout(flag_line)

        # FILE UPLOAD challenge
        if challenge.get('upload_check'):
            self.upload_button = QPushButton("Submit File")
            self.upload_button.setFixedWidth(150)
            self.upload_button.clicked.connect(self.submit_file)
            left_layout.addWidget(self.upload_button)

        left_layout.addStretch()
        main_layout.addLayout(left_layout)

        # === COLONNE DE DROITE ===
        right_layout = QVBoxLayout()
        right_layout.addStretch()

        # Download bouton
        self.download_button = QPushButton("Download")
        self.download_button.clicked.connect(self.download_file)
        self.download_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border-radius: 5px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)

        # Hint bouton
        self.hint_button = QPushButton("Hint")
        self.hint_button.clicked.connect(self.show_hint)
        self.hint_button.setStyleSheet("""
            QPushButton {
                background-color: #f39c12;
                color: white;
                border-radius: 5px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d35400;
            }
        """)

        btn_line = QHBoxLayout()
        btn_line.addStretch()
        btn_line.addWidget(self.download_button)
        btn_line.addWidget(self.hint_button)

        right_layout.addLayout(btn_line)
        main_layout.addLayout(right_layout)

        outer_layout.addWidget(self.frame)


    def download_file(self):
        file_name = self.challenge.get('file')
        if not file_name:
            QMessageBox.warning(self, "No file", "No file specified.")
            return

        source_path = os.path.join('./challenge_files', file_name)
        if not os.path.exists(source_path):
            QMessageBox.warning(self, "File not found", f"{file_name} not found.")
            return

        dest_path, _ = QFileDialog.getSaveFileName(self, "Save File", file_name)
        if dest_path:
            shutil.copyfile(source_path, dest_path)
            QMessageBox.information(self, "Success", f"File '{file_name}' downloaded.")

    def submit_file(self):
        submitted_file, _ = QFileDialog.getOpenFileName(self, "Submit your file", "", "All Files (*)")
        if not submitted_file:
            return

        expected_file_path = os.path.join('./expected_output', self.challenge.get('file'))

        # Vérifie l'égalité (contenu binaire) ou appelle ta fonction de comparaison
        try:
            if self.compare_files(submitted_file, expected_file_path):
                QMessageBox.information(self, "Success", "✅ Submitted file is correct!")
            else:
                QMessageBox.critical(self, "Failed", "❌ Submitted file is incorrect.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {e}")

    def compare_files(self, user_file, expected_file):
        with open(user_file, 'rb') as f1, open(expected_file, 'rb') as f2:
            return f1.read() == f2.read()


    def check_flag(self):
        user_flag = self.flag_input.text().strip()
        correct_flag = self.challenge.get('flag')

        msg = QMessageBox(self)
        msg.setStyleSheet("""
            QMessageBox {
                color: black;
            }
        """)

        if user_flag == correct_flag:
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Correct")
            msg.setText("Flag is Correct.")
        else:
            msg.setIcon(QMessageBox.Critical)
            msg.setWindowTitle("Incorrect")
            msg.setText("Flag is Incorrect.")

        msg.exec_()


    def show_hint(self):
        hint_text = self.challenge.get('hint', 'No hint available.')
        QMessageBox.information(self, "Hint", hint_text)


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
