import sys
import os
import json
import shutil
from PyQt5 import QtCore
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QListWidgetItem, QWidget, QVBoxLayout, QLabel, QFrame, QHBoxLayout, QLineEdit, QPushButton, QMessageBox, QGridLayout
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
        self.ui.challenge_list.setSpacing(10) 

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
        self.load_challenges()

    def on_challenges_btn_2_toggled(self):
        self.ui.stackedWidget.setCurrentIndex(2)
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

        # Frame de fond
        self.frame = QFrame()
        self.frame.setObjectName("challenge_frame")
        main_layout = QHBoxLayout(self.frame)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(20)

        # === GAUCHE ===
        left_layout = QVBoxLayout()
        left_layout.setSpacing(8)

        title_label = QLabel(f"<b>{challenge['title']}</b>")
        description_label = QLabel(challenge['description'])
        description_label.setWordWrap(True)

        # Flag + Submit
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

        # Assemble gauche
        left_layout.addWidget(title_label)
        left_layout.addWidget(description_label)
        left_layout.addStretch()
        left_layout.addLayout(flag_line)

        main_layout.addLayout(left_layout)

        # === DROITE ===
        right_layout = QVBoxLayout()
        right_layout.addStretch()  # pousse les boutons en bas

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

        # Ajoute à droite
        btn_line = QHBoxLayout()
        btn_line.addStretch()  # pousse à droite
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
