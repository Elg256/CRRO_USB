import base64
import sys
import os
import hashlib
import time
import os

from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QTreeView, QWidget, QLabel, QFileSystemModel\
    , QMessageBox, QMenu, QPushButton, QDialog, QLineEdit, QHBoxLayout
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon, QPixmap
# from cryptcrro.symetric import crro
import tempfile
from PyQt5.QtCore import QMimeData, QUrl
from cryptography.fernet import Fernet



encrypted_data_path = os.path.abspath("./encrypted_data/")

class Get_Passord(QDialog):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)

        self.main_window = main_window
        self.setWindowTitle('Password')
        self.setWindowIcon(QIcon("usb_img/crro.png"))

        self.message = QLabel("If you find this usb-stick please \ncontact me at PutYourEmail@gmail.com", self)
        self.message.setGeometry(25, 10, 200, 30)

        self.label = QLabel('Password:', self)
        self.label.setGeometry(80, 50, 110, 20)

        self.input_field = QLineEdit(self)
        self.input_field.setGeometry(25, 70, 200, 20)
        self.input_field.setEchoMode(QLineEdit.EchoMode.Password)

        self.ok_button = QPushButton('Ok', self)
        self.ok_button.setGeometry(25, 100, 200, 30)

        self.ok_button.clicked.connect(self.take_user_input)

    def take_user_input(self, checked=False):
        user_input = self.input_field.text()
        if user_input.strip():
            _key = user_input
            self.main_window.set_key(_key)
        else:
            QMessageBox("Enter a password", "Enter a password.")

        self.accept()


class DecryptFileSystemModel(QFileSystemModel):
    def __init__(self, decryption_key, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.decryption_key = decryption_key

    def data(self, index, role=Qt.DisplayRole):

        if role == Qt.DisplayRole and index.column() == 0:
            file_path = os.path.abspath(self.filePath(index))
            print(file_path)

            if file_path.startswith(encrypted_data_path):

                encrypted_name = super().data(index, role)
                try:
                    key_hash = hashlib.pbkdf2_hmac(
                        "sha256", password=self.decryption_key.encode(),
                        salt=b"encryted_usb_stick", iterations=4000
                    )
                    #decrypted_name = crro.decrypt(key_hash, encrypted_name.encode()).decode()
                    f = Fernet(base64.urlsafe_b64encode(key_hash))
                    decrypted_name = f.decrypt(encrypted_name.encode()).decode()
                    print("decryption")
                    return decrypted_name
                except Exception as e:
                    print(f"Erreur de déchiffrement pour '{encrypted_name}': {e}")
                    return encrypted_name
            return super().data(index, role)

        return super().data(index, role)

    def mimeData(self, indexes):
        mime_data = QMimeData()
        for index in indexes:
            file_path = os.path.abspath(self.filePath(index))
            if file_path.startswith(encrypted_data_path):
                try:

                    key_hash = hashlib.pbkdf2_hmac(
                        "sha256", password=self.decryption_key.encode(),
                        salt=b"encryted_usb_stick", iterations=4000
                    )
                    with open(file_path, "rb") as encrypted_file:
                        encrypted_data = encrypted_file.read()
                        #decrypted_data = crro.decrypt(key_hash, encrypted_data)
                        f = Fernet(base64.urlsafe_b64encode(key_hash))
                        decrypted_data = f.decrypt(encrypted_data)

                    #original_name = crro.decrypt(key_hash, os.path.basename(file_path).encode()).decode()
                    f = Fernet(base64.urlsafe_b64encode(key_hash))
                    original_name = f.decrypt(os.path.basename(file_path).encode()).decode()
                    temp_dir = tempfile.gettempdir()
                    temp_file_path = os.path.join(temp_dir, original_name)
                    with open(temp_file_path, "wb") as temp_file:
                        temp_file.write(decrypted_data)


                    mime_data.setUrls([QUrl.fromLocalFile(temp_file_path)])
                except Exception as e:
                    print(f"Erreur lors du déchiffrement pour '{file_path}': {e}")
            else:
                mime_data.setUrls([QUrl.fromLocalFile(file_path)])
        return mime_data



class MainWidget(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Crro_Usb")
        self.setWindowIcon(QIcon("usb_img/crro.png"))
        #self.resize(720, 480)
        self.adjustSize()
        self.setAcceptDrops(True)

        self.key = ""

        self.show_password_windows_access()

        self.file_model = DecryptFileSystemModel(decryption_key=self.key)
        self.file_model.setRootPath("")
        self.file_model.setReadOnly(True)

        self.tree_view = QTreeView()
        self.tree_view.setModel(self.file_model)
        self.tree_view.setRootIndex(self.file_model.index("./encrypted_data"))
        self.tree_view.setSelectionMode(QTreeView.SingleSelection)
        self.tree_view.setDragEnabled(True)
        self.tree_view.setAcceptDrops(True)
        self.tree_view.setDropIndicatorShown(True)
        self.tree_view.setColumnWidth(0, 220)

        self.tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_view.customContextMenuRequested.connect(self.show_context_menu)

        layout = QVBoxLayout()

        layout_img = QHBoxLayout()
        label = QLabel(self)

        pixmap = QPixmap('usb_img/img.png')
        label.setPixmap(pixmap)
        layout_img.addWidget(label)

        label_logo = QLabel(self)
        pixmap_logo = QPixmap('usb_img/crro.png')
        pixmap_logo_resize = pixmap_logo.scaled(pixmap.width() + 5, pixmap.height() + 5, Qt.KeepAspectRatio)
        label_logo.setPixmap(pixmap_logo_resize)

        layout_img.addWidget(label_logo)

        layout.addLayout(layout_img)
        layout.addWidget(self.tree_view)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.adjustSize()

        current_size = self.size()
        extra_width = 90
        extra_height = 80
        self.resize(current_size.width() + extra_width, current_size.height() + extra_height)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        for f in files:

            start_time = time.time()

            with open(f, "rb") as _file:
                data = _file.read()

            try:
                key_hash = hashlib.pbkdf2_hmac(
                    "sha256", password=self.key.encode(),
                    salt=b"encryted_usb_stick", iterations=4000
                )
                #encrypted_file_name = crro.encrypt(key_hash, os.path.basename(f).encode()).decode()
                fernet = Fernet(base64.urlsafe_b64encode(key_hash))
                encrypted_file_name = fernet.encrypt(os.path.basename(f).encode()).decode()
                with open(f".\\encrypted_data\\{encrypted_file_name}", "wb+") as file:
                    f = Fernet(base64.urlsafe_b64encode(key_hash))
                    #encrypted_data = crro.encrypt(key_hash, data)
                    encrypted_data = f.encrypt(data)
                    file.write(encrypted_data)
                end_time = time.time()

            except Exception as e:
                print(f"Erreur lors du chiffrement : {e}")

    def set_key(self, _key):
        self.key = _key

    def show_password_windows_access(self):
        get_password = Get_Passord(self)
        get_password.exec()

    def show_context_menu(self, position):
        index = self.tree_view.indexAt(position)
        if not index.isValid():
            return

        file_path = self.file_model.filePath(index)
        menu = QMenu()

        delete_action = menu.addAction("Delete")
        action = menu.exec_(self.tree_view.viewport().mapToGlobal(position))

        if action == delete_action:
            self.delete_file(file_path)

    def delete_file(self, file_path):
        key_hash = hashlib.pbkdf2_hmac(
            "sha256", password=self.key.encode(),
            salt=b"encryted_usb_stick", iterations=4000
        )
        # encrypted_file_name = crro.encrypt(key_hash, os.path.basename(f).encode()).decode()
        fernet = Fernet(base64.urlsafe_b64encode(key_hash))
        file_path_str = fernet.decrypt(os.path.basename(file_path)).decode()

        reply = QMessageBox.question(
            self, "Confirmation", f"Do you really want to deletech '{file_path_str}' ?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:

            os.remove(file_path)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ui = MainWidget()
    ui.show()
    sys.exit(app.exec_())
