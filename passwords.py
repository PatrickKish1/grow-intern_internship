import sys
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QProgressBar
from PyQt6.QtGui import QFont
import re

class PasswordStrengthTester(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Password Strength Tester')
        self.setGeometry(100, 100, 500, 400)
        self.setStyleSheet("background-color: #f0f0f0;")

        layout = QVBoxLayout()

        self.label = QLabel('Enter your password:')
        self.label.setFont(QFont('Arial', 14))
        self.label.setStyleSheet("color: #000")
        layout.addWidget(self.label)

        self.password_input = QLineEdit()
        
        self.password_input.textChanged.connect(self.check_password_strength)
        self.password_input.setStyleSheet("color: #000; font-size: 35px")
        layout.addWidget(self.password_input)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(3)
        layout.addWidget(self.progress_bar)

        self.length_label = QLabel('Minimum length 8')
        self.length_label.setFont(QFont('Arial', 12))
        self.length_label.setStyleSheet("color: red")
        layout.addWidget(self.length_label)

        self.capital_label = QLabel('Contains capital letters')
        self.capital_label.setFont(QFont('Arial', 12))
        self.capital_label.setStyleSheet("color: red")
        layout.addWidget(self.capital_label)

        self.number_label = QLabel('Contains numbers')
        self.number_label.setFont(QFont('Arial', 12))
        self.number_label.setStyleSheet("color: red")
        layout.addWidget(self.number_label)

        self.symbol_label = QLabel('Contains symbols')
        self.symbol_label.setFont(QFont('Arial', 12))
        self.symbol_label.setStyleSheet("color: red")
        layout.addWidget(self.symbol_label)

        self.strength_label = QLabel('Password Strength: ')
        self.strength_label.setFont(QFont('Arial', 14))
        self.strength_label.setStyleSheet("color: #000")
        layout.addWidget(self.strength_label)

        self.setLayout(layout)

    def check_password_strength(self):
        password = self.password_input.text()
        strength = self.calculate_strength(password)

        self.length_label.setStyleSheet("color: green" if len(password) >= 8 else "color: red")
        self.capital_label.setStyleSheet("color: green" if re.search("[A-Z]", password) else "color: red")
        self.number_label.setStyleSheet("color: green" if re.search("[0-9]", password) else "color: red")
        self.symbol_label.setStyleSheet("color: green" if re.search("[^a-zA-Z0-9]", password) else "color: red")
        
        self.strength_label.setText(f'Password Strength: {strength}')
        self.strength_label.setStyleSheet("color: #000")

        if strength == "Weak":
            self.progress_bar.setValue(25)
            self.progress_bar.setStyleSheet("QProgressBar::chunk {background-color: red;}")
        elif strength == "Moderate":
            self.progress_bar.setValue(50)
            self.progress_bar.setStyleSheet("QProgressBar::chunk {background-color: yellow;}")
        elif strength == "Strong":
            self.progress_bar.setValue(100)
            self.progress_bar.setStyleSheet("QProgressBar::chunk {background-color: green;}")

    def calculate_strength(self, password):
        length = len(password)
        lower = re.search("[a-z]", password)
        upper = re.search("[A-Z]", password)
        digit = re.search("[0-9]", password)
        special = re.search("[^a-zA-Z0-9]", password)

        if length < 8:
            return "Weak"
        elif length >= 8 and (lower and upper and digit and special):
            return "Strong"
        elif length >= 8 and (lower and upper or lower and digit or lower and special or upper and digit or upper and special or digit and special):
            return "Moderate"
        else:
            return "Weak"

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PasswordStrengthTester()
    ex.show()
    sys.exit(app.exec())
