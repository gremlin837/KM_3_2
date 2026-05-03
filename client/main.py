import sys
from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont

from client import MainWindow


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    main_window = MainWindow(username="engineer_ivanov", role="operator")
    main_window.show()
    sys.exit(app.exec())