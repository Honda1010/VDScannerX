import customtkinter as ctk
from src.gui.main_window import MainWindow

if __name__ == "__main__":
    ctk.set_appearance_mode("Light")  
    root = ctk.CTk()
    app = MainWindow(root)
    root.mainloop()

# pyinstaller --onefile --windowed --icon=bug.png main.py --- to make the executable file