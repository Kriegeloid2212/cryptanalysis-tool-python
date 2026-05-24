import tkinter as tk
from tkinter import ttk, messagebox
from collections import Counter
import math

# --- КОНСТАНТИ ---
ALPHABET_EN = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_UK = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"


# ==========================================
#                  MODELS
# ==========================================

class BaseCipher:

    def __init__(self):
        self.alphabet_lat = ALPHABET_EN
        self.alphabet_cyr = ALPHABET_UK

    def encrypt(self, text, key):
        raise NotImplementedError()

    def decrypt(self, text, key):
        raise NotImplementedError()

    def preprocess(self, text, lang="UK"):
        alphabet = self.alphabet_cyr if lang == "UK" else self.alphabet_lat
        text = text.upper()
        return "".join([c for c in text if c in alphabet])

    def detect_lang(self, text):
        uk_count = sum(1 for c in text.upper() if c in self.alphabet_cyr)
        en_count = sum(1 for c in text.upper() if c in self.alphabet_lat)
        return "UK" if uk_count >= en_count else "EN"


class CaesarCipher(BaseCipher):
    """Модель для шифру Цезаря"""

    def encrypt(self, text, shift):
        try:
            shift = int(shift)
        except ValueError:
            raise ValueError("Ключ для шифру Цезаря має бути цілим числом.")

        lang = self.detect_lang(text)
        alphabet = self.alphabet_cyr if lang == "UK" else self.alphabet_lat
        n = len(alphabet)
        result = []
        for char in text.upper():
            if char in alphabet:
                idx = alphabet.index(char)
                result.append(alphabet[(idx + shift) % n])
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, text, shift):
        try:
            shift = int(shift)
        except ValueError:
            raise ValueError("Ключ для шифру Цезаря має бути цілим числом.")
        return self.encrypt(text, -shift)

    def brute_force(self, ciphertext):
        lang = self.detect_lang(ciphertext)
        alphabet = self.alphabet_cyr if lang == "UK" else self.alphabet_lat
        clean = self.preprocess(ciphertext, lang)
        results = []
        for shift in range(1, len(alphabet)):
            decrypted = self.decrypt(clean, shift)
            results.append((shift, decrypted))
        return results


class AtbashCipher(BaseCipher):
    """Модель для шифру Атбаш"""

    def encrypt(self, text, key=None):
        lang = self.detect_lang(text)
        alphabet = self.alphabet_cyr if lang == "UK" else self.alphabet_lat
        n = len(alphabet)
        result = []
        for char in text.upper():
            if char in alphabet:
                idx = alphabet.index(char)
                result.append(alphabet[n - 1 - idx])
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, text, key=None):
        return self.encrypt(text, key)


class VigenereCipher(BaseCipher):
    """Модель для шифру Віженера"""

    def encrypt(self, text, key):
        lang = self.detect_lang(text)
        alphabet = self.alphabet_cyr if lang == "UK" else self.alphabet_lat
        clean_key = self.preprocess(key, lang)
        if not clean_key:
            raise ValueError("Ключ повинен містити літери обраного алфавіту.")

        n = len(alphabet)
        result = []
        key_idx = 0
        for char in text.upper():
            if char in alphabet:
                shift = alphabet.index(clean_key[key_idx % len(clean_key)])
                char_idx = alphabet.index(char)
                result.append(alphabet[(char_idx + shift) % n])
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)

    def decrypt(self, text, key):
        lang = self.detect_lang(text)
        alphabet = self.alphabet_cyr if lang == "UK" else self.alphabet_lat
        clean_key = self.preprocess(key, lang)
        if not clean_key:
            raise ValueError("Ключ повинен містити літери обраного алфавіту.")

        n = len(alphabet)
        result = []
        key_idx = 0
        for char in text.upper():
            if char in alphabet:
                shift = alphabet.index(clean_key[key_idx % len(clean_key)])
                char_idx = alphabet.index(char)
                result.append(alphabet[(char_idx - shift) % n])
                key_idx += 1
            else:
                result.append(char)
        return "".join(result)


class PlayfairCipher(BaseCipher):
    """Модель для шифру Плейфера"""

    def __init__(self):
        super().__init__()
        self.matrix = []
        self.size = 5

    def build_matrix(self, key, lang="UK"):
        alphabet = self.alphabet_cyr if lang == "UK" else self.alphabet_lat
        clean_key = "".join([c for c in key.upper() if c in alphabet])
        if lang == "EN":
            clean_key = clean_key.replace("J", "I")

        matrix_chars = []
        for char in clean_key + alphabet:
            if char not in matrix_chars:
                if lang == "EN" and char == 'J':
                    continue
                matrix_chars.append(char)

        if lang == "UK":
            for pad in "123":
                if pad not in matrix_chars:
                    matrix_chars.append(pad)
            self.size = 6
            self.matrix = [matrix_chars[i:i + 6] for i in range(0, 36, 6)]
        else:
            self.size = 5
            self.matrix = [matrix_chars[i:i + 5] for i in range(0, 25, 5)]
        return self.matrix

    def prepare_pairs(self, text, lang="UK"):
        alphabet = self.alphabet_cyr if lang == "UK" else self.alphabet_lat
        clean_text = "".join([c for c in text.upper() if c in alphabet])
        if lang == "EN":
            clean_text = clean_text.replace("J", "I")

        filler = 'X' if lang == "EN" else 'Х'
        pairs = []
        i = 0
        while i < len(clean_text):
            a = clean_text[i]
            b = clean_text[i + 1] if i + 1 < len(clean_text) else filler
            if a == b:
                pairs.append((a, filler))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        return pairs

    def encrypt(self, text, key):
        lang = self.detect_lang(text)
        matrix = self.build_matrix(key, lang)
        pairs = self.prepare_pairs(text, lang)
        size = self.size

        def find_pos(char):
            for r in range(size):
                for c in range(size):
                    if matrix[r][c] == char:
                        return r, c
            return -1, -1

        result = []
        for a, b in pairs:
            r1, c1 = find_pos(a)
            r2, c2 = find_pos(b)
            if r1 == -1 or r2 == -1:
                result.extend([a, b])
                continue

            if r1 == r2:
                result.append(matrix[r1][(c1 + 1) % size])
                result.append(matrix[r2][(c2 + 1) % size])
            elif c1 == c2:
                result.append(matrix[(r1 + 1) % size][c1])
                result.append(matrix[(r2 + 1) % size][c2])
            else:
                result.append(matrix[r1][c2])
                result.append(matrix[r2][c1])
        return "".join(result)

    def decrypt(self, text, key):
        lang = self.detect_lang(text)
        matrix = self.build_matrix(key, lang)
        pairs = self.prepare_pairs(text, lang)
        size = self.size

        def find_pos(char):
            for r in range(size):
                for c in range(size):
                    if matrix[r][c] == char:
                        return r, c
            return -1, -1

        result = []
        for a, b in pairs:
            r1, c1 = find_pos(a)
            r2, c2 = find_pos(b)
            if r1 == -1 or r2 == -1:
                result.extend([a, b])
                continue

            if r1 == r2:
                result.append(matrix[r1][(c1 - 1) % size])
                result.append(matrix[r2][(c2 - 1) % size])
            elif c1 == c2:
                result.append(matrix[(r1 - 1) % size][c1])
                result.append(matrix[(r2 - 1) % size][c2])
            else:
                result.append(matrix[r1][c2])
                result.append(matrix[r2][c1])
        return "".join(result)


class FrequencyAnalyzer:
    """Клас для розрахунку частоти використання літер"""

    def __init__(self):
        self.freq_ukr = {
            'О': 9.28, 'А': 8.34, 'И': 6.12, 'Н': 6.07, 'В': 5.25, 'І': 4.88, 'Е': 4.75, 'Р': 4.74,
            'Т': 4.71, 'К': 4.00, 'С': 3.93, 'Д': 3.51, 'Л': 3.12, 'М': 3.02, 'У': 2.70, 'П': 2.62,
            'Я': 2.15, 'Ь': 1.83, 'З': 1.51, 'Б': 1.49, 'Ч': 1.42, 'Х': 1.17, 'Й': 1.08
        }
        self.freq_eng = {
            'E': 12.02, 'T': 9.10, 'A': 8.12, 'O': 7.68, 'I': 7.31, 'N': 6.95, 'S': 6.28, 'R': 6.02,
            'H': 5.92, 'D': 4.32, 'L': 3.98, 'U': 2.88, 'C': 2.71, 'M': 2.61, 'F': 2.30, 'Y': 2.11
        }

    def analyze(self, text, lang="UK"):
        alphabet = ALPHABET_UK if lang == "UK" else ALPHABET_EN
        clean = "".join([c for c in text.upper() if c in alphabet])
        if not clean:
            return {}
        total = len(clean)
        counter = Counter(clean)
        return {char: (count / total) * 100 for char, count in counter.items()}


class KasiskiAnalyzer:
    """Аналіз індексу збігів та оцінка довжини ключа"""

    def index_of_coincidence(self, text, lang="UK"):
        alphabet = ALPHABET_UK if lang == "UK" else ALPHABET_EN
        clean = "".join([c for c in text.upper() if c in alphabet])
        n = len(clean)
        if n <= 1:
            return 0.0
        freqs = Counter(clean)
        num = sum(f * (f - 1) for f in freqs.values())
        return num / (n * (n - 1))

    def calc_key_length(self, text, lang="UK"):
        alphabet = ALPHABET_UK if lang == "UK" else ALPHABET_EN
        clean = "".join([c for c in text.upper() if c in alphabet])
        if len(clean) < 10:
            return []

        ic_results = []
        for key_len in range(1, min(16, len(clean))):
            avg_ic = 0
            for i in range(key_len):
                subseq = clean[i::key_len]
                if len(subseq) > 1:
                    freqs = Counter(subseq)
                    n_sub = len(subseq)
                    ic = sum(f * (f - 1) for f in freqs.values()) / (n_sub * (n_sub - 1))
                    avg_ic += ic
            avg_ic /= key_len
            ic_results.append((key_len, avg_ic))

        ic_results.sort(key=lambda x: x[1], reverse=True)
        return ic_results[:5]


# ==========================================
#                CONTROLLER
# ==========================================

class AppController:
    """Клас-контролер для координації представлення та бізнес-моделей"""

    def __init__(self):
        self.caesar = CaesarCipher()
        self.atbash = AtbashCipher()
        self.vigenere = VigenereCipher()
        self.playfair = PlayfairCipher()
        self.freq_analyzer = FrequencyAnalyzer()
        self.kasiski = KasiskiAnalyzer()

    def process_crypto(self, cipher_type, text, key, decrypt=False):
        if not text.strip():
            raise ValueError("Будь ласка, введіть вхідний текст.")

        if cipher_type == "Caesar":
            if decrypt:
                return self.caesar.decrypt(text, key)
            return self.caesar.encrypt(text, key)

        elif cipher_type == "Atbash":
            if decrypt:
                return self.atbash.decrypt(text)
            return self.atbash.encrypt(text)

        elif cipher_type == "Vigenere":
            if decrypt:
                return self.vigenere.decrypt(text, key)
            return self.vigenere.encrypt(text, key)

        elif cipher_type == "Playfair":
            if decrypt:
                return self.playfair.decrypt(text, key)
            return self.playfair.encrypt(text, key)

        else:
            raise ValueError("Невідомий тип алгоритму.")


# ==========================================
#                  VIEW
# ==========================================

class CryptoApp(tk.Tk):
    """Основне графічне вікно програми (представлення)"""

    def __init__(self, controller):
        super().__init__()
        self.controller = controller
        self.title("Криптоаналіз класичних шифрів")
        self.geometry("1000x820")
        self.minsize(850, 650)

        self.create_widgets()

    def create_widgets(self):
        # Налаштування стилів
        style = ttk.Style()
        style.configure("TNotebook", padding=5)
        style.configure("TFrame", padding=5)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Створення вкладок
        self.caesar_tab = ttk.Frame(self.notebook)
        self.atbash_tab = ttk.Frame(self.notebook)
        self.vigenere_tab = ttk.Frame(self.notebook)
        self.playfair_tab = ttk.Frame(self.notebook)
        self.frequency_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.caesar_tab, text="Шифр Цезаря")
        self.notebook.add(self.atbash_tab, text="Шифр Атбаш")
        self.notebook.add(self.vigenere_tab, text="Шифр Віженера")
        self.notebook.add(self.playfair_tab, text="Шифр Плейфера")
        self.notebook.add(self.frequency_tab, text="Частотний аналіз")

        # Додавання контенту до кожної вкладки
        self.build_caesar_tab()
        self.build_atbash_tab()
        self.build_vigenere_tab()
        self.build_playfair_tab()
        self.build_frequency_tab()

    # ДОПОМІЖНІ МЕТОДИ СТВОРЕННЯ UI ШАБЛОНІВ ---
    def create_text_io_fields(self, parent):
        """Побудова спільних полів вводу та виводу"""
        io_frame = ttk.Frame(parent)
        io_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        io_frame.columnconfigure(0, weight=1)
        io_frame.columnconfigure(1, weight=1)

        input_lf = ttk.LabelFrame(io_frame, text="Вхідний текст")
        input_lf.grid(row=0, column=0, padx=5, sticky="nsew")
        input_text = tk.Text(input_lf, height=8, wrap=tk.WORD)
        input_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        output_lf = ttk.LabelFrame(io_frame, text="Результат")
        output_lf.grid(row=0, column=1, padx=5, sticky="nsew")
        output_text = tk.Text(output_lf, height=8, wrap=tk.WORD)
        output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Контекстні меню
        self.apply_context_menu(input_text)
        self.apply_context_menu(output_text)

        return input_text, output_text

    def create_status_bar(self, parent):
        """Побудова інформаційного рядка стану"""
        sb_frame = ttk.Frame(parent)
        sb_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=2)
        status_label = ttk.Label(sb_frame, text="Символів: 0 | Мова: Визначається автоматично", relief=tk.SUNKEN,
                                 anchor=tk.W)
        status_label.pack(fill=tk.X)
        return status_label

    def update_status_bar(self, widget, label, text_content):
        length = len(text_content.strip())
        lang = "UK" if any(c in ALPHABET_UK for c in text_content.upper()) else "EN"
        if length == 0:
            label.config(text="Символів: 0 | Готовий до роботи")
        else:
            label.config(text=f"Символів: {length} | Ймовірна мова: {lang}")

    def apply_context_menu(self, widget):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Копіювати", command=lambda: widget.event_generate("<<Copy>>"))
        menu.add_command(label="Вставити", command=lambda: widget.event_generate("<<Paste>>"))
        menu.add_command(label="Вирізати", command=lambda: widget.event_generate("<<Cut>>"))
        menu.add_separator()
        menu.add_command(label="Виділити все", command=lambda: widget.tag_add(tk.SEL, "1.0", tk.END))
        menu.add_command(label="Очистити", command=lambda: widget.delete("1.0", tk.END))

        widget.bind("<Button-3>", lambda e: menu.tk_popup(e.x_root, e.y_root))
        widget.bind("<Control-a>", lambda e: widget.tag_add(tk.SEL, "1.0", tk.END))

    # ==========================================
    #             ВКЛАДКА: ЦЕЗАР
    # ==========================================
    def build_caesar_tab(self):
        # Поля IO
        self.c_input, self.c_output = self.create_text_io_fields(self.caesar_tab)
        self.c_status = self.create_status_bar(self.caesar_tab)
        self.c_input.bind("<KeyRelease>", lambda e: self.update_status_bar(self.c_input, self.c_status,
                                                                           self.c_input.get("1.0", tk.END)))

        # Керування параметрами
        control_frame = ttk.LabelFrame(self.caesar_tab, text="Параметри та операції")
        control_frame.pack(fill=tk.X, pady=5)

        ttk.Label(control_frame, text="Зсув (ключ):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.c_key = ttk.Entry(control_frame, width=10)
        self.c_key.insert(0, "3")
        self.c_key.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # Кнопки
        ttk.Button(control_frame, text="Шифрувати", command=lambda: self.run_cipher("Caesar", False)).grid(row=0,
                                                                                                           column=2,
                                                                                                           padx=5,
                                                                                                           pady=5)
        ttk.Button(control_frame, text="Дешифрувати", command=lambda: self.run_cipher("Caesar", True)).grid(row=0,
                                                                                                            column=3,
                                                                                                            padx=5,
                                                                                                            pady=5)
        ttk.Button(control_frame, text="Запустити Brute Force", command=self.run_caesar_brute).grid(row=0, column=4,
                                                                                                    padx=5, pady=5)

        # Секція Brute Force (Діаграма з таблицею)
        bf_frame = ttk.LabelFrame(self.caesar_tab, text="Панель криптоаналізу (Brute Force)")
        bf_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.bf_tree = ttk.Treeview(bf_frame, columns=("Shift", "Text"), show="headings", height=6)
        self.bf_tree.heading("Shift", text="Зсув (Ключ)")
        self.bf_tree.heading("Text", text="Результат розшифрування")
        self.bf_tree.column("Shift", width=100, stretch=tk.NO)
        self.bf_tree.column("Text", stretch=tk.YES)

        scroll = ttk.Scrollbar(bf_frame, orient="vertical", command=self.bf_tree.yview)
        self.bf_tree.configure(yscrollcommand=scroll.set)

        self.bf_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.bf_tree.bind("<ButtonRelease-1>", self.on_bf_row_select)

    def run_caesar_brute(self):
        txt = self.c_input.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showwarning("Помилка", "Вхідний текст порожній.")
            return

        # Очистка таблиці
        for item in self.bf_tree.get_children():
            self.bf_tree.delete(item)

        results = self.controller.caesar.brute_force(txt)
        for shift, decrypted in results:
            self.bf_tree.insert("", tk.END, values=(shift, decrypted))

    def on_bf_row_select(self, event):
        selected = self.bf_tree.focus()
        if selected:
            values = self.bf_tree.item(selected, "values")
            self.c_key.delete(0, tk.END)
            self.c_key.insert(0, values[0])
            self.c_output.delete("1.0", tk.END)
            self.c_output.insert(tk.END, values[1])

    # ==========================================
    #             ВКЛАДКА: АТБАШ
    # ==========================================
    def build_atbash_tab(self):
        self.a_input, self.a_output = self.create_text_io_fields(self.atbash_tab)
        self.a_status = self.create_status_bar(self.atbash_tab)
        self.a_input.bind("<KeyRelease>", lambda e: self.update_status_bar(self.a_input, self.a_status,
                                                                           self.a_input.get("1.0", tk.END)))

        control_frame = ttk.LabelFrame(self.atbash_tab, text="Операції")
        control_frame.pack(fill=tk.X, pady=5)

        ttk.Button(control_frame, text="Шифрувати/Дешифрувати (Самообернений)",
                   command=lambda: self.run_cipher("Atbash", False)).pack(side=tk.LEFT, padx=10, pady=10)

    # ==========================================
    #             ВКЛАДКА: ВІЖЕНЕР
    # ==========================================
    def build_vigenere_tab(self):
        self.v_input, self.v_output = self.create_text_io_fields(self.vigenere_tab)
        self.v_status = self.create_status_bar(self.vigenere_tab)
        self.v_input.bind("<KeyRelease>", lambda e: self.update_status_bar(self.v_input, self.v_status,
                                                                           self.v_input.get("1.0", tk.END)))

        # Керування
        control_frame = ttk.LabelFrame(self.vigenere_tab, text="Параметри")
        control_frame.pack(fill=tk.X, pady=5)

        ttk.Label(control_frame, text="Ключ (слово):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.v_key = ttk.Entry(control_frame, width=25)
        self.v_key.insert(0, "КЛЮЧ")
        self.v_key.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Button(control_frame, text="Шифрувати", command=lambda: self.run_cipher("Vigenere", False)).grid(row=0,
                                                                                                             column=2,
                                                                                                             padx=5,
                                                                                                             pady=5)
        ttk.Button(control_frame, text="Дешифрувати", command=lambda: self.run_cipher("Vigenere", True)).grid(row=0,
                                                                                                              column=3,
                                                                                                              padx=5,
                                                                                                              pady=5)
        ttk.Button(control_frame, text="Оцінити довжину ключа (IC)", command=self.run_vigenere_analysis).grid(row=0,
                                                                                                              column=4,
                                                                                                              padx=5,
                                                                                                              pady=5)

        # Панель побудови графіка IC (Криптоаналіз)
        analysis_frame = ttk.LabelFrame(self.vigenere_tab, text="Аналіз індексу збігів (IC Graph)")
        analysis_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.ic_canvas = tk.Canvas(analysis_frame, bg="white", height=150)
        self.ic_canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def run_vigenere_analysis(self):
        txt = self.v_input.get("1.0", tk.END).strip()
        if len(txt) < 10:
            messagebox.showwarning("Помилка", "Текст закороткий для статистичного аналізу.")
            return

        lang = "UK" if any(c in ALPHABET_UK for c in txt.upper()) else "EN"
        results = self.controller.kasiski.calc_key_length(txt, lang)

        self.ic_canvas.delete("all")
        if not results:
            return

        # Побудова графіка в Canvas
        w = self.ic_canvas.winfo_width()
        h = self.ic_canvas.winfo_height()

        margin_x, margin_y = 40, 30
        plot_w = w - (2 * margin_x)
        plot_h = h - (2 * margin_y)

        # Осі координатні
        self.ic_canvas.create_line(margin_x, h - margin_y, w - margin_x, h - margin_y, width=2, fill="black")  # X
        self.ic_canvas.create_line(margin_x, margin_y, margin_x, h - margin_y, width=2, fill="black")  # Y

        self.ic_canvas.create_text(w / 2, h - 10, text="Оціночна довжина ключа", fill="black", font=("Arial", 9))
        self.ic_canvas.create_text(15, h / 2, text="IC", fill="black", angle=90, font=("Arial", 9))

        max_ic = max(r[1] for r in results) if results else 0.1
        max_y_val = max(0.08, max_ic * 1.2)

        # Точки
        points = []
        for idx, (length, ic) in enumerate(results):
            x = margin_x + (idx * (plot_w / max(1, len(results) - 1)))
            y = (h - margin_y) - (ic / max_y_val) * plot_h
            points.append((x, y))

            # Малювання точок
            self.ic_canvas.create_oval(x - 4, y - 4, x + 4, y + 4, fill="red", outline="darkred")
            self.ic_canvas.create_text(x, h - margin_y + 12, text=str(length), font=("Arial", 8))
            self.ic_canvas.create_text(x, y - 10, text=f"{ic:.3f}", font=("Arial", 7), fill="blue")

        # З'єднання ліній
        for i in range(len(points) - 1):
            self.ic_canvas.create_line(points[i][0], points[i][1], points[i + 1][0], points[i + 1][1], fill="gray",
                                       width=1)

    # ==========================================
    #             ВКЛАДКА: ПЛЕЙФЕР
    # ==========================================
    def build_playfair_tab(self):
        self.p_input, self.p_output = self.create_text_io_fields(self.playfair_tab)
        self.p_status = self.create_status_bar(self.playfair_tab)
        self.p_input.bind("<KeyRelease>", lambda e: self.update_status_bar(self.p_input, self.p_status,
                                                                           self.p_input.get("1.0", tk.END)))

        control_frame = ttk.LabelFrame(self.playfair_tab, text="Параметри")
        control_frame.pack(fill=tk.X, pady=5)

        ttk.Label(control_frame, text="Ключ (кодове слово):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.p_key = ttk.Entry(control_frame, width=25)
        self.p_key.insert(0, "ХАРЬКОВ")
        self.p_key.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Button(control_frame, text="Шифрувати", command=lambda: self.run_cipher("Playfair", False)).grid(row=0,
                                                                                                             column=2,
                                                                                                             padx=5,
                                                                                                             pady=5)
        ttk.Button(control_frame, text="Дешифрувати", command=lambda: self.run_cipher("Playfair", True)).grid(row=0,
                                                                                                              column=3,
                                                                                                              padx=5,
                                                                                                              pady=5)

        # Візуалізація матриці
        self.matrix_frame = ttk.LabelFrame(self.playfair_tab, text="Ключовий квадрат Плейфера")
        self.matrix_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.lbl_matrix_grid = []

    def draw_playfair_matrix(self, key, lang):
        for widget in self.matrix_frame.winfo_children():
            widget.destroy()

        matrix = self.controller.playfair.build_matrix(key, lang)
        size = self.controller.playfair.size

        # Побудова інтерактивної таблиці в інтерфейсі
        tbl_frame = ttk.Frame(self.matrix_frame)
        tbl_frame.pack(pady=10)

        for r in range(size):
            for c in range(size):
                lbl = tk.Label(tbl_frame, text=matrix[r][c], width=6, height=2,
                               relief="ridge", bg="#f0f0f0", font=("Arial", 11, "bold"))
                lbl.grid(row=r, column=c, padx=2, pady=2)

    # ==========================================
    #             ВКЛАДКА: АНАЛІЗ
    # ==========================================
    def build_frequency_tab(self):
        # Окремий інтерфейс для аналізу
        top_frame = ttk.Frame(self.frequency_tab)
        top_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        top_frame.columnconfigure(0, weight=1)

        input_lf = ttk.LabelFrame(top_frame, text="Текст для криптоаналізу")
        input_lf.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.f_input = tk.Text(input_lf, height=8, wrap=tk.WORD)
        self.f_input.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.apply_context_menu(self.f_input)

        btn_frame = ttk.Frame(self.frequency_tab)
        btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(btn_frame, text="Побудувати гістограму частотності", command=self.run_frequency_analysis).pack(
            padx=10, side=tk.LEFT)

        self.chart_canvas = tk.Canvas(self.frequency_tab, bg="white", height=250)
        self.chart_canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def run_frequency_analysis(self):
        txt = self.f_input.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showwarning("Помилка", "Текст відсутній.")
            return

        lang = "UK" if any(c in ALPHABET_UK for c in txt.upper()) else "EN"
        actual_freqs = self.controller.freq_analyzer.analyze(txt, lang)

        standard_freqs = self.controller.freq_analyzer.freq_ukr if lang == "UK" else self.controller.freq_analyzer.freq_eng

        self.chart_canvas.delete("all")

        # Отримання 12 найчастіших символів для відображення на графіку
        sorted_chars = sorted(standard_freqs.keys(), key=lambda x: standard_freqs[x], reverse=True)[:12]

        w = self.chart_canvas.winfo_width()
        h = self.chart_canvas.winfo_height()

        margin_x, margin_y = 50, 40
        plot_w = w - (2 * margin_x)
        plot_h = h - (2 * margin_y)

        # Осі координат
        self.chart_canvas.create_line(margin_x, h - margin_y, w - margin_x, h - margin_y, width=2, fill="black")
        self.chart_canvas.create_line(margin_x, margin_y, margin_x, h - margin_y, width=2, fill="black")

        max_val = max(max(standard_freqs.values()), max(actual_freqs.values(), default=0))
        max_y_val = max_val * 1.1

        col_width = plot_w / (len(sorted_chars) * 2)

        for idx, char in enumerate(sorted_chars):
            # Стандартна частота (сірий стовпчик)
            std_val = standard_freqs.get(char, 0)
            std_h = (std_val / max_y_val) * plot_h
            x1 = margin_x + (idx * col_width * 2) + 5
            y1 = h - margin_y - std_h
            x2 = x1 + col_width - 2
            y2 = h - margin_y
            self.chart_canvas.create_rectangle(x1, y1, x2, y2, fill="#d0d0d0", outline="gray")

            # Фактична частота з тексту (синій стовпчик)
            act_val = actual_freqs.get(char, 0.0)
            act_h = (act_val / max_y_val) * plot_h
            x1_act = x2 + 1
            y1_act = h - margin_y - act_h
            x2_act = x1_act + col_width - 2
            y2_act = h - margin_y
            self.chart_canvas.create_rectangle(x1_act, y1_act, x2_act, y2_act, fill="#4f81bd", outline="darkblue")

            # Підписи літер
            self.chart_canvas.create_text((x1 + x2_act) / 2, h - margin_y + 12, text=char, font=("Arial", 10, "bold"))

        # Легенда
        self.chart_canvas.create_rectangle(w - 180, 10, w - 165, 25, fill="#d0d0d0")
        self.chart_canvas.create_text(w - 110, 17, text="Норма мови", font=("Arial", 8))
        self.chart_canvas.create_rectangle(w - 180, 30, w - 165, 45, fill="#4f81bd")
        self.chart_canvas.create_text(w - 100, 37, text="Ваш шифртекст", font=("Arial", 8))

    # --- ЗАПУСК ШИФРІВ ---
    def run_cipher(self, cipher_type, decrypt=False):
        try:
            if cipher_type == "Caesar":
                text = self.c_input.get("1.0", tk.END).strip()
                key = self.c_key.get().strip()
                res = self.controller.process_crypto(cipher_type, text, key, decrypt)

                self.c_output.delete("1.0", tk.END)
                self.c_output.insert(tk.END, res)
                self.update_status_bar(self.c_input, self.c_status, text)

            elif cipher_type == "Atbash":
                text = self.a_input.get("1.0", tk.END).strip()
                res = self.controller.process_crypto(cipher_type, text, None, decrypt)

                self.a_output.delete("1.0", tk.END)
                self.a_output.insert(tk.END, res)
                self.update_status_bar(self.a_input, self.a_status, text)

            elif cipher_type == "Vigenere":
                text = self.v_input.get("1.0", tk.END).strip()
                key = self.v_key.get().strip()
                res = self.controller.process_crypto(cipher_type, text, key, decrypt)

                self.v_output.delete("1.0", tk.END)
                self.v_output.insert(tk.END, res)
                self.update_status_bar(self.v_input, self.v_status, text)

            elif cipher_type == "Playfair":
                text = self.p_input.get("1.0", tk.END).strip()
                key = self.p_key.get().strip()
                res = self.controller.process_crypto(cipher_type, text, key, decrypt)

                self.p_output.delete("1.0", tk.END)
                self.p_output.insert(tk.END, res)

                lang = self.controller.playfair.detect_lang(text)
                self.draw_playfair_matrix(key, lang)
                self.update_status_bar(self.p_input, self.p_status, text)

        except Exception as e:
            messagebox.showerror("Помилка обробки", str(e))


# ==========================================
#                   MAIN
# ==========================================

if __name__ == "__main__":
    controller = AppController()
    app = CryptoApp(controller)
    app.mainloop()