import unittest

from main import (
    CaesarCipher,
    AtbashCipher,
    VigenereCipher,
    PlayfairCipher,
    FrequencyAnalyzer,
    KasiskiAnalyzer
)


class ClassicalCiphersTest(unittest.TestCase):

    def setUp(self):
        self.caesar = CaesarCipher()
        self.atbash = AtbashCipher()
        self.vigenere = VigenereCipher()
        self.playfair = PlayfairCipher()
        self.freq_analyzer = FrequencyAnalyzer()
        self.kasiski = KasiskiAnalyzer()

    # ==========================================
    #             ШИФР ЦЕЗАРЯ (01 - 04)
    # ==========================================

    def test_01_caesar_encrypt_en(self):
        """Тест 1: Шифрування англійського тексту стандартним додатним зсувом"""
        plaintext = "HELLO WORLD"
        shift = 3
        ciphertext = self.caesar.encrypt(plaintext, shift)
        self.assertEqual(ciphertext, "KHOOR ZRUOG")

    def test_02_caesar_decrypt_en(self):
        """Тест 2: Дешифрування англійського тексту стандартним додатним зсувом"""
        ciphertext = "KHOOR ZRUOG"
        shift = 3
        decrypted = self.caesar.decrypt(ciphertext, shift)
        self.assertEqual(decrypted, "HELLO WORLD")

    def test_03_caesar_negative_shift(self):
        """Тест 3: Шифрування зсувом у від’ємному напрямку (лівий зсув)"""
        plaintext = "KHOOR"
        shift = -3
        self.assertEqual(self.caesar.encrypt(plaintext, shift), "HELLO")

    def test_04_caesar_invalid_key_exception(self):
        """Тест 4: Перевірка виникнення помилки при передачі нечислового ключа"""
        with self.assertRaises(ValueError):
            self.caesar.encrypt("TEXT", "invalid_key")

    # ==========================================
    #              ШИФР АТБАШ (05 - 07)
    # ==========================================

    def test_05_atbash_encrypt_en(self):
        """Тест 5: Перевірка симетричного шифрування Атбаш (латиниця)"""
        plaintext = "HELLO"
        ciphertext = self.atbash.encrypt(plaintext)
        self.assertEqual(ciphertext, "SVOOL")

    def test_06_atbash_decrypt_en(self):
        """Тест 6: Перевірка самооберненості алгоритму шифрування Атбаш"""
        ciphertext = "SVOOL"
        decrypted = self.atbash.decrypt(ciphertext)
        self.assertEqual(decrypted, "HELLO")

    def test_07_atbash_encrypt_uk(self):
        """Тест 7: Перевірка роботи шифру Атбаш для кириличного алфавіту"""
        plaintext = "АБВ"
        # Для українського алфавіту з 33 літер: А (0) -> Я (32), Б (1) -> Ю (31), В (2) -> Ь (30)
        ciphertext = self.atbash.encrypt(plaintext)
        self.assertEqual(ciphertext, "ЯЮЬ")

    # ==========================================
    #            ШИФР ВІЖЕНЕРА (08 - 10)
    # ==========================================

    def test_08_vigenere_encrypt_en(self):
        """Тест 8: Поліалфавітне шифрування Віженера англійським ключовим словом"""
        plaintext = "HELLO"
        key = "KEY"
        ciphertext = self.vigenere.encrypt(plaintext, key)
        self.assertEqual(ciphertext, "RIJVS")

    def test_09_vigenere_decrypt_en(self):
        """Тест 9: Розшифрування поліалфавітного тексту Віженера"""
        ciphertext = "RIJVS"
        key = "KEY"
        decrypted = self.vigenere.decrypt(ciphertext, key)
        self.assertEqual(decrypted, "HELLO")

    def test_10_vigenere_invalid_key_exception(self):
        """Тест 10: Стійкість до введення неалфавітної послідовності як ключа"""
        with self.assertRaises(ValueError):
            self.vigenere.encrypt("TEXT", "!!!")

    # ==========================================
    #            ШИФР ПЛЕЙФЕРА (11 - 12)
    # ==========================================

    def test_11_playfair_matrix_generation_en(self):
        """Тест 11: Автоматична заміна символу J на I в матриці Playfair"""
        matrix = self.playfair.build_matrix("PLAYFAIR", "EN")
        has_j = any('J' in row for row in matrix)
        self.assertFalse(has_j)
        self.assertEqual(self.playfair.size, 5)

    def test_12_playfair_encrypt_decrypt_cycle(self):
        """Тест 12: Повний цикл симетричного перетворення для біграмного шифру"""
        plaintext = "INSTRUMENT"
        key = "KEYWORD"
        ciphertext = self.playfair.encrypt(plaintext, key)
        decrypted = self.playfair.decrypt(ciphertext, key)
        self.assertEqual(decrypted, "INSTRUMENT")

    # ==========================================
    #             АНАЛІЗАТОРИ (13 - 14)
    # ==========================================

    def test_13_frequency_analysis_accuracy(self):
        """Тест 13: Перевірка точності обчислення відносної частоти літер"""
        text = "AAAA BBBB"
        freqs = self.freq_analyzer.analyze(text, "EN")
        self.assertIn('A', freqs)
        self.assertIn('B', freqs)
        self.assertAlmostEqual(freqs['A'], 50.0)
        self.assertAlmostEqual(freqs['B'], 50.0)

    def test_14_index_of_coincidence_calculation(self):
        """Тест 14: Розрахунок індексу збігів для рівномірно розподіленого тексту"""
        flat_text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ic = self.kasiski.index_of_coincidence(flat_text, "EN")
        self.assertTrue(ic < 0.04)


if __name__ == "__main__":
    unittest.main()