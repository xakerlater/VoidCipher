from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
import struct, zlib, secrets, os, base64, getpass, shutil, tempfile
from colorama import Fore, Style, init

#  (GitHub: xakerlater) (TG: @Rigew)  ꧁•⊹٭Гусь٭⊹•꧂  (TG: @Rigew) (GitHub: xakerlater)
#   - Привет, дорогой друг! Я - Гусь, создатель данного "софта".
#   Проект представляет собой защищенный инструмент для общения, созданный в образовательных целях.
#   В качестве алгоритма шифрования используется надежный стандарт AES (ранее тестировался Fernet, но был заменен для оптимизации и минимизации следов).
#   Это первая демонстрационная версия, в будущих версиях я буду добавлять новые способы шифровки, или дам возможность "прятать" зашифрованные данные в текст и тд

class TextEncryptor:
    def __init__(self, password: str):
        self.password = password.encode()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**16, r=8, p=1)
        return kdf.derive(self.password)

    def _encrypt_bytes(self, data: bytes) -> bytes:
        """Внутренний метод для шифрования байтов."""
        salt = os.urandom(16)
        key = self._derive_key(salt)

        # Сжатие и добавление стойкого криптомусора
        compressed_data = zlib.compress(data)
        padding_length = secrets.randbelow(925) + 100  # от 100 до 1024 байт
        padding = os.urandom(padding_length)
        payload = struct.pack(">I", len(compressed_data)) + compressed_data + padding

        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        encrypted_payload = aesgcm.encrypt(nonce, payload, None)

        version_byte = b'\x01'  # Версия 1: AES-GCM
        return version_byte + salt + nonce + encrypted_payload

    def encrypt(self, text: str) -> str:
        """Шифрует текстовую строку."""
        encrypted_bytes = self._encrypt_bytes(text.encode('utf-8'))
        return base64.urlsafe_b64encode(encrypted_bytes).decode('ascii')

    def _decrypt_bytes(self, decoded_data: bytes) -> bytes:
        """Внутренний метод для расшифровки байтов."""
        if not decoded_data:
            raise ValueError("Пустые входные данные.")

        # Проверяем первый байт на наличие версии
        version = decoded_data[0]
        is_new_format = version == 1

        if is_new_format:
            if len(decoded_data) < 1 + 16 + 12:  # version + salt + nonce
                raise ValueError("Данные повреждены: слишком короткий текст для формата v1.")
            salt = decoded_data[1:17]
            encrypted_body = decoded_data[17:]
            return self._decrypt_gcm_payload(salt, encrypted_body)
        else:
            # Обработка старого формата без байта версии
            if len(decoded_data) < 16 + 12:  # salt + nonce
                raise ValueError("Данные повреждены или имеют неизвестный формат.")

            salt = decoded_data[:16]
            encrypted_body = decoded_data[16:]

            if encrypted_body.startswith(b"gAAAAAB"):
                raise ValueError("Сообщение старое (Fernet), дешифровка отключена в целях безопасности.")

            print("Предупреждение: используется устаревший формат шифрования без версионирования.")
            return self._decrypt_gcm_payload(salt, encrypted_body)

    def _decrypt_gcm_payload(self, salt: bytes, encrypted_body: bytes) -> bytes:
        """Расшифровывает полезную нагрузку AES-GCM и возвращает исходные байты."""
        if len(encrypted_body) < 12:
            raise ValueError("Данные повреждены: отсутствует nonce.")

        nonce = encrypted_body[:12]
        encrypted_payload = encrypted_body[12:]
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)

        try:
            decrypted_payload = aesgcm.decrypt(nonce, encrypted_payload, None)
        except InvalidTag:
            raise ValueError("Ошибка: Неверный пароль или данные повреждены!")

        # Распаковка
        if len(decrypted_payload) < 4:
            raise ValueError("Ошибка протокола: пустой пакет.")
        data_len = struct.unpack(">I", decrypted_payload[:4])[0]
        if len(decrypted_payload) < 4 + data_len:
            raise ValueError("Ошибка целостности: данные обрезаны.")
        compressed_data = decrypted_payload[4:4 + data_len]
        return zlib.decompress(compressed_data)

    def decrypt(self, encrypted_text: str) -> str:
        """Расшифровывает текстовую строку."""
        try:
            decoded_data = base64.urlsafe_b64decode(encrypted_text)
        except Exception:
            raise ValueError("Неверный формат Base64.")

        decrypted_bytes = self._decrypt_bytes(decoded_data)
        try:
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Ошибка: не удалось декодировать данные как текст. Возможно, это зашифрованный файл.")

    def encrypt_file(self, input_path: str, output_path: str):
        """Шифрует файл. Внимание: файл полностью загружается в память."""
        try:
            with open(input_path, 'rb') as f:
                file_data = f.read()
            encrypted_bytes = self._encrypt_bytes(file_data)
            with open(output_path, 'wb') as f:
                f.write(base64.urlsafe_b64encode(encrypted_bytes))
        except FileNotFoundError:
            raise ValueError(f"Файл не найден: {input_path}")
        except Exception as e:
            raise RuntimeError(f"Ошибка при шифровании файла: {e}")

    def decrypt_file(self, input_path: str, output_path: str):
        """Расшифровывает файл. Внимание: файл полностью загружается в память."""
        try:
            with open(input_path, 'rb') as f:
                encrypted_data_b64 = f.read()
            decoded_data = base64.urlsafe_b64decode(encrypted_data_b64)
            decrypted_file_data = self._decrypt_bytes(decoded_data)
            with open(output_path, 'wb') as f:
                f.write(decrypted_file_data)
        except FileNotFoundError:
            raise ValueError(f"Файл не найден: {input_path}")
        except (ValueError, RuntimeError) as e:
            raise e

    def encrypt_folder(self, input_folder: str, output_file: str):
        """Шифрует целую папку, архивируя ее в zip-файл."""
        if not os.path.isdir(input_folder):
            raise ValueError(f"Папка не найдена: {input_folder}")

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_name = os.path.join(temp_dir, 'archive_to_encrypt')
            # Создаем zip-архив папки
            try:
                archive_path = shutil.make_archive(archive_name, 'zip', input_folder)
            except Exception as e:
                raise RuntimeError(f"Не удалось создать архив: {e}")

            # Шифруем созданный архив
            self.encrypt_file(archive_path, output_file)

    def decrypt_folder(self, input_file: str, output_folder: str):
        """Расшифровывает файл в папку."""
        if not os.path.isfile(input_file):
            raise ValueError(f"Файл не найден: {input_file}")

        with tempfile.TemporaryDirectory() as temp_dir:
            decrypted_archive_path = os.path.join(temp_dir, 'decrypted_archive.zip')

            # Расшифровываем файл во временный архив
            self.decrypt_file(input_file, decrypted_archive_path)

            os.makedirs(output_folder, exist_ok=True)
            shutil.unpack_archive(decrypted_archive_path, output_folder, 'zip')

def display_banner():
    """Отображает красивый баннер."""
    print(Fore.CYAN + "=======================================================")
    print(Fore.GREEN + r"""""" + Fore.YELLOW + "v1.1 - Secure Crypto Tool by Goose")
    print(Fore.CYAN + "=======================================================" + Style.RESET_ALL)

def main():
    """Основная функция для запуска интерфейса."""
    init(autoreset=True)
    os.system('cls' if os.name == 'nt' else 'clear')
    display_banner()

    try:
        user_password = getpass.getpass(Fore.YELLOW + "Введите пароль для сессии: " + Style.RESET_ALL)
        if not user_password:
            print(Fore.RED + "\nПароль не может быть пустым. Выход.")
            return
        encryptor = TextEncryptor(user_password)
        print(Fore.GREEN + "Пароль принят. Инициализация прошла успешно.")
        input(Fore.WHITE + "Нажмите Enter, чтобы продолжить...")
    except (KeyboardInterrupt, EOFError):
        print("\n" + Fore.RED + "Ввод отменен. Выход.")
        return

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        display_banner()
        print(Fore.CYAN + "Выберите действие:")
        print(f" {Fore.GREEN}1.{Style.RESET_ALL} Зашифровать текст")
        print(f" {Fore.GREEN}2.{Style.RESET_ALL} Расшифровать текст")
        print(f" {Fore.GREEN}3.{Style.RESET_ALL} Зашифровать файл")
        print(f" {Fore.GREEN}4.{Style.RESET_ALL} Расшифровать файл")
        print(f" {Fore.GREEN}5.{Style.RESET_ALL} Зашифровать папку")
        print(f" {Fore.GREEN}6.{Style.RESET_ALL} Расшифровать папку")
        print(f" {Fore.RED}7.{Style.RESET_ALL} Выход")
        
        choice = input(Fore.YELLOW + "\nВаш выбор: " + Style.RESET_ALL)

        try:
            if choice == "1":
                message = input("Введите текст для шифрования: ")
                encrypted = encryptor.encrypt(message)
                print(Fore.GREEN + "\nЗашифрованный текст:")
                print(Fore.WHITE + encrypted)
            elif choice == "2":
                encrypted_text = input("Введите текст для дешифрования: ")
                decrypted = encryptor.decrypt(encrypted_text)
                print(Fore.GREEN + "\nРасшифрованный текст:")
                print(Fore.WHITE + decrypted)
            elif choice == "3":
                in_file = input("Введите путь к исходному файлу: ").strip('"')
                out_file = input("Введите путь для сохранения зашифрованного файла: ").strip('"')
                encryptor.encrypt_file(in_file, out_file)
                print(Fore.GREEN + f"\nФайл '{in_file}' успешно зашифрован в '{out_file}'.")
            elif choice == "4":
                in_file = input("Введите путь к зашифрованному файлу: ").strip('"')
                out_file = input("Введите путь для сохранения расшифрованного файла: ").strip('"')
                encryptor.decrypt_file(in_file, out_file)
                print(Fore.GREEN + f"\nФайл '{in_file}' успешно расшифрован в '{out_file}'.")
            elif choice == "5":
                in_folder = input("Введите путь к исходной папке: ").strip('"')
                out_file = input("Введите путь для сохранения зашифрованного архива: ").strip('"')
                encryptor.encrypt_folder(in_folder, out_file)
                print(Fore.GREEN + f"\nПапка '{in_folder}' успешно зашифрована в файл '{out_file}'.")
            elif choice == "6":
                in_file = input("Введите путь к зашифрованному архиву: ").strip('"')
                out_folder = input("Введите путь для сохранения расшифрованной папки: ").strip('"')
                encryptor.decrypt_folder(in_file, out_folder)
                print(Fore.GREEN + f"\nФайл '{in_file}' успешно расшифрован в папку '{out_folder}'.")
            elif choice == "7":
                print(Fore.YELLOW + "Безопасный выход.")
                break
            else:
                print(Fore.RED + "Неверный выбор, попробуйте снова.")
        
        except (ValueError, RuntimeError, FileNotFoundError) as e:
            print(Fore.RED + f"\nПроизошла ошибка: {e}")
        except Exception as e:
            print(Fore.RED + f"\nПроизошла неизвестная ошибка: {e}")

        input(Fore.WHITE + "\nНажмите Enter, чтобы вернуться в меню...")

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n" + Fore.RED + "Программа прервана пользователем. Выход.")
