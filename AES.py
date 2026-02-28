from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
import struct, zlib, secrets, os, base64, getpass #активировать getpass можно по желанию

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

    def encrypt(self, text: str) -> str:
        salt = os.urandom(16)
        key = self._derive_key(salt)
        
        # Сжатие и добавление стойкого криптомусора
        compressed_data = zlib.compress(text.encode())
        padding_length = secrets.randbelow(925) + 100  # от 100 до 1024 байт
        padding = os.urandom(padding_length)
        payload = struct.pack(">I", len(compressed_data)) + compressed_data + padding
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12) 
        encrypted_payload = aesgcm.encrypt(nonce, payload, None)
        
        final_bytes = salt + nonce + encrypted_payload
        return base64.urlsafe_b64encode(final_bytes).decode()

    def decrypt(self, encrypted_text: str) -> str:
        try: decoded_data = base64.urlsafe_b64decode(encrypted_text)
        except Exception: raise ValueError("Неверный формат Base64.")
            
        if len(decoded_data) < 16: raise ValueError("Данные повреждены.")
            
        salt = decoded_data[:16]
        encrypted_body = decoded_data[16:]
        
        if encrypted_body.startswith(b"gAAAAAB"): # Старый формат / если увидел признак Fernet
            raise ValueError("Сообщение старое, дешифровка возможна, но отключена в целях безопасности.")

        return self._decrypt_gcm(salt, encrypted_body) # Если это новый формат AES-GCM

    def _decrypt_gcm(self, salt: bytes, encrypted_body: bytes) -> str:
        if len(encrypted_body) < 28:
            raise ValueError("Данные повреждены: слишком короткий текст.")
            
        nonce = encrypted_body[:12]
        encrypted_payload = encrypted_body[12:]
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        
        try: decrypted_payload = aesgcm.decrypt(nonce, encrypted_payload, None)
        except InvalidTag: raise ValueError("Ошибка: Неверный пароль или данные повреждены!")
            
        return self._unpack_payload(decrypted_payload)

    def _unpack_payload(self, decrypted_payload: bytes) -> str:
        if len(decrypted_payload) < 4:
            raise ValueError("Ошибка протокола: пустой пакет.")
        data_len = struct.unpack(">I", decrypted_payload[:4])[0]
        if len(decrypted_payload) < 4 + data_len:
            raise ValueError("Ошибка целостности: данные обрезаны.")
        compressed_data = decrypted_payload[4:4+data_len]
        return zlib.decompress(compressed_data).decode()

# Запуск "демонстрации" для тестов, можно удалить, изменить - творите, что хотите
if __name__ == "__main__":
    user_password = input("Введите пароль (для шифрования и дешифрования): ") # или getpass.getpass("Введите пароль: ") для скрытого ввода пароля
    encryptor = TextEncryptor(user_password)

    while True:
        print("\nВыберите действие:")
        print("1. Зашифровать текст")
        print("2. Расшифровать текст")
        print("3. Выход")
        choice = input("Ваш выбор: ")

        if choice == "1":
            message = input("Введите текст для шифрования: ")
            print(f"Зашифрованный текст:\n{encryptor.encrypt(message)}")
        elif choice == "2":
            encrypted_text = input("Введите текст для дешифрования: ")
            try: print(f"Расшифрованный текст:\n{encryptor.decrypt(encrypted_text)}")
            except ValueError as e: print(f"{e}")
            except Exception: print("Произошла неизвестная ошибка при расшифровке.")
        elif choice == "3":
            print("Безопасный выход.")
            break
        else:

            print("Неверный выбор, попробуйте снова.")


