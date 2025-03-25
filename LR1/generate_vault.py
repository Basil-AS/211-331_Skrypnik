#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Скрипт для генерации зашифрованного файла паролей.
Использует библиотеку cryptography для AES-256 шифрования.
"""

import json
import base64
import os
import sys
import hashlib
from datetime import datetime

# Проверяем наличие библиотеки cryptography
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    print("ПРЕДУПРЕЖДЕНИЕ: Библиотека cryptography не установлена.")
    print("Чтобы установить её, выполните: pip install cryptography")
    print("Будет использоваться упрощенное шифрование для демонстрации.\n")

def encrypt_aes_256_cbc(data, key):
    """
    Шифруем данные с помощью AES-256-CBC
    """
    if CRYPTOGRAPHY_AVAILABLE:
        # Генерируем случайный IV
        iv = os.urandom(16)
        
        # Создаем шифр
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Добавляем padding к данным
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Шифруем данные
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Возвращаем IV и зашифрованные данные
        return iv + encrypted_data
    else:
        # Простая имитация шифрования, только для демонстрации!
        # Не использовать в реальных проектах!
        # В реальном проекте используйте полноценную библиотеку cryptography
        
        # Используем первые 16 байт ключа как IV для демонстрации
        iv = key[:16]
        
        # XOR каждый байт данных с соответствующим байтом ключа (циклически)
        result = bytearray()
        for i, byte in enumerate(data):
            if isinstance(byte, str):  # Python 2/3 совместимость
                byte = ord(byte)
            result.append(byte ^ key[i % len(key)])
        
        return iv + bytes(result)

def encrypt_with_pincode(data, pincode):
    """
    Шифруем данные с использованием пинкода в качестве ключа
    """
    # Создаем хеш SHA-256 от пинкода для использования в качестве ключа
    key = hashlib.sha256(pincode.encode('utf-8')).digest()
    
    # Шифруем данные
    return encrypt_aes_256_cbc(data, key)

def generate_vault(pincode="1234"):
    """
    Генерирует зашифрованный файл с учетными данными
    """
    # Создаем тестовые данные
    credentials = [
        {"url": "https://vk.com",                "login": "user1@mail.ru",           "password": "SecurePass1!"},
        {"url": "https://ok.ru",                 "login": "user2@ok.ru",             "password": "OKPass2@"},
        {"url": "https://yandex.ru",             "login": "user3@yandex.ru",         "password": "Yandex3#"},
        {"url": "https://mail.ru",               "login": "mail_user@mail.ru",       "password": "MailRu4$"},
        {"url": "https://sberbank.ru",           "login": "finance_user@sberbank.ru","password": "Sberbank9)"},
        {"url": "https://tinkoff.ru",            "login": "tinkoff_user@tinkoff.ru", "password": "Tinkoff0!"},
        {"url": "https://ozon.ru",               "login": "shop_user@ozon.ru",       "password": "OzonPass11@"},
        {"url": "https://wildberries.ru",        "login": "wb_user@wildberries.ru",  "password": "Wildberries12#"},
        {"url": "https://avito.ru",              "login": "avito_user@avito.ru",     "password": "Avito13$"},
        {"url": "https://hh.ru",                 "login": "hh_user@hh.ru",           "password": "HHjob14%"},
        {"url": "https://2gis.ru",               "login": "gis_user@2gis.ru",        "password": "2GISmap15&"},
        {"url": "https://drom.ru",               "login": "drom_user@drom.ru",       "password": "DromAuto16*"}
    ]

    
    # Зашифруем логины и пароли для второго уровня защиты
    for cred in credentials:
        # Шифруем логин и пароль с тем же пинкодом
        cred["login"] = base64.b64encode(
            encrypt_with_pincode(cred["login"].encode('utf-8'), pincode)
        ).decode('utf-8')
        
        cred["password"] = base64.b64encode(
            encrypt_with_pincode(cred["password"].encode('utf-8'), pincode)
        ).decode('utf-8')
    
    # Сериализуем в JSON
    json_data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    
    # Шифруем весь JSON с пинкодом для первого уровня защиты
    encrypted_data = encrypt_with_pincode(json_data, pincode)
    
    # Сохраняем в файл
    with open("vault.enc", "wb") as f:
        f.write(encrypted_data)
    
    # Печатаем информацию о файле
    print(f"Файл vault.enc сгенерирован с {len(credentials)} записями.")
    print(f"Размер файла: {os.path.getsize('vault.enc')} байт")
    print(f"Дата создания: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}")
    print(f"Пин-код для доступа: {pincode}")
    
    if not CRYPTOGRAPHY_AVAILABLE:
        print("\nВНИМАНИЕ: Файл создан с упрощенным шифрованием (только для демонстрации)!")
        print("Для полноценного шифрования установите библиотеку cryptography:")
        print("pip install cryptography")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        pincode = sys.argv[1]
    else:
        pincode = "1234"  # Пинкод по умолчанию
    
    generate_vault(pincode)
    print("Для генерации с другим пинкодом: python generate_vault.py <пинкод>")
