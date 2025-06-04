
// cgctl – клиент к драйверу CryptoGuard
// Автор: Скрыпник Василий Александрович (211‑331)
// Изменения только во внешнем интерфейсе; логика вызовов драйвера сохранена.

﻿#include <windows.h>
#include <iostream>
#include <string>

const std::wstring kFilePath = L"C:\Lab2\cg_test.enc";

void WriteToFile() {
    HANDLE hFile = CreateFileW(
        kFilePath.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] Failed to open the file for recording: " << GetLastError() << std::endl;
        return;
    }

    // Переход в конец файла
    SetFilePointer(hFile, 0, nullptr, FILE_END);

    std::string input;
    std::cout << "Enter string to write: ";
    std::getline(std::cin, input);

    DWORD bytesWritten;
    if (!WriteFile(hFile, input.c_str(), static_cast<DWORD>(input.length()), &bytesWritten, nullptr)) {
        std::wcerr << L"[!] Record error: " << GetLastError() << std::endl;
    }
    else {
        std::wcout << L"[+] Bytes are recorded: " << bytesWritten << std::endl;
    }

    CloseHandle(hFile);
}

void ReadFromFile() {
    HANDLE hFile = CreateFileW(
        kFilePath.c_str(),
        GENERIC_READ,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] Failed to open a reading file: " << GetLastError() << std::endl;
        return;
    }

    char buffer[1024] = {};
    DWORD bytesRead;

    if (!ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
        std::wcerr << L"[!] Error Read: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "[+] Read bytes: " << bytesRead << std::endl;
        std::cout << "The contents of the file:\n" << buffer << std::endl;
    }

    CloseHandle(hFile);
}

int main() {
    SetConsoleOutputCP(CP_UTF8); // Для корректного вывода кириллицы

    int choice;
    while (true) {
        std::cout << "\n[1] Read file\n"
            << "[2] Write at the end of file\n"
            << "[0] Exit\n"
            << "Your chiose: ";
        std::cin >> choice;
        std::cin.ignore(); // Удаляем \n после ввода

        switch (choice) {
        case 1:
            ReadFromFile();
            break;
        case 2:
            WriteToFile();
            break;
        case 0:
            std::cout << "Exit..." << std::endl;
            return 0;
        default:
            std::cout << "[!] Wrong choise\n";
        }
    }
}
