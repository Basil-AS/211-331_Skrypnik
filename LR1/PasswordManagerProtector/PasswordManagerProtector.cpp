#include <iostream>
#include <windows.h>
#include <string>

// Для Windows API функций (DebugActiveProcess и т.д.)
#pragma comment(lib, "advapi32.lib")

// Для справки https://anti-debug.checkpoint.com/techniques/interactive.html#self-debugging

// Используем обычный main (без аргументов для упрощения)
extern "C" int main()
{
    // Установка кодировки для корректного отображения кириллицы
    SetConsoleCP(1251);         // Кодировка ввода - кириллица Windows
    SetConsoleOutputCP(CP_UTF8); // Кодировка вывода - UTF-8
    
    // Настраиваем шрифт консоли для лучшего отображения кириллицы
    CONSOLE_FONT_INFOEX cfi;
    cfi.cbSize = sizeof(cfi);
    cfi.nFont = 0;
    cfi.dwFontSize.X = 0;
    cfi.dwFontSize.Y = 16; // Размер шрифта
    cfi.FontFamily = FF_DONTCARE;
    cfi.FontWeight = FW_NORMAL;
    wcscpy(cfi.FaceName, L"Consolas"); // Шрифт с поддержкой кириллицы
    SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), FALSE, &cfi);
    
    // Изменяем заголовок окна консоли
    SetConsoleTitleA("Менеджер паролей: Защита от отладки");
    // 1. Запустить password manager и получить его PID
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Путь к исполняемому файлу нашего менеджера паролей
    char cmdLine[] = "LR1.exe";

    std::cout << "[*] Запуск менеджера паролей с защитой от отладки..." << std::endl;

    if(CreateProcessA(
                NULL, cmdLine,
                NULL, NULL,
                TRUE, NULL,
                NULL,NULL,
                &si, &pi)){
        std::cout << "[+] CreateProcess() успешно!" << std::endl;
        std::cout << "[+] ID процесса = " << std::dec << pi.dwProcessId << std::endl;
    } else {
        DWORD error = GetLastError();
        std::cout << "[-] CreateProcess() ОШИБКА! Код: " << std::dec << error << std::endl;
        std::cout << "[-] Убедитесь, что файл LR1.exe находится в текущей директории." << std::endl;
        system("pause");
        return 1;
    }

    // 2. Подключиться к процессу как отладчик
    bool isAttached = DebugActiveProcess(pi.dwProcessId);
    if(!isAttached) {
        DWORD lastError = GetLastError();
        std::cout << "[-] DebugActiveProcess() ОШИБКА! Код: " << std::dec << lastError << std::endl;
        system("pause");
        return 1;
    } else {
        std::cout << "[+] DebugActiveProcess() успешно!" << std::endl;
        std::cout << "[+] Защита от отладки активирована." << std::endl;
    }

    // 3. Пропускать поступающие сигналы отладки
    std::cout << "[*] Менеджер паролей запущен и защищен. Работает обработка отладочных событий..." << std::endl;
    std::cout << "[*] Пожалуйста, не закрывайте это окно до завершения работы с менеджером паролей." << std::endl;

    DEBUG_EVENT debugEvent;
    while(true) {
        bool result1 = WaitForDebugEvent(&debugEvent, INFINITE);
        if (result1) {
            // Проверка завершения процесса
            if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                std::cout << "[*] Менеджер паролей завершил работу." << std::endl;
                break;
            }
            
            bool result2 = ContinueDebugEvent(debugEvent.dwProcessId,
                                  debugEvent.dwThreadId,
                                  DBG_CONTINUE);
                                  
            if (!result2) {
                std::cout << "[-] ContinueDebugEvent() ОШИБКА! Код: " << std::dec << GetLastError() << std::endl;
            }
        } else {
            std::cout << "[-] WaitForDebugEvent() ОШИБКА! Код: " << std::dec << GetLastError() << std::endl;
            break;
        }
    }

    std::cout << "[*] Программа-протектор завершает работу..." << std::endl;
    system("pause");
    return 0;
}
