#include "mainwindow.h"

#include <QApplication>
#include <QMessageBox>
#include <windows.h>
#include <QCryptographicHash>
#include <QDebug>

// Определяем тип QWORD для Windows x64
typedef ULONGLONG QWORD;

// Проверка наличия отладчика
bool isDebuggerPresent() {
    return IsDebuggerPresent();
}

// Проверка целостности исполняемого файла
bool checkExecutableIntegrity() {
    // 1) определить, где в памяти начало сегмента .text
    QWORD imageBase = (QWORD)GetModuleHandle(NULL);
    QWORD baseOfCode = 0x1000;
    QWORD textBase = imageBase + baseOfCode;

    // 2) определить, какой он длины
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
    PIMAGE_NT_HEADERS peHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
        imageBase + dosHeader->e_lfanew);
    QWORD textSize = peHeader->OptionalHeader.SizeOfCode;

    // 3) от бинарного блока в диапазоне textBase...(textBase+textSize) посчитать хеш
    QByteArray textSegmentContents = QByteArray(reinterpret_cast<char*>(textBase), textSize);
    QByteArray calculatedTextHash = QCryptographicHash::hash(
        textSegmentContents, QCryptographicHash::Sha256);
    QByteArray calculatedTextHashBase64 = calculatedTextHash.toBase64();
    
    // 4) сравнить полученный хеш с заранее рассчитанным
    const QByteArray referenceTextHashBase64 = QByteArray("0z2cYXK84/qs3tp09dVNPR9WrpefGW+kjyjfILWw8I0=");
    
    qDebug() << "textBase = " << Qt::hex << textBase;
    qDebug() << "textSize = " << textSize;
    qDebug() << "====== КОПИРОВАТЬ ХЕШ ОТСЮДА ======";
    qDebug() << "calculatedTextHashBase64 = " << calculatedTextHashBase64;
    qDebug() << "====== КОПИРОВАТЬ ХЕШ ДОСЮДА ======";
    
    // Реальная проверка хеша сегмента .text
    bool checkresult = (calculatedTextHashBase64 == referenceTextHashBase64);
    
    // Вывод результата проверки для отладки
    qDebug() << "Integrity check result = " << checkresult;
    
    return checkresult;
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
      // Проверка аргументов командной строки
    bool calculateHashOnly = false;
    bool skipIntegrityCheck = false;
    for (int i = 1; i < argc; ++i) {
        QString arg = argv[i];
        if (arg == "--calculate-hash") {
            calculateHashOnly = true;
        }
        if (arg == "--dev-mode" || arg == "--skip-integrity") {
            skipIntegrityCheck = true;
        }
    }
    
    // Если запрошен только расчет хеша, пропускаем проверки безопасности
    if (!calculateHashOnly) {
        // Проверка наличия отладчика
        if (isDebuggerPresent()) {
            QMessageBox::critical(nullptr, "Предупреждение безопасности", 
                "Обнаружен отладчик! Приложение не может быть запущено в режиме отладки.");
            return 1;
        }
    }    // Проверка целостности исполняемого файла
    if (!calculateHashOnly && !skipIntegrityCheck && !checkExecutableIntegrity()) {
        QMessageBox::critical(nullptr, "Предупреждение безопасности", 
            "Обнаружена модификация исполняемого файла! Приложение не может быть запущено.");
        return 2;
    }
    
    // Если запрошен только расчет хеша, выходим после вывода данных
    if (calculateHashOnly) {
        return 0;
    }
    
    MainWindow w;
    w.show();
    return a.exec();
}
