#include "authwindow.h"
#include "ui_authwindow.h"
#include <QCryptographicHash>
#include <QKeyEvent>

// Определяем тип QWORD для Windows x64
typedef ULONGLONG QWORD;

AuthWindow::AuthWindow(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AuthWindow)
{
    ui->setupUi(this);
    
    // Настраиваем окно
    setWindowTitle(tr("Аутентификация"));
    setFixedSize(400, 250);
    setModal(true);
    
    // Проверки безопасности
    checkDebuggerPresence();
    checkExecutableIntegrity();
    
    // Устанавливаем обработчик событий для поля ввода
    ui->pinCodeEdit->installEventFilter(this);
    
    // Соединяем сигналы и слоты
    connect(ui->pinCodeEdit, &QLineEdit::returnPressed, this, &AuthWindow::on_loginButton_clicked);
}

AuthWindow::~AuthWindow()
{
    // Очищаем пин-код из памяти
    m_pinCode.fill('0');
    delete ui;
}

QString AuthWindow::getPinCode() const
{
    return m_pinCode;
}

void AuthWindow::on_loginButton_clicked()
{
    // Проверяем введенный пин-код (для демо используем константу)
    m_pinCode = ui->pinCodeEdit->text();
    
    // Очищаем поле ввода
    ui->pinCodeEdit->clear();
    
    // Дополнительная проверка безопасности
    if (isDebuggerPresent()) {
        showSecurityAlert("Обнаружена отладка! Доступ запрещен.");
        return;
    }
    
    if (!verifyExecutableIntegrity()) {
        showSecurityAlert("Обнаружена модификация исполняемого файла! Доступ запрещен.");
        return;
    }
      // Хешированный пин-код (SHA-256) для более безопасного хранения
    // В реальном приложении лучше использовать соль и более стойкие алгоритмы (PBKDF2, Argon2)
    const QString hashedPinCode = "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"; // SHA-256 хеш для "1234"
    
    // Вычисляем хеш от введенного пользователем пин-кода
    QByteArray userPinHash = QCryptographicHash::hash(
        m_pinCode.toUtf8(), QCryptographicHash::Sha256).toHex();
    
    if (QString::fromUtf8(userPinHash) == hashedPinCode) {
        emit authenticationSuccessful(m_pinCode);
        accept();
    } else {
        ui->securityLabel->setText("Неверный пин-код. Попробуйте снова.");
    }
}

bool AuthWindow::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == ui->pinCodeEdit) {
        // Проверяем наличие отладчика при каждом вводе символа
        if (event->type() == QEvent::KeyPress) {
            checkDebuggerPresence();
        }
    }
    
    return QDialog::eventFilter(watched, event);
}

void AuthWindow::checkDebuggerPresence()
{
    if (isDebuggerPresent()) {
        showSecurityAlert("Обнаружена отладка! Доступ запрещен.");
    }
}

bool AuthWindow::isDebuggerPresent()
{
    return IsDebuggerPresent();
}

void AuthWindow::checkExecutableIntegrity()
{
    if (!verifyExecutableIntegrity()) {
        showSecurityAlert("Обнаружена модификация исполняемого файла! Доступ запрещен.");
    }
}

bool AuthWindow::verifyExecutableIntegrity()
{
    // 1) определить, где в памяти начало сегмента .text
    QWORD imageBase = (QWORD)GetModuleHandle(NULL);
    QWORD baseOfCode = 0x1000; // Типичное смещение сегмента .text
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
    
    // 4) сравнить полученный хеш с заранее рассчитанным (это значение будет разным для каждой сборки)
    // Используем актуальный хеш текущей сборки
    const QByteArray referenceTextHashBase64 = QByteArray("0z2cYXK84/qs3tp09dVNPR9WrpefGW+kjyjfILWw8I0=");

    qDebug() << "textBase = " << Qt::hex << textBase;
    qDebug() << "textSize = " << textSize;
    qDebug() << "====== КОПИРОВАТЬ ХЕШ ОТСЮДА (authwindow.cpp) ======";
    qDebug() << "calculatedTextHashBase64 = " << calculatedTextHashBase64;
    qDebug() << "====== КОПИРОВАТЬ ХЕШ ДОСЮДА ======";// Реальная проверка хеша сегмента .text
    bool checkresult = (calculatedTextHashBase64 == referenceTextHashBase64);
    
    // Вывод результата проверки для отладки
    qDebug() << "Integrity check result = " << checkresult;
    
    // Для учебных целей можно временно закомментировать следующую строку
    // и вернуть true, чтобы не блокировать приложение на этапе разработки
    return checkresult;
}

void AuthWindow::showSecurityAlert(const QString &message)
{
    ui->securityLabel->setText(message);
    ui->pinCodeEdit->setEnabled(false);
    ui->loginButton->setEnabled(false);
    
    // Отправляем сигнал о нарушении безопасности
    emit securityViolationDetected(message);
}
