#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDir>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_authWindow(nullptr)
    , m_credentialsModel(nullptr)
    , m_proxyModel(nullptr)
{
    ui->setupUi(this);
    
    setWindowTitle(tr("Менеджер паролей"));
    
    // Инициализация моделей
    setupModels();
    
    // Установка соединений
    setupConnections();
    
    // Создаем окно аутентификации
    m_authWindow = new AuthWindow(this);
    
    // Подключаем сигналы
    connect(m_authWindow, &AuthWindow::authenticationSuccessful, this, &MainWindow::onAuthenticated);
    connect(m_authWindow, &AuthWindow::securityViolationDetected, this, &MainWindow::onSecurityViolation);
}

MainWindow::~MainWindow()
{
    // Очищаем пин-код из памяти
    m_currentPinCode.fill('0');
    delete ui;
}

void MainWindow::showEvent(QShowEvent *event)
{
    QMainWindow::showEvent(event);
    
    // При первом показе главного окна отображаем окно аутентификации
    static bool firstShow = true;
    if (firstShow) {
        firstShow = false;
        
        // Скрываем главное окно до аутентификации
        hide();
        
        // Показываем окно аутентификации
        if (m_authWindow->exec() == QDialog::Rejected) {
            // Если окно аутентификации было закрыто без успешной аутентификации
            close();
        } else {
            // После успешной аутентификации показываем главное окно
            show();
        }
    }
}

void MainWindow::setupModels()
{
    // Создаем модель данных
    m_credentialsModel = new CredentialsModel(this);
    
    // Создаем прокси-модель для фильтрации
    m_proxyModel = new QSortFilterProxyModel(this);
    m_proxyModel->setSourceModel(m_credentialsModel);
    m_proxyModel->setFilterKeyColumn(0); // Фильтруем по колонке URL
    
    // Устанавливаем модель для таблицы
    ui->credentialsTable->setModel(m_proxyModel);
    
    // Настраиваем отображение таблицы
    ui->credentialsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

void MainWindow::setupConnections()
{
    // Подключаем поисковое поле
    connect(ui->searchLineEdit, &QLineEdit::textChanged,
            this, &MainWindow::onSearchTextChanged);
    
    // Подключаем выбор строки в таблице
    connect(ui->credentialsTable->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::onItemSelected);
}

void MainWindow::loadCredentials()
{
    // Загружаем данные из зашифрованного файла
    QString vaultFile = QDir::currentPath() + "/vault.enc";
    
    qDebug() << "Loading encrypted file: " << vaultFile;
    
    if (m_credentialsModel->loadEncryptedData(vaultFile, m_currentPinCode)) {
        // Обновляем отображение
        m_proxyModel->invalidate();
    } else {
        QMessageBox::critical(this, tr("Ошибка"), tr("Не удалось загрузить данные из хранилища. Проверьте пин-код и целостность файла."));
    }
}

void MainWindow::onAuthenticated(const QString &pincode)
{
    // Сохраняем пин-код
    m_currentPinCode = pincode;
    
    // Загружаем данные
    loadCredentials();
}

void MainWindow::onSecurityViolation(const QString &message)
{
    QMessageBox::critical(this, tr("Нарушение безопасности"), message);
    close();
}

void MainWindow::onSearchTextChanged(const QString &text)
{
    m_proxyModel->setFilterFixedString(text);
}

void MainWindow::onItemSelected(const QModelIndex &index)
{
    if (!index.isValid())
        return;
    
    // Получаем соответствующую строку исходной модели
    int sourceRow = m_proxyModel->mapToSource(index).row();
    
    // Показываем детали
    showCredentialDetails(sourceRow);
}

void MainWindow::showCredentialDetails(int row)
{
    if (row < 0 || row >= m_credentialsModel->rowCount())
        return;
    
    // Запрашиваем пин-код для дешифрования
    AuthWindow authDlg(this);
    authDlg.setWindowTitle(tr("Подтвердите доступ"));
    
    if (authDlg.exec() != QDialog::Accepted)
        return;
    
    QString pinCode = authDlg.getPinCode();
    
    // Проверяем пин-код
    if (pinCode != m_currentPinCode) {
        QMessageBox::warning(this, tr("Ошибка"), tr("Неверный пин-код"));
        return;
    }
    
    // Получаем и отображаем данные учетной записи
    ui->urlLineEdit->setText(m_credentialsModel->getUrl(row));
    ui->loginLineEdit->setText(m_credentialsModel->getLogin(row, pinCode));
    ui->passwordLineEdit->setText(m_credentialsModel->getPassword(row, pinCode));
}
