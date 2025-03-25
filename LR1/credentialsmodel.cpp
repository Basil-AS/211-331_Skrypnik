#include "credentialsmodel.h"

CredentialsModel::CredentialsModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

int CredentialsModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    
    return m_credentials.size();
}

int CredentialsModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid())
        return 0;
    
    return 3; // URL, Login, Password
}

QVariant CredentialsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_credentials.size())
        return QVariant();
        
    if (role == Qt::DisplayRole || role == Qt::EditRole) {
        const Credential &cred = m_credentials.at(index.row());
        
        switch (index.column()) {
            case 0: // URL
                return cred.url;
            case 1: // Login
                return QString("••••••••");
            case 2: // Password
                return QString("••••••••");
            default:
                return QVariant();
        }
    }
    
    return QVariant();
}

QVariant CredentialsModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        switch (section) {
            case 0:
                return QString("URL");
            case 1:
                return QString("Логин");
            case 2:
                return QString("Пароль");
            default:
                return QVariant();
        }
    }
    
    return QVariant();
}

QByteArray CredentialsModel::generateKey(const QString &pincode) const
{
    // Используем SHA-256 для создания ключа из пароля
    QByteArray hashData = QCryptographicHash::hash(
        pincode.toUtf8(), QCryptographicHash::Sha256);
    
    return hashData;
}

bool CredentialsModel::loadEncryptedData(const QString &filename, const QString &pincode)
{
    QFile file(filename);
    if (!file.open(QIODevice::ReadOnly)) {
        qDebug() << "Не удалось открыть файл" << filename;
        return false;
    }
    
    QByteArray encryptedData = file.readAll();
    file.close();
    
    // Генерируем ключ из пинкода
    QByteArray key = generateKey(pincode);
    
    // Дешифруем данные файла
    QByteArray decryptedData;
    try {
        decryptedData = decryptData(encryptedData, key);
    } catch (const std::exception &e) {
        qDebug() << "Ошибка при дешифровании данных: " << e.what();
        return false;
    }
    
    if (decryptedData.isEmpty()) {
        qDebug() << "Дешифрованные данные пусты. Возможно неверный пинкод.";
        return false;
    }
    
    // Парсим JSON
    QJsonParseError jsonError;
    QJsonDocument doc = QJsonDocument::fromJson(decryptedData, &jsonError);
    
    if (jsonError.error != QJsonParseError::NoError) {
        qDebug() << "Ошибка при разборе JSON: " << jsonError.errorString();
        return false;
    }
    
    if (!doc.isArray()) {
        qDebug() << "Документ JSON не является массивом";
        return false;
    }
    
    QJsonArray credArray = doc.array();
    m_credentials.clear();
    
    for (const QJsonValue &val : credArray) {
        QJsonObject obj = val.toObject();
        QString url = obj["url"].toString();
        QByteArray encLogin = QByteArray::fromBase64(obj["login"].toString().toLatin1());
        QByteArray encPassword = QByteArray::fromBase64(obj["password"].toString().toLatin1());
        
        m_credentials.append(Credential(url, encLogin, encPassword));
    }
    
    return true;
}

QByteArray CredentialsModel::decryptCredential(const QByteArray &encryptedData, const QString &pincode) const
{
    QByteArray key = generateKey(pincode);
    return decryptData(encryptedData, key);
}

bool CredentialsModel::isUrlMatching(int row, const QString &searchText) const
{
    if (row < 0 || row >= m_credentials.size())
        return false;
        
    return m_credentials[row].url.contains(searchText, Qt::CaseInsensitive);
}

QString CredentialsModel::getUrl(int row) const
{
    if (row < 0 || row >= m_credentials.size())
        return QString();
        
    return m_credentials[row].url;
}

QString CredentialsModel::getLogin(int row, const QString &pincode) const
{
    if (row < 0 || row >= m_credentials.size())
        return QString();
    
    QByteArray decryptedLogin;
    try {
        decryptedLogin = decryptCredential(m_credentials[row].encryptedLogin, pincode);
    } catch (const std::exception &e) {
        qDebug() << "Ошибка при дешифровании логина: " << e.what();
        return QString();
    }
    
    return QString::fromUtf8(decryptedLogin);
}

QString CredentialsModel::getPassword(int row, const QString &pincode) const
{
    if (row < 0 || row >= m_credentials.size())
        return QString();
    
    QByteArray decryptedPassword;
    try {
        decryptedPassword = decryptCredential(m_credentials[row].encryptedPassword, pincode);
    } catch (const std::exception &e) {
        qDebug() << "Ошибка при дешифровании пароля: " << e.what();
        return QString();
    }
    
    return QString::fromUtf8(decryptedPassword);
}

QByteArray CredentialsModel::encryptData(const QByteArray &data, const QByteArray &key) const
{
    // Использование OpenSSL для шифрования AES-256-CBC
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Не удалось создать контекст шифрования");
    }
    
    // Создаем вектор инициализации (IV)
    QByteArray iv(16, 0); // 16 байт нулей для простоты
    
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, 
                               reinterpret_cast<const unsigned char*>(key.constData()),
                               reinterpret_cast<const unsigned char*>(iv.constData()))) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ошибка инициализации шифрования");
    }
    
    int outlen1, outlen2;
    QByteArray encrypted(data.size() + EVP_MAX_BLOCK_LENGTH, 0);
    
    if (1 != EVP_EncryptUpdate(ctx,
                              reinterpret_cast<unsigned char*>(encrypted.data()), &outlen1,
                              reinterpret_cast<const unsigned char*>(data.constData()), data.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ошибка шифрования");
    }
    
    if (1 != EVP_EncryptFinal_ex(ctx, 
                                reinterpret_cast<unsigned char*>(encrypted.data()) + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ошибка финализации шифрования");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    encrypted.resize(outlen1 + outlen2);
    
    // Добавляем IV к зашифрованным данным для использования при дешифровании
    QByteArray result = iv + encrypted;
    return result;
}

QByteArray CredentialsModel::decryptData(const QByteArray &encryptedData, const QByteArray &key) const
{
    if (encryptedData.size() <= 16) { // должен быть хотя бы IV (16 байт)
        throw std::runtime_error("Ошибка: шифрованные данные слишком коротки");
    }
    
    // Извлекаем IV из начала данных
    QByteArray iv = encryptedData.left(16);
    QByteArray actualData = encryptedData.mid(16);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Не удалось создать контекст дешифрования");
    }
    
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL,
                               reinterpret_cast<const unsigned char*>(key.constData()),
                               reinterpret_cast<const unsigned char*>(iv.constData()))) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ошибка инициализации дешифрования");
    }
    
    QByteArray decrypted(actualData.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int outlen1, outlen2;
    
    if (1 != EVP_DecryptUpdate(ctx,
                              reinterpret_cast<unsigned char*>(decrypted.data()), &outlen1,
                              reinterpret_cast<const unsigned char*>(actualData.constData()), actualData.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ошибка дешифрования");
    }
    
    if (1 != EVP_DecryptFinal_ex(ctx,
                                reinterpret_cast<unsigned char*>(decrypted.data()) + outlen1, &outlen2)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Ошибка финализации дешифрования. Возможно неверный ключ.");
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    decrypted.resize(outlen1 + outlen2);
    return decrypted;
}
