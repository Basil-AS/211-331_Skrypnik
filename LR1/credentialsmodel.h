#ifndef CREDENTIALSMODEL_H
#define CREDENTIALSMODEL_H

#include <QAbstractTableModel>
#include <QVector>
#include <QString>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QFile>
#include <QCryptographicHash>
#include <QDebug>
#include <openssl/evp.h>
#include <openssl/err.h>

class Credential {
public:
    QString url;
    QByteArray encryptedLogin;
    QByteArray encryptedPassword;
    
    Credential(const QString& u, const QByteArray& l, const QByteArray& p) : 
        url(u), encryptedLogin(l), encryptedPassword(p) {}
};

class CredentialsModel : public QAbstractTableModel {
    Q_OBJECT
    
public:
    explicit CredentialsModel(QObject *parent = nullptr);
    
    // Базовые методы QAbstractTableModel
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
      // Методы для работы с шифрованием
    bool loadEncryptedData(const QString &filename, const QString &pincode);
    QByteArray decryptCredential(const QByteArray &encryptedData, const QString &pincode) const;
    bool isUrlMatching(int row, const QString &searchText) const;
    
    // Методы для доступа к данным
    const QVector<Credential>& credentials() const { return m_credentials; }
    QString getUrl(int row) const;
    QString getLogin(int row, const QString &pincode) const;
    QString getPassword(int row, const QString &pincode) const;
    
private:
    QVector<Credential> m_credentials;
    
    // Методы шифрования/дешифрования
    QByteArray generateKey(const QString &pincode) const;
    QByteArray encryptData(const QByteArray &data, const QByteArray &key) const;
    QByteArray decryptData(const QByteArray &encryptedData, const QByteArray &key) const;
};

#endif // CREDENTIALSMODEL_H
