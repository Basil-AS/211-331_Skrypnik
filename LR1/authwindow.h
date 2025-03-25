#ifndef AUTHWINDOW_H
#define AUTHWINDOW_H

#include <QDialog>
#include <QMessageBox>
#include <QString>
#include <QDebug>
#include <windows.h>

namespace Ui {
class AuthWindow;
}

class AuthWindow : public QDialog
{
    Q_OBJECT

public:
    explicit AuthWindow(QWidget *parent = nullptr);
    ~AuthWindow();
    
    QString getPinCode() const;
    bool eventFilter(QObject *watched, QEvent *event) override;

signals:
    void authenticationSuccessful(const QString &pincode);
    void securityViolationDetected(const QString &message);

private slots:
    void on_loginButton_clicked();
    void checkDebuggerPresence();
    void checkExecutableIntegrity();

private:
    Ui::AuthWindow *ui;
    QString m_pinCode;
    
    // Функции проверки безопасности
    bool isDebuggerPresent();
    bool verifyExecutableIntegrity();
    void showSecurityAlert(const QString &message);
};

#endif // AUTHWINDOW_H
