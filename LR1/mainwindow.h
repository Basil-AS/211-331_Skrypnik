#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStandardItemModel>
#include <QSortFilterProxyModel>
#include <QMessageBox>
#include <QString>
#include <QTimer>
#include <windows.h>
#include "credentialsmodel.h"
#include "authwindow.h"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void showEvent(QShowEvent *event) override;

private slots:
    void onAuthenticated(const QString &pincode);
    void onSecurityViolation(const QString &message);
    void onSearchTextChanged(const QString &text);
    void onItemSelected(const QModelIndex &index);

private:
    Ui::MainWindow *ui;
    AuthWindow *m_authWindow;
    CredentialsModel *m_credentialsModel;
    QSortFilterProxyModel *m_proxyModel;
    QString m_currentPinCode;

    void setupModels();
    void setupConnections();
    void loadCredentials();
    void showCredentialDetails(int row);
};
#endif // MAINWINDOW_H
