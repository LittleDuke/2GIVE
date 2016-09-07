#ifndef IMPORTKEYDIALOG_H
#define IMPORTKEYDIALOG_H

#include <QDialog>

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

namespace Ui {
    class ImportKeyDialog;
}
class AddressTableModel;

/** Dialog for editing an address and associated information.
 */
class ImportKeyDialog : public QDialog
{
    Q_OBJECT

public:

    explicit ImportKeyDialog(QWidget *parent = 0);
    ~ImportKeyDialog();

    void setModel(AddressTableModel *model);
    void loadRow(int row);

    void accept();

    QString getAddress() const;
    void setAddress(const QString &address);
    void setPrivateKey(const QString &privkey);
    void setLabel(const QString &label);

private:
    bool saveCurrentRow();

    Ui::ImportKeyDialog *ui;
    QDataWidgetMapper *mapper;
    AddressTableModel *model;

    QString label;
    QString address;
    QString privateKey;
};

#endif // IMPORTKEYDIALOG_H
