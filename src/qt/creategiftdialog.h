// Copyright 2016 Strength in Numbers Foundation


#ifndef CREATEGIFTDIALOG_H
#define CREATEGIFTDIALOG_H

#include <QDialog>

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

namespace Ui {
    class CreateGiftDialog;
}
class GiftCardTableModel;

/** Dialog for editing an address and associated information.
 */
class CreateGiftDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        NewGiftAddress,
        EditGiftAddress
    };

    explicit CreateGiftDialog(Mode mode, QWidget *parent = 0);
    ~CreateGiftDialog();

    void setModel(GiftCardTableModel *model);
    void loadRow(int row);

    void accept();

    QString getAddress() const;
    void setAddress(const QString &address);
private:
    bool saveCurrentRow();

    Ui::CreateGiftDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    GiftCardTableModel *model;

    QString address;
};

#endif // CreateGiftDialog_H
