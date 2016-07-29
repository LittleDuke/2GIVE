#ifndef EDITCONTACTDIALOG_H
#define EDITCONTACTDIALOG_H

#include <QDialog>

QT_BEGIN_NAMESPACE
class QDataWidgetMapper;
QT_END_NAMESPACE

namespace Ui {
    class EditContactDialog;
}
class ContactTableModel;

/** Dialog for editing an address and associated information.
 */
class EditContactDialog : public QDialog
{
    Q_OBJECT

public:
    enum Mode {
        NewSendingAddress,
        EditSendingAddress
    };

    explicit EditContactDialog(Mode mode, QWidget *parent = 0);
    ~EditContactDialog();

    void setModel(ContactTableModel *model);
    void loadRow(int row);

    void accept();

    int getID() const;
    QString getAddress() const;
    QString getLabel() const;
    void setAddress(const QString &address);
    void setLabel(const QString &label);
    QString getEmail() const;
    void setEmail(const QString &email);
    QString getURL() const;
    void setURL(const QString &url);


private:
    bool saveCurrentRow();

    Ui::EditContactDialog *ui;
    QDataWidgetMapper *mapper;
    Mode mode;
    ContactTableModel *model;

    int     id;
    QString address;
    QString label;
    QString email;
    QString url;
};

#endif // EDITCONTACTDIALOG_H
