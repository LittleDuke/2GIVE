#include "editcontactdialog.h"
#include "ui_editcontactdialog.h"
#include "contacttablemodel.h"
#include "guiutil.h"

#include <QDataWidgetMapper>
#include <QMessageBox>

EditContactDialog::EditContactDialog(Mode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::EditContactDialog), mapper(0), mode(mode), model(0)
{
    ui->setupUi(this);

    GUIUtil::setupAddressWidget(ui->addressEdit, this);

    switch(mode)
    {
    case NewSendingAddress:
        setWindowTitle(tr("New Contact Info"));
        break;
    case EditSendingAddress:
        setWindowTitle(tr("Edit Contact Info"));
        break;
    }

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}

EditContactDialog::~EditContactDialog()
{
    delete ui;
}

void EditContactDialog::setModel(ContactTableModel *model)
{
    this->model = model;
    mapper->setModel(model);
    mapper->addMapping(ui->labelEdit, ContactTableModel::Label);
    mapper->addMapping(ui->addressEdit, ContactTableModel::Address);
    mapper->addMapping(ui->emailEdit, ContactTableModel::Email);
    mapper->addMapping(ui->urlEdit, ContactTableModel::URL);
}

void EditContactDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
}

bool EditContactDialog::saveCurrentRow()
{
    if(!model)
        return false;
    switch(mode)
    {
    case NewSendingAddress:
        address = model->addRow(
                ui->labelEdit->text(),
                ui->addressEdit->text(),
                ui->emailEdit->text(),
                ui->urlEdit->text());
//        address = ui->addressEdit->text();
        label = ui->labelEdit->text();
        email = ui->emailEdit->text();
        url = ui->urlEdit->text();

        break;
    case EditSendingAddress:
//        if(mapper->submit())
//        {
        address = ui->addressEdit->text();
        label = ui->labelEdit->text();
        email = ui->emailEdit->text();
        url = ui->urlEdit->text();
//            }
        break;
    }


    return !address.isEmpty();
}

void EditContactDialog::accept()
{
    if(!model)
        return;
    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case ContactTableModel::DUPLICATE_ADDRESS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered address \"%1\" is already in the address book.").arg(ui->addressEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case ContactTableModel::INVALID_ADDRESS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered address \"%1\" is not a valid 2GiveCoin address.").arg(ui->addressEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        case ContactTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        case ContactTableModel::KEY_GENERATION_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("New key generation failed."),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        case ContactTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        }

        return;
    }
    QDialog::accept();
}

int EditContactDialog::getID() const
{
    return id;
}

QString EditContactDialog::getAddress() const
{
    return address;
}

void EditContactDialog::setAddress(const QString &address)
{
    this->address = address;
    ui->addressEdit->setText(address);
}

QString EditContactDialog::getLabel() const
{
    return label;
}

void EditContactDialog::setLabel(const QString &label)
{
    this->label = label;
    ui->labelEdit->setText(label);
}

QString EditContactDialog::getEmail() const
{
    return email;
}

void EditContactDialog::setEmail(const QString &email)
{
    this->email = email;
    ui->emailEdit->setText(email);
}

QString EditContactDialog::getURL() const
{
    return url;
}

void EditContactDialog::setURL(const QString &url)
{
    this->url = url;
    ui->urlEdit->setText(url);
}
