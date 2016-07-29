#include "importkeydialog.h"
#include "ui_importkeydialog.h"
#include "addresstablemodel.h"
#include "guiutil.h"

#include <QDataWidgetMapper>
#include <QMessageBox>

ImportKeyDialog::ImportKeyDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportKeyDialog), mapper(0), model(0)
{
    ui->setupUi(this);

//    GUIUtil::setupAddressWidget(ui->addressEdit, this);


    setWindowTitle(tr("Import Private Key"));
    ui->privateKeyEdit->setEnabled(true);
    ui->addressEdit->setEnabled(false);
    ui->progressBar->setVisible(false);

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}

ImportKeyDialog::~ImportKeyDialog()
{
    delete ui;
}

void ImportKeyDialog::setModel(AddressTableModel *model)
{
    this->model = model;
    mapper->setModel(model);
    mapper->addMapping(ui->labelEdit, AddressTableModel::Label);
    mapper->addMapping(ui->privateKeyEdit, AddressTableModel::Address);
}

void ImportKeyDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
}

bool ImportKeyDialog::saveCurrentRow()
{
    if(!model)
        return false;

    address = model->addRow(
                AddressTableModel::Receive,
                ui->labelEdit->text(),
                ui->addressEdit->text());

    return !address.isEmpty();
}

void ImportKeyDialog::accept()
{
    if(!model)
        return;
    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case AddressTableModel::DUPLICATE_ADDRESS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered address \"%1\" is already in the address book.").arg(ui->addressEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case AddressTableModel::INVALID_ADDRESS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered address \"%1\" is not a valid 2GiveCoin address.").arg(ui->addressEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        case AddressTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        case AddressTableModel::KEY_GENERATION_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("New key generation failed."),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        case AddressTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        }

        return;
    }
    QDialog::accept();
}

QString ImportKeyDialog::getAddress() const
{
    return address;
}

void ImportKeyDialog::setAddress(const QString &address)
{
    this->address = address;
    ui->addressEdit->setText(address);
}
