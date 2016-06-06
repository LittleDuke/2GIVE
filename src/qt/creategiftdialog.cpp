// Copyright 2016 Strength in Numbers Foundation


#include "creategiftdialog.h"
#include "ui_creategiftdialog.h"
#include "giftcardtablemodel.h"
#include "guiutil.h"

#include <QDataWidgetMapper>
#include <QMessageBox>

CreateGiftDialog::CreateGiftDialog(Mode mode, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CreateGiftDialog), mapper(0), mode(mode), model(0)
{
    ui->setupUi(this);

    GUIUtil::setupAddressWidget(ui->addressEdit, this);

    switch(mode)
    {
    case NewGiftAddress:
        setWindowTitle(tr("New Gift* address"));
        ui->addressEdit->setEnabled(false);
        break;
    case EditGiftAddress:
        setWindowTitle(tr("Edit Gift* address"));
        ui->addressEdit->setDisabled(true);
        break;
    }

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
}

CreateGiftDialog::~CreateGiftDialog()
{
    delete ui;
}

void CreateGiftDialog::setModel(GiftCardTableModel *model)
{
    this->model = model;
    mapper->setModel(model);
    mapper->addMapping(ui->labelEdit, GiftCardTableModel::Label);
    mapper->addMapping(ui->addressEdit, GiftCardTableModel::Address);
}

void CreateGiftDialog::loadRow(int row)
{
    mapper->setCurrentIndex(row);
}

bool CreateGiftDialog::saveCurrentRow()
{
    if(!model)
        return false;
    switch(mode)
    {
    case NewGiftAddress:
        address = model->addRow(GiftCardTableModel::Gift,
                ui->labelEdit->text(),
                ui->addressEdit->text());
        break;
    case EditGiftAddress:
        if(mapper->submit())
        {
            address = ui->addressEdit->text();
        }
        break;
    }
    return !address.isEmpty();
}

void CreateGiftDialog::accept()
{
    if(!model)
        return;
    if(!saveCurrentRow())
    {
        switch(model->getEditStatus())
        {
        case GiftCardTableModel::DUPLICATE_ADDRESS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered address \"%1\" is already in the address book.").arg(ui->addressEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            break;
        case GiftCardTableModel::INVALID_ADDRESS:
            QMessageBox::warning(this, windowTitle(),
                tr("The entered address \"%1\" is not a valid 2GiveCoin address.").arg(ui->addressEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        case GiftCardTableModel::WALLET_UNLOCK_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("Could not unlock wallet."),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        case GiftCardTableModel::KEY_GENERATION_FAILURE:
            QMessageBox::critical(this, windowTitle(),
                tr("New key generation failed."),
                QMessageBox::Ok, QMessageBox::Ok);
            return;
        case GiftCardTableModel::OK:
            // Failed with unknown reason. Just reject.
            break;
        }

        return;
    }
    QDialog::accept();
}

QString CreateGiftDialog::getAddress() const
{
    return address;
}

void CreateGiftDialog::setAddress(const QString &address)
{
    this->address = address;
    ui->addressEdit->setText(address);
}
