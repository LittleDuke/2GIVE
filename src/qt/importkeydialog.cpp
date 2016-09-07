#include "importkeydialog.h"
#include "ui_importkeydialog.h"
#include "addresstablemodel.h"
#include "guiutil.h"

#include <QDataWidgetMapper>
#include <QMessageBox>

#include "init.h" // for pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "base58.h"

using namespace json_spirit;
using namespace std;

ImportKeyDialog::ImportKeyDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ImportKeyDialog), mapper(0), model(0)
{
    ui->setupUi(this);

//   GUIUtil::setupAddressWidget(ui->privateKeyEdit, this);


    setWindowTitle(tr("Import Private Key"));
    ui->privateKeyEdit->setEnabled(true);
    ui->addressLabel->setVisible(false);
    ui->addressEdit->setVisible(false);
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
    Array   params;

    if(!model)
        return false;

    string strSecret = ui->privateKeyEdit->text().toStdString();
    string strLabel = ui->labelEdit->text().toStdString();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) {
        QMessageBox::warning(this, windowTitle(),
            tr("Invalid private key."),
            QMessageBox::Ok, QMessageBox::Ok);
        return false;
    }
    if (fWalletUnlockMintOnly) { // ppcoin: no importprivkey in mint-only mode
        QMessageBox::warning(this, windowTitle(),
            tr("Wallet is unlocked for minting only."),
            QMessageBox::Ok, QMessageBox::Ok);
        return false;
    }
    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CPubKey nPubKey = key.GetPubKey();
    CKeyID vchAddress = key.GetPubKey().GetID();

    std::string strAddress = CBitcoinAddress(nPubKey.GetID()).ToString();

    QString pubKey = QString::fromStdString(strAddress);

    printf("pubKey = %s\n", pubKey.toStdString().c_str());

    setAddress(pubKey);

    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(vchAddress, strLabel);

        if (!pwalletMain->AddKey(key)) {
            QMessageBox::warning(this, windowTitle(),
                tr("Error adding key \"%1\" to wallet").arg(ui->addressEdit->text()),
                QMessageBox::Ok, QMessageBox::Ok);
            return false;
        }

        ui->addressLabel->setVisible(true);
        ui->addressEdit->setVisible(true);
        ui->progressBar->setVisible(true);
        ui->progressBar->setValue(0);

        pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);

        ui->progressBar->setValue(50);

        pwalletMain->ReacceptWalletTransactions();

        ui->progressBar->setValue(100);
    }

    return true;
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

void ImportKeyDialog::setPrivateKey(const QString &privkey)
{
    this->privateKey = privkey;
    ui->privateKeyEdit->setText(privkey);
}

void ImportKeyDialog::setLabel(const QString &label)
{
    this->label = label;
    ui->labelEdit->setText(label);
}
