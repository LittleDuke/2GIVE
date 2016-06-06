// Copyright 2016 Strength in Numbers Foundation


#include "giftcardpage.h"
#include "ui_giftcardpage.h"

#include "giftcardtablemodel.h"
#include "optionsmodel.h"
#include "bitcoingui.h"
#include "creategiftdialog.h"
#include "csvmodelwriter.h"
#include "guiutil.h"
#include "paperwallet.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>
#include <QDir>
#include <QFile>
#include <QTextStream>
#include <QDesktopServices>     // dvd add for launching URL
#include <QUrl>                 // dvd add for launching URL

#ifdef USE_QRCODE
#include "qrcodedialog.h"
#endif

extern int VanityGen(int addrtype, char *prefix, char *pubKey, char *privKey);


GiftCardPage::GiftCardPage(Mode mode, Tabs tab, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::GiftCardPage),
    model(0),
    optionsModel(0),
    mode(mode),
    tab(tab)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->newAddressButton->setIcon(QIcon());
    ui->templateButton->setIcon(QIcon());
    ui->copyToClipboard->setIcon(QIcon());
    ui->deleteButton->setIcon(QIcon());
#endif

#ifndef USE_QRCODE
    ui->showQRCode->setVisible(false);
#endif

    switch(mode)
    {
    case ForSending:
        connect(ui->tableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(accept()));
        ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
        ui->tableView->setFocus();
        break;
    case ForEditing:
        ui->buttonBox->setVisible(false);
        break;
    }

    ui->labelExplanation->setVisible(true);
    ui->deleteButton->setVisible(true);
    ui->signMessage->setVisible(false);

//dvd considering adding a "Give" option from the right click

    // Context menu actions
    QAction *copyLabelAction = new QAction(tr("Copy &Label"), this);
    QAction *copyAddressAction = new QAction(ui->copyToClipboard->text(), this);
    QAction *editAction = new QAction(tr("&Edit"), this);
    QAction *showQRCodeAction = new QAction(ui->showQRCode->text(), this);
//    QAction *signMessageAction = new QAction(ui->signMessage->text(), this);
    QAction *verifyMessageAction = new QAction(ui->verifyMessage->text(), this);
    deleteAction = new QAction(ui->deleteButton->text(), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(editAction);
    contextMenu->addAction(deleteAction);
    contextMenu->addSeparator();
    contextMenu->addAction(showQRCodeAction);
    contextMenu->addAction(verifyMessageAction);

    // Connect signals for context menu actions
    connect(copyAddressAction, SIGNAL(triggered()), this, SLOT(on_copyToClipboard_clicked()));
    connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(onCopyLabelAction()));
    connect(editAction, SIGNAL(triggered()), this, SLOT(onEditAction()));
    connect(deleteAction, SIGNAL(triggered()), this, SLOT(on_deleteButton_clicked()));
    connect(showQRCodeAction, SIGNAL(triggered()), this, SLOT(on_showQRCode_clicked()));
//    connect(signMessageAction, SIGNAL(triggered()), this, SLOT(on_signMessage_clicked()));
    connect(verifyMessageAction, SIGNAL(triggered()), this, SLOT(on_verifyMessage_clicked()));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

    // Pass through accept action from button box
    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));

    // Set default filepath to save to
    filePath = QDir::homePath();
    printf("homePath = %s\n", filePath.toStdString().c_str());
}

GiftCardPage::~GiftCardPage()
{
    delete ui;
}

void GiftCardPage::setModel(GiftCardTableModel *model)
{
    this->model = model;
    if(!model)
        return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

    proxyModel->setFilterRole(GiftCardTableModel::TypeRole);
    proxyModel->setFilterFixedString(GiftCardTableModel::Gift);

    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->resizeSection(
            GiftCardTableModel::Address, 333);
    ui->tableView->horizontalHeader()->setResizeMode(
            GiftCardTableModel::Label, QHeaderView::Stretch);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(GiftCardTableModel::Label, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(GiftCardTableModel::Address, QHeaderView::ResizeToContents);
#endif

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));

    // Select row for newly created address
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)),
            this, SLOT(selectNewAddress(QModelIndex,int,int)));

    selectionChanged();
}

void GiftCardPage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}

void GiftCardPage::on_copyToClipboard_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, GiftCardTableModel::Address);
}

void GiftCardPage::onCopyLabelAction()
{
    GUIUtil::copyEntryData(ui->tableView, GiftCardTableModel::Label);
}

void GiftCardPage::onEditAction()
{
    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows();
    if(indexes.isEmpty())
        return;


    CreateGiftDialog dlg(CreateGiftDialog::EditGiftAddress);

    dlg.setModel(model);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    dlg.exec();

}

void GiftCardPage::on_signMessage_clicked()
{
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(GiftCardTableModel::Address);
    QString addr;

    foreach (QModelIndex index, indexes)
    {
        QVariant address = index.data();
        addr = address.toString();
    }

    emit signMessage(addr);
}

void GiftCardPage::on_verifyMessage_clicked()
{
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(GiftCardTableModel::Address);
    QString addr;

    foreach (QModelIndex index, indexes)
    {
        QVariant address = index.data();
        addr = address.toString();
    }

    emit verifyMessage(addr);
}

void GiftCardPage::on_newAddressButton_clicked()
{
    char    strPubKey[256],
            strPrivKey[256];

    if(!model)
        return;

    printf("GiftCardPage::on_newAddressButton(): CreateGiftDialog\n");
    CreateGiftDialog dlg(CreateGiftDialog::NewGiftAddress);
    dlg.setModel(model);
    if(dlg.exec())
    {
        printf("GiftCardPage::on_newAddressButton(): dlg.exec()\n");
        newAddressToSelect = dlg.getAddress();
        QStringList giftKeys = newAddressToSelect.split(":");

        strcpy(strPubKey, giftKeys.at(0).toStdString().c_str());
        strcpy(strPrivKey, giftKeys.at(1).toStdString().c_str());
        printf("strPubKey = %s\tstrPrivKey = %s\n", strPubKey, strPrivKey);

//        QString appDirPath = QCoreApplication::applicationDirPath();
//        printf("appDirPath = %s\n", appDirPath.toStdString().c_str());

        QString defaultFileName = filePath + QDir::separator() + giftKeys.at(0) + ".html";

        printf("defaultFileName = %s\n", defaultFileName.toStdString().c_str());

        QString fileName = GUIUtil::getSaveFileName(
                    this, tr("Save Gift* Card"), defaultFileName, tr("Cards (*.html)"));

        if (!fileName.isNull()) {
            PaperWallet pWallet = PaperWallet(fileName, giftKeys.at(0), giftKeys.at(1), "");
            if (pWallet.genWallet()) {
                QFile file(fileName);
                if (file.exists()) {
                    // save the user selected folder for easy next use
                    QFileInfo fileInfo(file.fileName());
                    filePath = fileInfo.absolutePath();

                    // launch browser to display/print
                    //QString url = "file://" + fileName;
                    QDesktopServices::openUrl(QUrl::fromLocalFile(fileName));
                }
            }
        }
    }
}

void GiftCardPage::on_templateButton_clicked()
{
    QMessageBox msgBox;

    msgBox.setWindowTitle("Update Template");
    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.setDefaultButton(QMessageBox::Ok);

    PaperWallet pWallet = PaperWallet("", "", "", "");

    if (pWallet.updateTemplates())
        msgBox.setText("Template Update Successful");
    else {
        msgBox.setText("Template Update Failed");
        msgBox.setInformativeText("Check your network connectivity and retry");
    }
    msgBox.exec();
}

void GiftCardPage::on_deleteButton_clicked()
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;
    QModelIndexList indexes = table->selectionModel()->selectedRows();
    if(!indexes.isEmpty())
    {
        table->model()->removeRow(indexes.at(0).row());
    }
}

void GiftCardPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        // In gift tab, allow deletion of selection
        ui->deleteButton->setEnabled(true);
        ui->deleteButton->setVisible(true);
        deleteAction->setEnabled(true);
        ui->signMessage->setEnabled(false);
        ui->signMessage->setVisible(false);
        ui->verifyMessage->setEnabled(true);
        ui->verifyMessage->setVisible(true);
        ui->copyToClipboard->setEnabled(true);
        ui->showQRCode->setEnabled(true);
    }
    else
    {
        ui->deleteButton->setEnabled(false);
        ui->showQRCode->setEnabled(false);
        ui->copyToClipboard->setEnabled(false);
        ui->signMessage->setEnabled(false);
        ui->verifyMessage->setEnabled(false);
    }
}

void GiftCardPage::done(int retval)
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel() || !table->model())
        return;
    // When this is a tab/widget and not a model dialog, ignore "done"
    if(mode == ForEditing)
        return;

    // Figure out which address was selected, and return it
    QModelIndexList indexes = table->selectionModel()->selectedRows(GiftCardTableModel::Address);

    foreach (QModelIndex index, indexes)
    {
        QVariant address = table->model()->data(index);
        returnValue = address.toString();
    }

    if(returnValue.isEmpty())
    {
        // If no address entry selected, return rejected
        retval = Rejected;
    }

    QDialog::done(retval);
}

void GiftCardPage::exportClicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Address Book Data"), QString(),
            tr("Comma separated file (*.csv)"));

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Label", GiftCardTableModel::Label, Qt::EditRole);
    writer.addColumn("Address", GiftCardTableModel::Address, Qt::EditRole);

    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}

void GiftCardPage::on_showQRCode_clicked()
{
#ifdef USE_QRCODE
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(GiftCardTableModel::Address);

    foreach (QModelIndex index, indexes)
    {
        QString address = index.data().toString(), label = index.sibling(index.row(), 0).data(Qt::EditRole).toString();

        QRCodeDialog *dialog = new QRCodeDialog(address, label, tab == ReceivingTab, this);
        if(optionsModel)
            dialog->setModel(optionsModel);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->show();
    }
#endif
}

void GiftCardPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}

void GiftCardPage::selectNewAddress(const QModelIndex &parent, int begin, int end)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, GiftCardTableModel::Address, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect))
    {
        // Select row of newly created address, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newAddressToSelect.clear();
    }
}
