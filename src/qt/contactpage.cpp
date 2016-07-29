#include "contactpage.h"
#include "ui_contactpage.h"

#include "contacttablemodel.h"
#include "optionsmodel.h"
#include "bitcoingui.h"
#include "editcontactdialog.h"
#include "csvmodelwriter.h"
#include "guiutil.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>

#ifdef USE_QRCODE
#include "qrcodedialog.h"
#endif

ContactPage::ContactPage(Mode mode, Tabs tab, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ContactPage),
    model(0),
    optionsModel(0),
    mode(mode),
    tab(tab)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->newContactButton->setIcon(QIcon());
    ui->copyToClipboard->setIcon(QIcon());
    ui->deleteButton->setIcon(QIcon());
#endif

#ifndef USE_QRCODE
    ui->showQRCode->setVisible(false);
#endif

    switch(mode)
    {
    case ForSending:
//        connect(ui->tableView, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(accept()));
        ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
        ui->tableView->setFocus();
        break;
    case ForEditing:
        ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
        ui->buttonBox->setVisible(false);
        break;
    }
    switch(tab)
    {
    case SendingTab:
//        ui->labelExplanation->setVisible(false);
        ui->deleteButton->setVisible(true);
        ui->signMessage->setVisible(false);
        break;
    case ReceivingTab:
        ui->deleteButton->setVisible(false);
        ui->signMessage->setVisible(true);
        break;
    }

    // Context menu actions
    QAction *giveAction = new QAction(tr("Give"), this);
    QAction *copyLabelAction = new QAction(tr("Copy &Label"), this);
    QAction *copyAddressAction = new QAction(ui->copyToClipboard->text(), this);
    QAction *editAction = new QAction(tr("&Edit"), this);
    QAction *showQRCodeAction = new QAction(ui->showQRCode->text(), this);
    QAction *signMessageAction = new QAction(ui->signMessage->text(), this);
    QAction *verifyMessageAction = new QAction(ui->verifyMessage->text(), this);
    deleteAction = new QAction(ui->deleteButton->text(), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(giveAction);
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(editAction);
    if(tab == SendingTab)
        contextMenu->addAction(deleteAction);
    contextMenu->addSeparator();
    contextMenu->addAction(showQRCodeAction);
    if(tab == ReceivingTab)
        contextMenu->addAction(signMessageAction);
    else if(tab == SendingTab)
        contextMenu->addAction(verifyMessageAction);

    // Connect signals for context menu actions
    connect(giveAction, SIGNAL(triggered()), this, SLOT(on_giveButton_clicked()));

    connect(copyAddressAction, SIGNAL(triggered()), this, SLOT(on_copyToClipboard_clicked()));
    connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(onCopyLabelAction()));
    connect(editAction, SIGNAL(triggered()), this, SLOT(onEditAction()));
    connect(deleteAction, SIGNAL(triggered()), this, SLOT(on_deleteButton_clicked()));
    connect(showQRCodeAction, SIGNAL(triggered()), this, SLOT(on_showQRCode_clicked()));
    connect(signMessageAction, SIGNAL(triggered()), this, SLOT(on_signMessage_clicked()));
    connect(verifyMessageAction, SIGNAL(triggered()), this, SLOT(on_verifyMessage_clicked()));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

    // Pass through accept action from button box
    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
}

ContactPage::~ContactPage()
{
    delete ui;
}

void ContactPage::setModel(ContactTableModel *model)
{
    this->model = model;
    if(!model)
        return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    switch(tab)
    {
    case ReceivingTab:
        // Receive filter
        proxyModel->setFilterRole(ContactTableModel::TypeRole);
//        proxyModel->setFilterFixedString(ContactTableModel::Receive);
        break;
    case SendingTab:
        // Send filter
        proxyModel->setFilterRole(ContactTableModel::TypeRole);
//        proxyModel->setFilterFixedString(ContactTableModel::Send);
        break;
    }
    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->resizeSection(ContactTableModel::Address, 333);
    ui->tableView->horizontalHeader()->setResizeMode(ContactTableModel::Label, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setResizeMode(ContactTableModel::Email, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setResizeMode(ContactTableModel::URL, QHeaderView::Stretch);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(ContactTableModel::Label, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(ContactTableModel::Address, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(ContactTableModel::Email, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(ContactTableModel::URL, QHeaderView::ResizeToContents);
#endif

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));

    // Select row for newly created address
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)),
            this, SLOT(selectNewAddress(QModelIndex,int,int)));

    selectionChanged();
}

void ContactPage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}

void ContactPage::on_giveButton_clicked()
{
    QTableView *table = ui->tableView;
    QModelIndex index;

    if (!table->selectionModel())
        return;

    QModelIndexList indexes = table->selectionModel()->selectedRows(1);
    if(!indexes.isEmpty())
    {
        index = indexes.at(0);

        QString pubKey = index.data().toString(), label = index.sibling(index.row(), 0).data(Qt::EditRole).toString();

        QMetaObject::invokeMethod(this->parent()->parent(), "gotoSendCoinsGiftPage", GUIUtil::blockingGUIThreadConnection(),
                                  Q_ARG(QString, pubKey),
                                  Q_ARG(QString, label));
    }
}


void ContactPage::on_copyToClipboard_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, ContactTableModel::Address);
}

void ContactPage::onCopyLabelAction()
{
    GUIUtil::copyEntryData(ui->tableView, ContactTableModel::Label);
}

void ContactPage::onEditAction()
{
    QTableView *table = ui->tableView;

    ContactDataEntry   contact;

    ccdb = model->contactDataBase();

    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows(1);
    if(indexes.isEmpty())
        return;

    QString pubkey = indexes.at(0).data().toString();
    ccdb.readContact(pubkey, contact);

    EditContactDialog dlg(EditContactDialog::EditSendingAddress);

    dlg.setModel(model);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    if (dlg.exec()) {
        printf("onEditAction / id=%d\n", contact.id);
        QString address = dlg.getAddress();
        QString label = dlg.getLabel();
        QString email = dlg.getEmail();
        QString url = dlg.getURL();
        printf("address,email,url = %s, %s, %s\n", pubkey.toStdString().c_str(), email.toStdString().c_str(), url.toStdString().c_str());

        ccdb.updateContact(contact.id, address, label, email, url);
        model->refreshContactTable();
    }

}

void ContactPage::on_editButton_clicked()
{
    onEditAction();
}

void ContactPage::on_signMessage_clicked()
{
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(ContactTableModel::Address);
    QString addr;

    foreach (QModelIndex index, indexes)
    {
        QVariant address = index.data();
        addr = address.toString();
    }

    emit signMessage(addr);
}

void ContactPage::on_verifyMessage_clicked()
{
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(ContactTableModel::Address);
    QString addr;

    foreach (QModelIndex index, indexes)
    {
        QVariant address = index.data();
        addr = address.toString();
    }

    emit verifyMessage(addr);
}

void ContactPage::on_newContactButton_clicked()
{
    ContactDataEntry   contact;
    QString email, url;

    ccdb = model->contactDataBase();

    if(!model)
        return;

    EditContactDialog dlg(EditContactDialog::NewSendingAddress);
    dlg.setModel(model);
    if(dlg.exec())
    {
        newAddressToSelect = dlg.getAddress();
        QString email = dlg.getEmail();
        QString url = dlg.getURL();
        printf("address,email,url = %s, %s, %s\n", newAddressToSelect.toStdString().c_str(), email.toStdString().c_str(), url.toStdString().c_str());

        ccdb.readContact(newAddressToSelect, contact);
        ccdb.updateContact(contact.id, contact.pubkey, contact.label, email, url);
    }
}

void ContactPage::on_deleteButton_clicked()
{
    QTableView *table = ui->tableView;
    QMessageBox confirm;

    confirm.setWindowTitle("Delete entry");
    confirm.setText("Are you sure you want to delete this contact?");
    confirm.setStandardButtons(QMessageBox::Yes);
    confirm.addButton(QMessageBox::No);
    confirm.setDefaultButton(QMessageBox::No);

    ccdb = model->contactDataBase();

    if(!table->selectionModel())
        return;
    QModelIndexList indexes = table->selectionModel()->selectedRows(1);
    if(!indexes.isEmpty())
    {
        QString pubkey = indexes.at(0).data().toString();

        if (confirm.exec() == QMessageBox::Yes) {
//        printf("ContactPage::on_deleteButton_clicked / pubkey = %s\n", pubkey.toStdString().c_str());
            table->model()->removeRow(indexes.at(0).row());

            ccdb.deleteContact(pubkey);
        }
    }
}

void ContactPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        switch(tab)
        {
        case SendingTab:
            // In sending tab, allow deletion of selection
            ui->giveButton->setEnabled(true);
            ui->deleteButton->setEnabled(true);
            ui->deleteButton->setVisible(true);
            deleteAction->setEnabled(true);
            ui->signMessage->setEnabled(false);
            ui->signMessage->setVisible(false);
            ui->verifyMessage->setEnabled(true);
            ui->verifyMessage->setVisible(true);
            break;
        case ReceivingTab:
            // Deleting receiving addresses, however, is not allowed
            ui->giveButton->setEnabled(true);
            ui->deleteButton->setEnabled(false);
            ui->deleteButton->setVisible(false);
            deleteAction->setEnabled(false);
            ui->signMessage->setEnabled(true);
            ui->signMessage->setVisible(true);
            ui->verifyMessage->setEnabled(false);
            ui->verifyMessage->setVisible(false);
            break;
        }
        ui->copyToClipboard->setEnabled(true);
        ui->showQRCode->setEnabled(true);
    }
    else
    {
        ui->giveButton->setEnabled(false);
        ui->deleteButton->setEnabled(false);
        ui->showQRCode->setEnabled(false);
        ui->copyToClipboard->setEnabled(false);
        ui->signMessage->setEnabled(false);
        ui->verifyMessage->setEnabled(false);
    }
}

void ContactPage::done(int retval)
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel() || !table->model())
        return;
    // When this is a tab/widget and not a model dialog, ignore "done"
    if(mode == ForEditing)
        return;

    // Figure out which address was selected, and return it
    QModelIndexList indexes = table->selectionModel()->selectedRows(ContactTableModel::Address);

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

void ContactPage::exportClicked()
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
    writer.addColumn("Label", ContactTableModel::Label, Qt::EditRole);
    writer.addColumn("Address", ContactTableModel::Address, Qt::EditRole);

    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}

void ContactPage::on_showQRCode_clicked()
{
#ifdef USE_QRCODE
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(ContactTableModel::Address);

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

void ContactPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}

void ContactPage::selectNewAddress(const QModelIndex &parent, int begin, int end)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, ContactTableModel::Address, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect))
    {
        // Select row of newly created address, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newAddressToSelect.clear();
    }
}
