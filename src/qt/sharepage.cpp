#include "sharepage.h"
#include "ui_sharepage.h"

#include "sharetablemodel.h"
#include "optionsmodel.h"
#include "bitcoingui.h"
#include "csvmodelwriter.h"
#include "guiutil.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>
#include <QDesktopServices>     // dvd add for launching URL
#include <QUrl>                 // dvd add for launching URL


#ifdef USE_QRCODE
#include "qrcodedialog.h"
#endif

SharePage::SharePage(Mode mode, Tabs tab, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SharePage),
    model(0),
    optionsModel(0),
    mode(mode),
    tab(tab)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->copyToClipboard->setIcon(QIcon());
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
    }
    switch(tab)
    {
    case SendingTab:
//        ui->labelExplanation->setVisible(false);
        break;
    case ReceivingTab:
        break;
    }

    // Context menu actions
    QAction *giveAction = new QAction(tr("Give"), this);
    QAction *visitAction = new QAction(tr("Visit Website"), this);
    QAction *copyLabelAction = new QAction(tr("Copy &Label"), this);
    QAction *copyAddressAction = new QAction(ui->copyToClipboard->text(), this);
    QAction *showQRCodeAction = new QAction(ui->showQRCode->text(), this);
    QAction *verifyMessageAction = new QAction(ui->verifyMessage->text(), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(giveAction);
    contextMenu->addAction(visitAction);
    contextMenu->addAction(copyAddressAction);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addSeparator();
    contextMenu->addAction(showQRCodeAction);
    if(tab == SendingTab)
        contextMenu->addAction(verifyMessageAction);

    // Connect signals for context menu actions
    connect(giveAction, SIGNAL(triggered()), this, SLOT(on_giveButton_clicked()));
    connect(visitAction, SIGNAL(triggered()), this, SLOT(on_visitButton_clicked()));

    connect(copyAddressAction, SIGNAL(triggered()), this, SLOT(on_copyToClipboard_clicked()));
    connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(onCopyLabelAction()));
    connect(showQRCodeAction, SIGNAL(triggered()), this, SLOT(on_showQRCode_clicked()));
    connect(verifyMessageAction, SIGNAL(triggered()), this, SLOT(on_verifyMessage_clicked()));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

    ui->refreshButton->setEnabled(false);
    ui->refreshButton->setVisible(false);

    ccdb.updateCampaigns();
}

SharePage::~SharePage()
{
    delete ui;
}

void SharePage::setModel(ShareTableModel *model)
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
        proxyModel->setFilterRole(ShareTableModel::TypeRole);
//        proxyModel->setFilterFixedString(ShareTableModel::Receive);
        break;
    case SendingTab:
        // Send filter
        proxyModel->setFilterRole(ShareTableModel::TypeRole);
//        proxyModel->setFilterFixedString(ShareTableModel::Send);
        break;
    }
    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->resizeSection(ShareTableModel::Address, 333);
    ui->tableView->horizontalHeader()->setResizeMode(ShareTableModel::Label, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(ShareTableModel::Email, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setResizeMode(ShareTableModel::URL, QHeaderView::ResizeToContents);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(ShareTableModel::Label, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->setSectionResizeMode(ShareTableModel::Address, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(ShareTableModel::Email, QHeaderView::ResizeToContents);
    ui->tableView->horizontalHeader()->setSectionResizeMode(ShareTableModel::URL, QHeaderView::ResizeToContents);
#endif

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));

    // Select row for newly created address
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)),
            this, SLOT(selectNewAddress(QModelIndex,int,int)));

    selectionChanged();
}

void SharePage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}

void SharePage::on_giveButton_clicked()
{
    QTableView *table = ui->tableView;
    QModelIndex index;

    if (!table->selectionModel())
        return;

    QModelIndexList indexes = table->selectionModel()->selectedRows(ShareTableModel::Address);
    if(!indexes.isEmpty())
    {
        index = indexes.at(0);

        QString pubKey = index.data().toString(), label = index.sibling(index.row(), 0).data(Qt::EditRole).toString();

        QMetaObject::invokeMethod(this->parent()->parent(), "gotoSendCoinsGiftPage", GUIUtil::blockingGUIThreadConnection(),
                                  Q_ARG(QString, pubKey),
                                  Q_ARG(QString, label));
    }
}


void SharePage::on_copyToClipboard_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, ShareTableModel::Address);
}

void SharePage::onCopyLabelAction()
{
    GUIUtil::copyEntryData(ui->tableView, ShareTableModel::Label);
}



void SharePage::on_verifyMessage_clicked()
{
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(ShareTableModel::Address);
    QString addr;

    foreach (QModelIndex index, indexes)
    {
        QVariant address = index.data();
        addr = address.toString();
    }

    emit verifyMessage(addr);
}

void SharePage::on_refreshButton_clicked()
{
    QMessageBox msgBox;

    msgBox.setWindowTitle("Update Campaigns");
    msgBox.setStandardButtons(QMessageBox::Ok);
    msgBox.setDefaultButton(QMessageBox::Ok);

    if (ccdb.updateCampaigns())
        msgBox.setText("Campaigns Update Successful");
    else {
        msgBox.setText("Campaigns Update Failed");
        msgBox.setInformativeText("Check your network connectivity and retry");
    }
    msgBox.exec();

    setModel(model);
//    ui->tableView->reset();
    model->refreshShareTable();
//    ui->tableView->update();
//    ui->tableView->repaint();
    ui->tableView->setModel(model);
}


void SharePage::selectionChanged()
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
            ui->verifyMessage->setEnabled(true);
            ui->verifyMessage->setVisible(true);
            break;
        case ReceivingTab:
            // Deleting receiving addresses, however, is not allowed
            ui->giveButton->setEnabled(true);
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
        ui->showQRCode->setEnabled(false);
        ui->copyToClipboard->setEnabled(false);
        ui->verifyMessage->setEnabled(false);
    }
}

void SharePage::done(int retval)
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel() || !table->model())
        return;
    // When this is a tab/widget and not a model dialog, ignore "done"
    if(mode == ForEditing)
        return;

    // Figure out which address was selected, and return it
    QModelIndexList indexes = table->selectionModel()->selectedRows(ShareTableModel::Address);

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

void SharePage::exportClicked()
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
    writer.addColumn("Label", ShareTableModel::Label, Qt::EditRole);
    writer.addColumn("Address", ShareTableModel::Address, Qt::EditRole);

    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}

void SharePage::on_showQRCode_clicked()
{
#ifdef USE_QRCODE
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(ShareTableModel::Address);

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

void SharePage::on_visitButton_clicked()
{
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(ShareTableModel::URL);

    if (!table->selectionModel())
        return;

    if(!indexes.isEmpty())
    {
        QString url = indexes.at(0).data().toString();

        QDesktopServices::openUrl(QUrl(url));
    }
}

void SharePage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}

void SharePage::selectNewAddress(const QModelIndex &parent, int begin, int end)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, ShareTableModel::Address, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect))
    {
        // Select row of newly created address, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newAddressToSelect.clear();
    }
}
