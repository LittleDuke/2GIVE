// Copyright 2016 Strength in Numbers Foundation


#ifndef GIFTCARDPAGE_H
#define GIFTCARDPAGE_H

#include "giftcarddatamanager.h"

#include <QDialog>

namespace Ui {
    class GiftCardPage;
}
class GiftCardTableModel;
class OptionsModel;
class GiftCardDataManager;

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

/** Widget that shows a list of sending or receiving addresses.
  */
class GiftCardPage : public QDialog
{
    Q_OBJECT

public:
    enum Tabs {
        SendingTab = 0,
        ReceivingTab = 1,
        GiftingTab = 2
    };

    enum Mode {
        ForSending, /**< Open address book to pick address for sending */
        ForEditing  /**< Open address book for editing */
    };

    explicit GiftCardPage(Mode mode, Tabs tab, QWidget *parent = 0);
    ~GiftCardPage();

    void viewGiftCard(const QString &fileName);
    void setModel(GiftCardTableModel *model);
    void setOptionsModel(OptionsModel *optionsModel);
    const QString &getReturnValue() const { return returnValue; }

public slots:
    void done(int retval);
    void exportClicked();

private:
    Ui::GiftCardPage *ui;
    GiftCardTableModel *model;
    OptionsModel *optionsModel;
    Mode mode;
    Tabs tab;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction;
    QString newAddressToSelect;
    QString filePath;
    GiftCardDataManager gcdb;

private slots:
    void on_newAddressButton_clicked();
    void on_templateButton_clicked();
    void on_editButton_clicked();
    void on_fundButton_clicked();
    void on_viewButton_clicked();
    void on_regenerateButton_clicked();


    void on_deleteButton_clicked();

    /** Copy address of currently selected address entry to clipboard */
    void on_copyToClipboard_clicked();
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);

    /** Copy label of currently selected address entry to clipboard */
    void onCopyLabelAction();
    /** Edit currently selected address entry */
    void onEditAction();

    /** New entry/entries were added to address table */
    void selectNewAddress(const QModelIndex &parent, int begin, int end);
};

#endif // GIFTCARDPAGE_H
