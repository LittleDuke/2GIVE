#ifndef SHARETABLEMODEL_H
#define SHARETABLEMODEL_H

#include <QAbstractTableModel>
#include <QStringList>

#include "sharedatamanager.h"

class ShareTablePriv;
class CWallet;
class WalletModel;

/**
   Qt model of the address book in the core. This allows views to access and modify the address book.
 */
class ShareTableModel : public QAbstractTableModel
{
    Q_OBJECT
public:    
    explicit ShareTableModel(ShareDataManager ccdb, WalletModel *parent = 0);
    ~ShareTableModel();

    enum ColumnIndex {
        Label = 0,
        URL = 1,
        Email = 2,
        Address = 3,
        About = 4
    };

    enum RoleIndex {
        TypeRole = Qt::UserRole /**< Type of address (#Send or #Receive) */
    };

    /** Return status of edit/insert operation */
    enum EditStatus {
        OK,
        INVALID_ADDRESS,   /**< Unparseable address */
        DUPLICATE_ADDRESS,  /**< Address already in address book */
        WALLET_UNLOCK_FAILURE, /**< Wallet could not be unlocked to create new receiving address */
        KEY_GENERATION_FAILURE /**< Generating a new public key for a receiving address failed */
    };

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    bool setData(const QModelIndex & index, const QVariant & value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex & parent) const;
    bool removeRows(int row, int count, const QModelIndex & parent = QModelIndex());
    Qt::ItemFlags flags(const QModelIndex & index) const;
    /*@}*/


    /* Look up label for address in address book, if not found return empty string.
     */
    QString labelForAddress(const QString &address) const;

    /* Look up row index of an address in the model.
       Return -1 if not found.
     */
    int lookupAddress(const QString &address) const;

    EditStatus getEditStatus() const { return editStatus; }

    ShareDataManager shareDatabase(void);

private:
    WalletModel *walletModel;
    ShareDataManager ccdb;
    ShareTablePriv *priv;
    QStringList columns;
    EditStatus editStatus;

    /** Notify listeners that data changed. */
    void emitDataChanged(int index);

signals:
    void defaultAddressChanged(const QString &address);

public slots:
    /* Update address list from core.
     */
    void updateEntry(const QString &address, const QString &label, const QString &email, const QString &url, const QString &about, int status);
    void refreshShareTable(void);

    friend class ShareTablePriv;
};

#endif // ShareTABLEMODEL_H
