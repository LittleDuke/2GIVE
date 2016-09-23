#include "sharedatamanager.h"
#include "sharetablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"

#include "wallet.h"
#include "base58.h"

#include <QFont>
#include <QColor>

// Amount column is right-aligned it contains numbers
static int column_alignments[] = {
        Qt::AlignLeft|Qt::AlignVCenter,
        Qt::AlignLeft|Qt::AlignVCenter,
        Qt::AlignLeft|Qt::AlignVCenter,
        Qt::AlignLeft|Qt::AlignVCenter
    };


struct ShareTableEntry
{
    int     id;
    QString label;
    QString address;
    QString email;
    QString url;
    QString about;

    ShareTableEntry() {}
    ShareTableEntry(const int &id, const QString &label, const QString &address, const QString &email, const QString &url, const QString &about):
        id(id), label(label), address(address), email(email), url(url), about(about) {}
};

struct ShareTableEntryLessThan
{
    bool operator()(const ShareTableEntry &a, const ShareTableEntry &b) const
    {
        return a.address < b.address;
    }
    bool operator()(const ShareTableEntry &a, const QString &b) const
    {
        return a.address < b;
    }
    bool operator()(const QString &a, const ShareTableEntry &b) const
    {
        return a < b.address;
    }
};

// Private implementation
class ShareTablePriv
{
public:
    ShareDataManager ccdb;
    CWallet *wallet;
    QList<ShareTableEntry> cachedShareTable;
    ShareTableModel *parent;

    ShareTablePriv(ShareDataManager ccdb, ShareTableModel *parent):
        ccdb(ccdb), parent(parent) {}

    void refreshShareTable()
    {
        QList<ShareDataEntry> contacts;

//        printf("PRE cachedShareTable.size() = %d\n", this->size());

        parent->beginRemoveRows(QModelIndex(), 0, cachedShareTable.size());
        cachedShareTable.erase(cachedShareTable.begin(), cachedShareTable.end());
        cachedShareTable.clear();
        parent->endRemoveRows();
        {
//            printf("CLR cachedShareTable.size() = %d\n", this->size());
            if (ccdb.allContacts(contacts, QString("label"))) {
                foreach (ShareDataEntry entry, contacts) {
//                    cachedShareTable.append(ShareTableEntry(ShareTableEntry::Sending, entry.label, entry.pubkey, entry.email, entry.url));
                    cachedShareTable.append(ShareTableEntry(entry.id, entry.label, entry.pubkey, entry.email, entry.url, entry.about));

//                    printf("%d | %s | %s\n", entry.id, entry.pubkey.toStdString().c_str(), entry.label.toStdString().c_str());

                }
            }
        }
        printf("POST cachedShareTable.size() = %d\n", this->size());

        qSort(cachedShareTable.begin(), cachedShareTable.end(), ShareTableEntryLessThan());
        parent->emitDataChanged(0);

    }

    void updateEntry(const QString &address, const QString &label, const QString &email, const QString &url, const QString &about, int status)
    {
        ShareDataEntry contact;

        // Find address / label in model
        QList<ShareTableEntry>::iterator lower = qLowerBound(
            cachedShareTable.begin(), cachedShareTable.end(), address, ShareTableEntryLessThan());
        QList<ShareTableEntry>::iterator upper = qUpperBound(
            cachedShareTable.begin(), cachedShareTable.end(), address, ShareTableEntryLessThan());
        int lowerIndex = (lower - cachedShareTable.begin());
        int upperIndex = (upper - cachedShareTable.begin());
        bool inModel = (lower != upper);

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                OutputDebugStringF("Warning: ShareTablePriv::updateEntry: Got CT_NEW, but entry is already in model\n");
                break;
            }
            ccdb.readContact(address, contact);
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedShareTable.insert(lowerIndex, ShareTableEntry(contact.id, label, address, email, url, about));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                OutputDebugStringF("Warning: ShareTablePriv::updateEntry: Got CT_UPDATED, but entry is not in model\n");
                break;
            }
//            ccdb.readContact(address, contact);
            lower->address = address;
            lower->label = label;
            lower->email = email;
            lower->url = url;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                OutputDebugStringF("Warning: ShareTablePriv::updateEntry: Got CT_DELETED, but entry is not in model\n");
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedShareTable.erase(lower, upper);
            parent->endRemoveRows();
            parent->emitDataChanged(lowerIndex);
            break;
        }
    }

    int size()
    {
        return cachedShareTable.size();
    }

    ShareTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedShareTable.size())
        {
            return &cachedShareTable[idx];
        }
        else
        {
            return 0;
        }
    }
};

ShareTableModel::ShareTableModel(ShareDataManager ccdb, WalletModel *parent) :
    QAbstractTableModel(parent),walletModel(parent),ccdb(ccdb),priv(0)
{
    columns << tr("Name") << tr("URL") << tr("Email") << tr("Address");
    priv = new ShareTablePriv(ccdb, this);
    priv->refreshShareTable();
}

ShareTableModel::~ShareTableModel()
{
    delete priv;
}

int ShareTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int ShareTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant ShareTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    ShareTableEntry *rec = static_cast<ShareTableEntry*>(index.internalPointer());

    if(role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Label:
            if(rec->label.isEmpty() && role == Qt::DisplayRole)
            {
                return tr("(no label)");
            }
            else
            {
                return rec->label;
            }
        case Address:
            return rec->address;
        case Email:
            return rec->email;
        case URL:
            return rec->url;
        }
    }
    else if (role == Qt::FontRole)
    {
        QFont font;
        if(index.column() == Address)
        {
            font = GUIUtil::bitcoinAddressFont();
        }
        return font;
    }

    return QVariant();
}

bool ShareTableModel::setData(const QModelIndex & index, const QVariant & value, int role)
{
    if(!index.isValid())
        return false;
    ShareTableEntry *rec = static_cast<ShareTableEntry*>(index.internalPointer());

    editStatus = OK;

    if(role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Label:
            rec->label = value.toString();
            break;
        case Email:
            rec->email = value.toString();
            break;
        case URL:
            rec->url = value.toString();
            break;
        case Address:
            // Refuse to set invalid address, set error status and return false
            if(!walletModel->validateAddress(value.toString()))
            {
                editStatus = INVALID_ADDRESS;
                return false;
            }
            // Double-check that we're not overwriting a receiving address
/*            if (rec->type == ShareTableEntry::Sending)
            {
                {
                    LOCK(wallet->cs_wallet);
                    // Remove old entry
                    wallet->DelAddressBookName(CBitcoinAddress(rec->address.toStdString()).Get());
                    // Add new entry with new address
                    wallet->SetAddressBookName(CBitcoinAddress(value.toString().toStdString()).Get(), rec->label.toStdString());
                }
            }
*/
            rec->address = value.toString();

            break;
        }

        updateEntry(rec->address, rec->label, rec->email, rec->url, rec->about, CT_UPDATED);

        return true;
    }
    return false;
}

QVariant ShareTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole)
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags ShareTableModel::flags(const QModelIndex & index) const
{
    if(!index.isValid())
        return 0;
    ShareTableEntry *rec = static_cast<ShareTableEntry*>(index.internalPointer());

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    return retval;
}

QModelIndex ShareTableModel::index(int row, int column, const QModelIndex & parent) const
{
    Q_UNUSED(parent);
    ShareTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void ShareTableModel::updateEntry(const QString &address, const QString &label, const QString &email, const QString &url, const QString &about, int status)
{
    priv->updateEntry(address, label, email, url, about, status);
    if (status != CT_DELETED)
        emitDataChanged(lookupAddress(address));
}


bool ShareTableModel::removeRows(int row, int count, const QModelIndex & parent)
{
    Q_UNUSED(parent);
    ShareTableEntry *rec = priv->index(row);
    if(count != 1 || !rec)
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        return false;
    }

    updateEntry(rec->address, rec->label, rec->email, rec->url, rec->about, CT_DELETED);

//    ccdb.deleteContact(rec->address);

    return true;
}

/* Look up label for address in address book, if not found return empty string.
 */
QString ShareTableModel::labelForAddress(const QString &address) const
{
    QString label;

    if (ccdb.readContactAttVal(address, "label", label)) {
        return label;
    } else
        return QString();
}

int ShareTableModel::lookupAddress(const QString &address) const
{
    QModelIndexList lst = match(index(0, Address, QModelIndex()),
                                Qt::EditRole, address, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

void ShareTableModel::emitDataChanged(int idx)
{
    emit dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}

ShareDataManager ShareTableModel::shareDatabase(void)
{
    return ccdb;
}

void ShareTableModel::refreshShareTable(void)
{

    priv->refreshShareTable();
    printf("RFS cachedShareTable.size() = %d\n", priv->size());

/*
    for (int i=0; i<priv->size(); i++)
        emit dataChanged(index(0, 0, QModelIndex()), index(i, 0, QModelIndex()));
        */
}
