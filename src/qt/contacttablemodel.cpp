#include "contactdatamanager.h"
#include "contacttablemodel.h"
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


struct ContactTableEntry
{
    int     id;
    QString label;
    QString address;
    QString email;
    QString url;

    ContactTableEntry() {}
    ContactTableEntry(const int &id, const QString &label, const QString &address, const QString &email, const QString &url):
        id(id), label(label), address(address), email(email), url(url) {}
};

struct ContactTableEntryLessThan
{
    bool operator()(const ContactTableEntry &a, const ContactTableEntry &b) const
    {
        return a.address < b.address;
    }
    bool operator()(const ContactTableEntry &a, const QString &b) const
    {
        return a.address < b;
    }
    bool operator()(const QString &a, const ContactTableEntry &b) const
    {
        return a < b.address;
    }
};

// Private implementation
class ContactTablePriv
{
public:
    ContactDataManager ccdb;
    CWallet *wallet;
    QList<ContactTableEntry> cachedContactTable;
    ContactTableModel *parent;

    ContactTablePriv(ContactDataManager ccdb, ContactTableModel *parent):
        ccdb(ccdb), parent(parent) {}

    void refreshContactTable()
    {
        QList<ContactDataEntry> contacts;

        cachedContactTable.clear();
        {
            if (ccdb.allContacts(contacts, QString("label"))) {
                foreach (ContactDataEntry entry, contacts) {
//                    cachedContactTable.append(ContactTableEntry(ContactTableEntry::Sending, entry.label, entry.pubkey, entry.email, entry.url));
                    cachedContactTable.append(ContactTableEntry(entry.id, entry.label, entry.pubkey, entry.email, entry.url));
    //                printf("%d | %s | %s\n", entry.id, entry.pubkey.toStdString().c_str(), entry.label.toStdString().c_str());

                }
            }
        }
        qSort(cachedContactTable.begin(), cachedContactTable.end(), ContactTableEntryLessThan());
    }

    void updateEntry(const QString &address, const QString &label, const QString &email, const QString &url, int status)
    {
        ContactDataEntry contact;

        // Find address / label in model
        QList<ContactTableEntry>::iterator lower = qLowerBound(
            cachedContactTable.begin(), cachedContactTable.end(), address, ContactTableEntryLessThan());
        QList<ContactTableEntry>::iterator upper = qUpperBound(
            cachedContactTable.begin(), cachedContactTable.end(), address, ContactTableEntryLessThan());
        int lowerIndex = (lower - cachedContactTable.begin());
        int upperIndex = (upper - cachedContactTable.begin());
        bool inModel = (lower != upper);

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                OutputDebugStringF("Warning: ContactTablePriv::updateEntry: Got CT_NEW, but entry is already in model\n");
                break;
            }
            ccdb.readContact(address, contact);
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedContactTable.insert(lowerIndex, ContactTableEntry(contact.id, label, address, email, url));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                OutputDebugStringF("Warning: ContactTablePriv::updateEntry: Got CT_UPDATED, but entry is not in model\n");
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
                OutputDebugStringF("Warning: ContactTablePriv::updateEntry: Got CT_DELETED, but entry is not in model\n");
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedContactTable.erase(lower, upper);
            parent->endRemoveRows();
            parent->emitDataChanged(lowerIndex);
            break;
        }
    }

    int size()
    {
        return cachedContactTable.size();
    }

    ContactTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedContactTable.size())
        {
            return &cachedContactTable[idx];
        }
        else
        {
            return 0;
        }
    }
};

ContactTableModel::ContactTableModel(ContactDataManager ccdb, WalletModel *parent) :
    QAbstractTableModel(parent),walletModel(parent),ccdb(ccdb),priv(0)
{
    columns << tr("Label") << tr("Address") << tr("Email") << tr("URL");
    priv = new ContactTablePriv(ccdb, this);
    priv->refreshContactTable();
}

ContactTableModel::~ContactTableModel()
{
    delete priv;
}

int ContactTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int ContactTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant ContactTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    ContactTableEntry *rec = static_cast<ContactTableEntry*>(index.internalPointer());

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

bool ContactTableModel::setData(const QModelIndex & index, const QVariant & value, int role)
{
    if(!index.isValid())
        return false;
    ContactTableEntry *rec = static_cast<ContactTableEntry*>(index.internalPointer());

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
/*            if (rec->type == ContactTableEntry::Sending)
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

        updateEntry(rec->address, rec->label, rec->email, rec->url, CT_UPDATED);

        return true;
    }
    return false;
}

QVariant ContactTableModel::headerData(int section, Qt::Orientation orientation, int role) const
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

Qt::ItemFlags ContactTableModel::flags(const QModelIndex & index) const
{
    if(!index.isValid())
        return 0;
    ContactTableEntry *rec = static_cast<ContactTableEntry*>(index.internalPointer());

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemIsEditable;
    return retval;
}

QModelIndex ContactTableModel::index(int row, int column, const QModelIndex & parent) const
{
    Q_UNUSED(parent);
    ContactTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void ContactTableModel::updateEntry(const QString &address, const QString &label, const QString &email, const QString &url, int status)
{
    priv->updateEntry(address, label, email, url, status);
    if (status != CT_DELETED)
        emitDataChanged(lookupAddress(address));
}

QString ContactTableModel::addRow(const QString &label, const QString &address, const QString &email, const QString &url)
{
    editStatus = OK;

    if (!walletModel->validateAddress(address))
    {
            editStatus = INVALID_ADDRESS;
            return QString();
    }
        // Check for duplicate addresses
/*        {
            LOCK(wallet->cs_wallet);
            if(wallet->mapAddressBook.count(CBitcoinAddress(strAddress).Get()))
            {
                editStatus = DUPLICATE_ADDRESS;
                return QString();
            }
        }
 */

    ccdb.addContact(address, label, email, url);
    updateEntry(address, label, email, url, CT_NEW);

    return address;
}

bool ContactTableModel::removeRows(int row, int count, const QModelIndex & parent)
{
    Q_UNUSED(parent);
    ContactTableEntry *rec = priv->index(row);
    if(count != 1 || !rec)
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        return false;
    }

    updateEntry(rec->address, rec->label, rec->email, rec->url, CT_DELETED);

//    ccdb.deleteContact(rec->address);

    return true;
}

/* Look up label for address in address book, if not found return empty string.
 */
QString ContactTableModel::labelForAddress(const QString &address) const
{
    QString label;

    if (ccdb.readContactAttVal(address, "label", label)) {
        return label;
    } else
        return QString();
}

int ContactTableModel::lookupAddress(const QString &address) const
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

void ContactTableModel::emitDataChanged(int idx)
{
    emit dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}

ContactDataManager ContactTableModel::contactDataBase(void)
{
    return ccdb;
}

void ContactTableModel::refreshContactTable(void)
{
    priv->refreshContactTable();
    emit dataChanged(index(0, 0, QModelIndex()), index(priv->size()-1, 0, QModelIndex()));
}
