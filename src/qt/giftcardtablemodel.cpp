// Copyright 2016 Strength in Numbers Foundation


#include "giftcardtablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"

#include "wallet.h"
#include "base58.h"

#include <QFont>
#include <QColor>

extern int VanityGen(int addrtype, char *prefix, char *pubKey, char *privKey);

const QString GiftCardTableModel::Gift = "G";

struct GiftCardTableEntry
{
    enum Type {
        Sending,
        Receiving,
        Gift
    };

    Type type;
    QString label;
    QString address;
    QString privkey;

    GiftCardTableEntry() {}
    GiftCardTableEntry(Type type, const QString &label, const QString &address):
        type(type), label(label), address(address) {}
};

struct GiftCardTableEntryLessThan
{
    bool operator()(const GiftCardTableEntry &a, const GiftCardTableEntry &b) const
    {
        return a.address < b.address;
    }
    bool operator()(const GiftCardTableEntry &a, const QString &b) const
    {
        return a.address < b;
    }
    bool operator()(const QString &a, const GiftCardTableEntry &b) const
    {
        return a < b.address;
    }
};

// Private implementation
class GiftCardTablePriv
{
public:
    CWallet *wallet;
    QList<GiftCardTableEntry> cachedGiftCardTable;
    GiftCardTableModel *parent;

    GiftCardTablePriv(CWallet *wallet, GiftCardTableModel *parent):
        wallet(wallet), parent(parent) {}

    void refreshAddressTable()
    {
        cachedGiftCardTable.clear();
        {
            LOCK(wallet->cs_wallet);
            BOOST_FOREACH(const PAIRTYPE(CTxDestination, std::string)& item, wallet->mapAddressBook)
            {
                const CBitcoinAddress& address = item.first;
                const std::string& strName = item.second;
//                bool fMine = IsMine(*wallet, address.Get());
                if (QString::fromStdString(address.ToString()).contains("Gift"))
                    cachedGiftCardTable.append(GiftCardTableEntry(GiftCardTableEntry::Gift,
                                  QString::fromStdString(strName),
                                  QString::fromStdString(address.ToString())));
            }
        }
        qSort(cachedGiftCardTable.begin(), cachedGiftCardTable.end(), GiftCardTableEntryLessThan());
    }

    void updateEntry(const QString &address, const QString &label, bool isMine, int status)
    {
        // Find address / label in model
        QList<GiftCardTableEntry>::iterator lower = qLowerBound(
            cachedGiftCardTable.begin(), cachedGiftCardTable.end(), address, GiftCardTableEntryLessThan());
        QList<GiftCardTableEntry>::iterator upper = qUpperBound(
            cachedGiftCardTable.begin(), cachedGiftCardTable.end(), address, GiftCardTableEntryLessThan());
        int lowerIndex = (lower - cachedGiftCardTable.begin());
        int upperIndex = (upper - cachedGiftCardTable.begin());
        bool inModel = (lower != upper);
        GiftCardTableEntry::Type newEntryType =  GiftCardTableEntry::Gift;

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                OutputDebugStringF("Warning: GiftCardTablePriv::updateEntry: Got CT_NOW, but entry is already in model\n");
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedGiftCardTable.insert(lowerIndex, GiftCardTableEntry(newEntryType, label, address));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                OutputDebugStringF("Warning: GiftCardTablePriv::updateEntry: Got CT_UPDATED, but entry is not in model\n");
                break;
            }
            lower->type = newEntryType;
            lower->label = label;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if(!inModel)
            {
                OutputDebugStringF("Warning: GiftCardTablePriv::updateEntry: Got CT_DELETED, but entry is not in model\n");
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedGiftCardTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }

    int size()
    {
        return cachedGiftCardTable.size();
    }

    GiftCardTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedGiftCardTable.size())
        {
            return &cachedGiftCardTable[idx];
        }
        else
        {
            return 0;
        }
    }
};

GiftCardTableModel::GiftCardTableModel(CWallet *wallet, WalletModel *parent) :
    QAbstractTableModel(parent),walletModel(parent),wallet(wallet),priv(0)
{
    columns << tr("Label") << tr("Address");
    priv = new GiftCardTablePriv(wallet, this);
    priv->refreshAddressTable();
}

GiftCardTableModel::~GiftCardTableModel()
{
    delete priv;
}

int GiftCardTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int GiftCardTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant GiftCardTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    GiftCardTableEntry *rec = static_cast<GiftCardTableEntry*>(index.internalPointer());

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
    else if (role == TypeRole)
    {
        return Gift;
    }
    return QVariant();
}

bool GiftCardTableModel::setData(const QModelIndex & index, const QVariant & value, int role)
{
    if(!index.isValid())
        return false;
    GiftCardTableEntry *rec = static_cast<GiftCardTableEntry*>(index.internalPointer());

    editStatus = OK;

    if(role == Qt::EditRole)
    {
        switch(index.column())
        {
        case Label:
            wallet->SetAddressBookName(CBitcoinAddress(rec->address.toStdString()).Get(), value.toString().toStdString());
            rec->label = value.toString();
            break;
        case Address:
            // Refuse to set invalid address, set error status and return false
            if(!walletModel->validateAddress(value.toString()))
            {
                editStatus = INVALID_ADDRESS;
                return false;
            }
            // Double-check that we're not overwriting a receiving address
            if (rec->type == GiftCardTableEntry::Gift)
            {
                {
                    LOCK(wallet->cs_wallet);
                    // Remove old entry
                    wallet->DelAddressBookName(CBitcoinAddress(rec->address.toStdString()).Get());
                    // Add new entry with new address
                    wallet->SetAddressBookName(CBitcoinAddress(value.toString().toStdString()).Get(), rec->label.toStdString());
                }
            }
            break;
        }

        return true;
    }
    return false;
}

QVariant GiftCardTableModel::headerData(int section, Qt::Orientation orientation, int role) const
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

Qt::ItemFlags GiftCardTableModel::flags(const QModelIndex & index) const
{
    if(!index.isValid())
        return 0;
    GiftCardTableEntry *rec = static_cast<GiftCardTableEntry*>(index.internalPointer());

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    // Can edit address and label for sending addresses,
    // and only label for receiving addresses.
    if ((rec->type == GiftCardTableEntry::Gift) && (index.column()==Label))
    {
        retval |= Qt::ItemIsEditable;
    }
    return retval;
}

QModelIndex GiftCardTableModel::index(int row, int column, const QModelIndex & parent) const
{
    Q_UNUSED(parent);
    GiftCardTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void GiftCardTableModel::updateEntry(const QString &address, const QString &label, bool isMine, int status)
{
    // Update address book model from Bitcoin core
    priv->updateEntry(address, label, isMine, status);
}

QString GiftCardTableModel::addRow(const QString &type, const QString &label, const QString &address)
{
    std::string strLabel = label.toStdString();
    std::string strAddress = address.toStdString();

    char    strPubKey[256],
            strPrivKey[256];

    editStatus = OK;

    if (type == Gift) {
        // Generate a new address to associate with given label

        VanityGen(39, "Gift", strPubKey, strPrivKey);

        printf("Address: %s\tPrivkey: %s\n", strPubKey, strPrivKey);
        strAddress = std::string(strPubKey);
    }
    else
    {
        return QString();
    }
    // Add entry
    {
        LOCK(wallet->cs_wallet);
        wallet->SetAddressBookName(CBitcoinAddress(strAddress).Get(), strLabel);
    }

    strAddress += ":" +  std::string(strPrivKey);

    return QString::fromStdString(strAddress);
}

bool GiftCardTableModel::removeRows(int row, int count, const QModelIndex & parent)
{
    Q_UNUSED(parent);
    GiftCardTableEntry *rec = priv->index(row);
    if(count != 1 || !rec || rec->type == GiftCardTableEntry::Receiving)
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;
    }
    {
        LOCK(wallet->cs_wallet);
        wallet->DelAddressBookName(CBitcoinAddress(rec->address.toStdString()).Get());
    }
    return true;
}

/* Look up label for address in address book, if not found return empty string.
 */
QString GiftCardTableModel::labelForAddress(const QString &address) const
{
    {
        LOCK(wallet->cs_wallet);
        CBitcoinAddress address_parsed(address.toStdString());
        std::map<CTxDestination, std::string>::iterator mi = wallet->mapAddressBook.find(address_parsed.Get());
        if (mi != wallet->mapAddressBook.end())
        {
            return QString::fromStdString(mi->second);
        }
    }
    return QString();
}

int GiftCardTableModel::lookupAddress(const QString &address) const
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

void GiftCardTableModel::emitDataChanged(int idx)
{
    emit dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}
