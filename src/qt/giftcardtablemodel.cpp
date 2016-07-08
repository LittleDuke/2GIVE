// Copyright 2016 Strength in Numbers Foundation

#include "giftcarddatamanager.h"
#include "giftcardtablemodel.h"
#include "guiutil.h"
#include "walletmodel.h"
#include "ui_interface.h"

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
    QString generated;
    float   balance;

    GiftCardTableEntry() {}
    GiftCardTableEntry(Type type, const QString &label, const QString &address, const QString &generated, const float balance):
        type(type), label(label), address(address), generated(generated), balance(balance) {}
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
    GiftCardDataManager gcdb;
    QList<GiftCardTableEntry> cachedGiftCardTable;
    GiftCardTableModel *parent;

    GiftCardTablePriv(GiftCardDataManager gcdb, GiftCardTableModel *parent):
        gcdb(gcdb), parent(parent) {}

    void refreshAddressTable()
    {
        QList<GiftCardDataEntry> cards;

        cachedGiftCardTable.clear();
        if (gcdb.allCards(cards,QString("label"))) {
            foreach (GiftCardDataEntry entry, cards) {
                cachedGiftCardTable.append(GiftCardTableEntry(GiftCardTableEntry::Gift,entry.label, entry.pubkey, entry.generated, entry.balance));
//                printf("%d | %s | %s\n", entry.id, entry.pubkey.toStdString().c_str(), entry.label.toStdString().c_str());

            }
            qSort(cachedGiftCardTable.begin(), cachedGiftCardTable.end(), GiftCardTableEntryLessThan());
        } else
            OutputDebugStringF("! FAIL gcdb.allCards\n");
    }

    void updateEntry(const QString &address, const QString &label, const QString &generated, const float balance, int status)
    {
        GiftCardDataEntry card;

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
            gcdb.readCard(address, card);
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedGiftCardTable.insert(lowerIndex, GiftCardTableEntry(newEntryType, label, address, card.generated, 0.0));
            parent->endInsertRows();
            break;
        case CT_UPDATED:
            if(!inModel)
            {
                OutputDebugStringF("Warning: GiftCardTablePriv::updateEntry: Got CT_UPDATED, but entry is not in model\n");
                break;
            }
            gcdb.readCard(address, card);
            lower->type = newEntryType;
            lower->label = label;
            lower->generated = card.generated;
            lower->balance = card.balance;
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
            parent->emitDataChanged(lowerIndex);

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

GiftCardTableModel::GiftCardTableModel(GiftCardDataManager gcdb, WalletModel *parent) :
    QAbstractTableModel(parent),walletModel(parent),gcdb(gcdb),priv(0)
{
    columns << tr("Label") << tr("Address") << tr("Generated") << tr("Balance");

    priv = new GiftCardTablePriv(gcdb, this);
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
        case Generated:
            return rec->generated;
        case Balance:
            return rec->balance;
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
    else if (role == Qt::TextAlignmentRole) {
        if (index.column() == Balance)
            return Qt::AlignRight;
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
        case Generated:
        case Balance:
            updateEntry(rec->address, value.toString(), rec->generated, rec->balance, CT_UPDATED);
            break;
        case Address:
//          Can't edit addresses / left as placeholder
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
//        retval |= Qt::ItemIsEditable;
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

void GiftCardTableModel::updateEntry(const QString &address, const QString &label, const QString &generated, const float balance, int status)
{
    priv->updateEntry(address, label, generated, balance, status);
    emitDataChanged(lookupAddress(address));
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

//        printf("Address: %s\tPrivkey: %s\n", strPubKey, strPrivKey);
        strAddress = std::string(strPubKey);
        gcdb.addCard(QString::fromStdString(std::string(strPubKey)), QString::fromStdString(std::string(strPrivKey)), label);
    }
    else
    {
        return QString();
    }

    updateEntry(QString::fromStdString(strAddress), label, QString(""), 0.0, CT_NEW);

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

    updateEntry(rec->address, rec->label, rec->generated, rec->balance, CT_DELETED);

    return true;
}

/* Look up label for address in address book, if not found return empty string.
 */
QString GiftCardTableModel::labelForAddress(const QString &address) const
{
    QString label;

    if (gcdb.readCardAttVal(address, "label", label)) {
        return label;
    } else
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

void GiftCardTableModel::refreshAddressTable(void)
{
    priv->refreshAddressTable();
}

GiftCardDataManager GiftCardTableModel::giftCardDataBase(void)
{
    return gcdb;
}
