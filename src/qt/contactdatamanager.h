#ifndef CONTACTDATAMANAGER_H
#define CONTACTDATAMANAGER_H

//#include "walletmodel.h"        // migrateFromBDB4
#include "wallet.h"             // migrateFromBDB4

#include <QSqlDatabase>

struct ContactDataEntry
{
    int     id;
    QString pubkey;
    QString label;
    QString email;
    QString url;
};

class ContactDataManager
{
public:
    explicit ContactDataManager();
    explicit ContactDataManager(const QString &path, bool &firstRun);
    explicit ContactDataManager(QSqlDatabase cdb, bool &firstRun);
    bool addContact(const QString &pubkey, const QString &label, const QString &email = "", const QString &url = "");
//    bool readContact(const QString &pubkey, QString &privkey, QString &label, QString &filename) const;
    bool readContact(const QString &pubkey, ContactDataEntry &contact);
    bool readContactAttVal(const QString &pubkey,  const QString &att, QString &val) const;
    bool deleteContact(const QString &pubkey);
    bool updateContact(const int id, const QString &pubkey, const QString &label, const QString &email = "", const QString &url = "");
    bool allContacts(QList<ContactDataEntry> &contacts, const QString &sortBy);
    float getBalance(const QString &pubkey);
    bool updateBalances(void);
    bool migrateFromBDB4(CWallet *wallet);
private:
    QString         cdbFilename;
    QSqlDatabase    cdb;

    bool initSchema(void);

};

#endif // CONTACTDATAMANAGER_H
