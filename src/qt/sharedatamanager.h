#ifndef SHAREDATAMANAGER_H
#define SHAREDATAMANAGER_H

//#include "walletmodel.h"        // migrateFromBDB4
#include "wallet.h"             // migrateFromBDB4

#include <QSqlDatabase>

struct ShareDataEntry
{
    int     id;
    QString pubkey;
    QString label;
    QString email;
    QString url;
    QString about;
};

class ShareDataManager
{
public:
    explicit ShareDataManager();
    explicit ShareDataManager(const QString &path, bool &firstRun);
    explicit ShareDataManager(QSqlDatabase cdb, bool &firstRun);
    bool addContact(const QString &pubkey, const QString &label, const QString &email = "", const QString &url = "");
//    bool readContact(const QString &pubkey, QString &privkey, QString &label, QString &filename) const;
    bool readContact(const QString &pubkey, ShareDataEntry &contact);
    bool readContactAttVal(const QString &pubkey,  const QString &att, QString &val) const;
    bool deleteContact(const QString &pubkey);
    bool updateContact(const int id, const QString &pubkey, const QString &label, const QString &email = "", const QString &url = "");
    bool allContacts(QList<ShareDataEntry> &contacts, const QString &sortBy);
    float getBalance(const QString &pubkey);
    bool updateBalances(void);
private:
    QString         cdbFilename;
    QSqlDatabase    cdb;

    bool initSchema(void);

};

#endif // SHAREDATAMANAGER_H
