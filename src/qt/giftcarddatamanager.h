#ifndef GIFTCARDDATAMANAGER_H
#define GIFTCARDDATAMANAGER_H

#include <QSqlDatabase>

class GiftCardDataManager
{
public:
    explicit GiftCardDataManager();
    explicit GiftCardDataManager(const QString &path);
    bool addCard(const QString &pubkey, const QString &privkey, const QString &filename, const QString &label);
    bool readCard(const QString &pubkey, QString &privkey, QString &label, QString &filename);
    bool deleteCard(const QString &pubkey, bool deleteFile = false);
    bool updateCard(const QString &pubkey, const QString &label, float balance = 0.0);
private:
    QString         gdbFilename;
    QSqlDatabase    gdb;

    bool initSchema(void);

};

#endif // GIFTCARDDATAMANAGER_H
