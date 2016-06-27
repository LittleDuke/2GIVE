#include "giftcarddatamanager.h"

#include <QFile>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QVariant>

GiftCardDataManager::GiftCardDataManager()
{

}

GiftCardDataManager::GiftCardDataManager(const QString &path) :
    gdbFilename(path)
{
    bool firstRun;

    gdb = QSqlDatabase::addDatabase("QSQLITE");
    gdb.setDatabaseName(path);

    QFile file(path);
    if (file.exists()) {
        firstRun = false;
    } else {
        firstRun = true;
    }


    if (!gdb.open()) {
        printf("Error: connection with database failed\n");
    } else {
//        printf("Database: connection ok\n");
        if (firstRun)
            initSchema();
    }
}

bool GiftCardDataManager::initSchema(void)
{
    bool success = false;
    QSqlQuery query;

    query.prepare("CREATE TABLE giftcards (id integer primary key, generated datetime default current_timestamp, pubkey text, privkey text, filename text, label text, text template, balance float)");

    if (query.exec()) {
        success = true;
    } else {
        printf("! Unable to initialize database schema\n");
    }

    return success;
}

bool GiftCardDataManager::addCard(const QString &pubkey, const QString &privkey, const QString &filename, const QString &label)
{
    bool success = false;
    QSqlQuery query;

    query.prepare("INSERT INTO giftcards (pubkey, privkey, filename, label) VALUES (:pubkey, :privkey, :filename, :label)");
    query.bindValue(":pubkey", pubkey);
    query.bindValue(":privkey", privkey);
    query.bindValue(":filename", filename);
    query.bindValue(":label", label);

    if (query.exec()) {
        success = true;
    } else {
        printf("! Unable to insert card into database\n");
    }

    return success;

}

bool GiftCardDataManager::deleteCard(const QString &pubkey, bool deleteFile)
{
    bool success = false;
    QSqlQuery query;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    query.prepare("SELECT filename FROM giftcards WHERE pubkey=(:pubkey)");
    query.bindValue(":pubkey", pubkey);

    if (query.exec()) {
        int idField = query.record().indexOf("filename");
//        printf("idField = %d\n", idField);
        if (query.next()) {
            QString fileName = query.value(idField).toString();
//            printf("fileName = %s\n", fileName.toStdString().c_str());

            query.prepare("DELETE FROM giftcards WHERE pubkey=(:pubkey)");
            query.bindValue(":pubkey", pubkey);

            if (query.exec()) {
                if (deleteFile) {
                    QFile file(fileName);
                    if (file.exists()) {
                        file.remove();
                    }
                }
                success = true;
            } else {
                printf("! Unable to delete card from database\n");
            }
        }
    }

    return success;
}

bool GiftCardDataManager::updateCard(const QString &pubkey, const QString &label, float balance)
{
    bool success = false;
    QSqlQuery query;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    query.prepare("SELECT id FROM giftcards WHERE pubkey=(:pubkey)");
    query.bindValue(":pubkey", pubkey);

    if (query.exec()) {
        int idField = query.record().indexOf("id");
//        printf("idField = %d\n", idField);
        if (query.next()) {
            QString idx = query.value(idField).toString();
//            printf("idx = %s\n", idx.toStdString().c_str());

            query.prepare("UPDATE giftcards SET label=(:label),balance=(:balance) WHERE id=(:id)");
            query.bindValue(":label", label);
            query.bindValue(":balance", balance);
            query.bindValue(":id", idx);

            if (query.exec()) {
                success = true;
            } else {
                printf("! Unable to delete card from database\n");
            }
        }
    }

    return success;
}


bool GiftCardDataManager::readCard(const QString &pubkey,  QString &privkey,  QString &label, QString &filename)
{
    bool success = false;
    QSqlQuery query;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    query.prepare("SELECT privkey, label, filename FROM giftcards WHERE pubkey=(:pubkey)");
    query.bindValue(":pubkey", pubkey);

    if (query.exec()) {
        if (query.next()) {
            QString tkey = query.value(0).toString();
            privkey = tkey;
//            printf("privKey = %s\n", privkey.toStdString().c_str());

            QString tlabel = query.value(1).toString();
            label = tlabel;
//            printf("label = %s\n", label.toStdString().c_str());

            QString tfile = query.value(2).toString();
            filename = tfile;
//            printf("fileName = %s\n", filename.toStdString().c_str());

            success = true;
        }
    } else {
        printf("! Unable to read card from database\n");
    }

    return success;
}
