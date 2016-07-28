#include "giftcarddatamanager.h"

#include <QFile>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QVariant>

#include <iostream>
#include <string>
#include <curl/curl.h>

static std::string readBuffer;

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size*nmemb);
    return size * nmemb;
}

GiftCardDataManager::GiftCardDataManager()
{

}

GiftCardDataManager::GiftCardDataManager(QSqlDatabase qdb, bool &firstRun) :
    gdb(qdb)
{
    if (firstRun)
        initSchema();
}

GiftCardDataManager::GiftCardDataManager(const QString &path, bool &firstRun) :
    gdbFilename(path)
{
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


bool GiftCardDataManager::addCard(const QString &pubkey, const QString &privkey, const QString &label, const QString &filename)
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

bool GiftCardDataManager::updateCard(const QString &pubkey, const QString &label, const QString &filename)
{
    bool success = false;
    float       balance=0.0;
    QString     sql;
    QSqlQuery   query;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    query.prepare("SELECT id FROM giftcards WHERE pubkey=(:pubkey)");
    query.bindValue(":pubkey", pubkey);

    if (query.exec()) {
        int idField = query.record().indexOf("id");
//        printf("idField = %d\n", idField);
        if (query.next()) {
            QString idx = query.value(idField).toString();
//            printf("idx = %s\n", idx.toStdString().c_str());
            sql = "UPDATE giftcards SET generated=DateTime('now'),label=(:label),balance=(:balance)";
            if (filename != "")
                sql += ",filename=(:filename)";
            sql += " WHERE id=(:id)";
            query.prepare(sql);
            query.bindValue(":label", label);
            query.bindValue(":filename", filename);

            balance = getBalance(pubkey);

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


bool GiftCardDataManager::readCard(const QString &pubkey,  GiftCardDataEntry &card)
{
    bool success = false;
    QSqlQuery query;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    query.prepare("SELECT privkey, label, filename, balance, generated FROM giftcards WHERE pubkey=(:pubkey)");
    query.bindValue(":pubkey", pubkey);

    if (query.exec()) {
        if (query.next()) {
            card.pubkey = pubkey;

            QString tkey = query.value(0).toString();
            card.privkey = tkey;
//            printf("privKey = %s\n", card.privkey.toStdString().c_str());

            QString tlabel = query.value(1).toString();
            card.label = tlabel;
//            printf("label = %s\n", card.label.toStdString().c_str());

            QString tfile = query.value(2).toString();
            card.filename = tfile;
//            printf("fileName = %s\n", card.filename.toStdString().c_str());

            QString tbalance = query.value(3).toString();
            card.balance =  tbalance.toFloat();
//            card.balance =  updateBalance(pubkey);
            printf("balance = %.2f\n", card.balance);

            QString tgenerated = query.value(4).toString();
            card.generated = tgenerated;
            printf("generated = %s\n", card.generated.toStdString().c_str());

            success = true;
        }
    } else {
        printf("! Unable to read card from database\n");
    }

    return success;
}

bool GiftCardDataManager::readCardAttVal(const QString &pubkey,  const QString &att, QString &val) const
{
    bool success = false;
    QSqlQuery query;
    QString sql;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    sql = "SELECT " + att + " FROM giftcards where pubkey=(:pubkey)";
    query.prepare(sql);
    query.bindValue(":pubkey", pubkey);

    if (query.exec()) {
        if (query.next()) {
            QString tkey = query.value(0).toString();
            val = tkey;
            success = true;
        }
    } else {
        printf("! Unable to read card from database\n");
    }

    return success;
}

bool GiftCardDataManager::allCards(QList<GiftCardDataEntry> &cards, const QString &sortBy)
{
    bool success = false;
    QString   sql;
    QSqlQuery query;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

///    printf("allCards sort by : %s\n", sortBy.toStdString().c_str());

    sql = QString("SELECT id, pubkey, privkey, label, filename, balance, generated FROM giftcards ORDER BY ") + sortBy;
    query.prepare(sql);

    if (query.exec()) {
        while (query.next()) {
            GiftCardDataEntry *entry = new GiftCardDataEntry;

            entry->id = query.value(0).toInt();
            entry->pubkey = query.value(1).toString();
            entry->privkey = query.value(2).toString();
            entry->label = query.value(3).toString();
            entry->filename = query.value(4).toString();
            entry->balance = query.value(5).toFloat();
//            entry->balance = getBalance(entry->pubkey);
            entry->generated = query.value(6).toString();
            cards.append(*entry);
//          printf("%d | %s | %s\n", entry->id, entry->pubkey.toStdString().c_str(), entry->label.toStdString().c_str());
            success = true;
        }
//        printf("QList size : %d\n", cards.size());
//        foreach (GiftCardDataEntry *entry, cards) {
//            printf("%d | %s | %s\n", entry->id, entry->pubkey.toStdString().c_str(), entry->label.toStdString().c_str());
//        }
    } else {
        printf("! Unable to read card from database\n");
    }

    return success;
}

float GiftCardDataManager::getBalance(const QString &pubkey)
{
    QString     url;
    CURL        *curl;
    CURLcode    res;
    float       balance=0.0;
    std::string readBuffer;

    url = QString("http://xtc.inter.com:2751/chain/2GiveCoin/q/addressbalance/") + pubkey;

    curl_global_init(CURL_GLOBAL_ALL);

    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url.toStdString().c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
//    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        balance = ::atof(readBuffer.c_str());
        printf("%s\n", readBuffer.c_str());
    } else {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
    }

    /* cleanup curl stuff */
    curl_easy_cleanup(curl);

    /* we're done with libcurl, so clean it up */
    curl_global_cleanup();

    return balance;
}

bool GiftCardDataManager::updateBalances(void)
{
    QList<GiftCardDataEntry> cards;

    if (allCards(cards,QString("label"))) {
        foreach (GiftCardDataEntry entry, cards) {
            updateCard(entry.pubkey, entry.label);
        }
        return true;
    }
    return false;
}

bool GiftCardDataManager::migrateFromBDB4(CWallet *wallet)
{
    QString empty = QString::fromStdString("");

    LOCK(wallet->cs_wallet);
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, std::string)& item, wallet->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const std::string& strName = item.second;
        QString pubKey = QString::fromStdString(address.ToString());
        QString label = QString::fromStdString(strName);

        if (QString::fromStdString(address.ToString()).contains("Gift"))
            addCard(pubKey, empty, label, empty);
    }

}
