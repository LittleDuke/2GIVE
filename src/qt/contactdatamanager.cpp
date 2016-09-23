#include "contactdatamanager.h"

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

ContactDataManager::ContactDataManager()
{

}

ContactDataManager::ContactDataManager(QSqlDatabase qdb, bool &firstRun) :
    cdb(qdb)
{
    if (firstRun)
        initSchema();
}

ContactDataManager::ContactDataManager(const QString &path, bool &firstRun) :
    cdbFilename(path)
{
    cdb = QSqlDatabase::addDatabase("QSQLITE", "wallet");
    cdb.setDatabaseName(path);

    QFile file(path);
    if (file.exists()) {
        firstRun = false;
    } else {
        firstRun = true;
    }


    if (!cdb.open()) {
        printf("Error: connection with database failed\n");
    } else {
//        printf("Database: connection ok\n");
        if (firstRun)
            initSchema();
    }
}

bool ContactDataManager::initSchema(void)
{
    bool success = false;
    QSqlQuery query(cdb);

    query.prepare("CREATE TABLE contacts (id integer primary key, created datetime default current_timestamp, pubkey text, label text, email text, url text)");

    if (query.exec()) {
        success = true;
    } else {
        printf("! Unable to initialize database schema\n");
    }

    return success;
}


bool ContactDataManager::addContact(const QString &pubkey, const QString &label, const QString &email, const QString &url)
{
    bool success = false;
    QSqlQuery query(cdb);

    query.prepare("INSERT INTO contacts (pubkey, label, email, url) VALUES (:pubkey, :label, :email, :url)");
    query.bindValue(":pubkey", pubkey);
    query.bindValue(":label", label);
    query.bindValue(":email", email);
    query.bindValue(":url", url);

    if (query.exec()) {
        success = true;
    } else {
        printf("! Unable to insert contact into database\n");
    }

    return success;

}

bool ContactDataManager::deleteContact(const QString &pubkey)
{
    bool success = false;
    QSqlQuery query(cdb);

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    query.prepare("SELECT id FROM contacts WHERE pubkey=(:pubkey)");
    query.bindValue(":pubkey", pubkey);

    if (query.exec()) {
        int idField = query.record().indexOf("id");
//        printf("idField = %d\n", idField);
        if (query.next()) {
            query.prepare("DELETE FROM contacts WHERE pubkey=(:pubkey)");
            query.bindValue(":pubkey", pubkey);

            if (query.exec()) {
                success = true;
            } else {
                printf("! Unable to delete contact from database\n");
            }
        }
    }

    return success;
}

bool ContactDataManager::updateContact(const int id, const QString &pubkey, const QString &label, const QString &email, const QString &url)
{
    bool success = false;
    QString     sql;
    QSqlQuery   query(cdb);

    printf("id = \"%d\"\n", id);

    query.prepare("SELECT id FROM contacts WHERE id=(:id)");
    query.bindValue(":id", id);

    if (query.exec()) {
        int idField = query.record().indexOf("id");
//        printf("idField = %d\n", idField);
        if (query.next()) {
            QString idx = query.value(idField).toString();
//            printf("idx = %s\n", idx.toStdString().c_str());
            sql = "UPDATE contacts SET pubkey=(:pubkey), label=(:label), email=(:email), url=(:url)";
            sql += " WHERE id=(:id)";
            query.prepare(sql);
            query.bindValue(":pubkey", pubkey);
            query.bindValue(":label", label);
            query.bindValue(":email", email);
            query.bindValue(":url", url);
            query.bindValue(":id", idx);

            if (query.exec()) {
                success = true;
            } else {
                printf("! Unable to update contact in database\n");
            }
        }
    }

    return success;
}


bool ContactDataManager::readContact(const QString &pubkey,  ContactDataEntry &contact)
{
    bool success = false;
    QSqlQuery query(cdb);

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    query.prepare("SELECT id, label, email, url FROM contacts WHERE pubkey=(:pubkey)");
    query.bindValue(":pubkey", pubkey);

    if (query.exec()) {
        if (query.next()) {
            contact.pubkey = pubkey;

            int tid = query.value(0).toInt();
            contact.id = tid;

            QString tlabel = query.value(1).toString();
            contact.label = tlabel;
//            printf("label = %s\n", contact.label.toStdString().c_str());

            QString tmail = query.value(2).toString();
            contact.email = tmail;
//            printf("email = %s\n", contact.email.toStdString().c_str());

            QString turl = query.value(3).toString();
            contact.url =  turl;
//            printf("url = %s\n", contact.url.toStdString().c_str());

            success = true;
        }
    } else {
        printf("! Unable to read contact from database\n");
    }

    return success;
}

bool ContactDataManager::readContactAttVal(const QString &pubkey,  const QString &att, QString &val) const
{
    bool success = false;
    QSqlQuery query(cdb);
    QString sql;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    sql = "SELECT " + att + " FROM contacts where pubkey=(:pubkey)";
    query.prepare(sql);
    query.bindValue(":pubkey", pubkey);

    if (query.exec()) {
        if (query.next()) {
            QString tkey = query.value(0).toString();
            val = tkey;
            success = true;
        }
    } else {
        printf("! Unable to read contact from database\n");
    }

    return success;
}

bool ContactDataManager::allContacts(QList<ContactDataEntry> &contacts, const QString &sortBy)
{
    bool success = false;
    QString   sql;
    QSqlQuery query(cdb);

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

///    printf("allcontacts sort by : %s\n", sortBy.toStdString().c_str());

    sql = QString("SELECT id, pubkey, label, email, url FROM contacts ORDER BY ") + sortBy;
    query.prepare(sql);

    if (query.exec()) {
        while (query.next()) {
            ContactDataEntry *entry = new ContactDataEntry;

            entry->id = query.value(0).toInt();
            entry->pubkey = query.value(1).toString();
            entry->label = query.value(2).toString();
            entry->email = query.value(3).toString();
            entry->url = query.value(4).toString();
            contacts.append(*entry);
//          printf("%d | %s | %s\n", entry->id, entry->pubkey.toStdString().c_str(), entry->label.toStdString().c_str());
            success = true;
        }
//        printf("QList size : %d\n", contacts.size());
//        foreach (ContactDataEntry *entry, contacts) {
//            printf("%d | %s | %s\n", entry->id, entry->pubkey.toStdString().c_str(), entry->label.toStdString().c_str());
//        }
    } else {
        printf("! Unable to read contact from database\n");
    }

    return success;
}

float ContactDataManager::getBalance(const QString &pubkey)
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


bool ContactDataManager::migrateFromBDB4(CWallet *wallet)
{
    QString empty = QString::fromStdString("");

    LOCK(wallet->cs_wallet);
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, std::string)& item, wallet->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        const std::string& strName = item.second;
        QString pubKey = QString::fromStdString(address.ToString());
        QString label = QString::fromStdString(strName);

        if (!QString::fromStdString(address.ToString()).contains("Gift"))
            addContact(pubKey, label);
    }

}
