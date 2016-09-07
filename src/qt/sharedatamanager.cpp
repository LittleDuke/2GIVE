#include "sharedatamanager.h"

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

ShareDataManager::ShareDataManager()
{

}

ShareDataManager::ShareDataManager(QSqlDatabase qdb, bool &firstRun) :
    cdb(qdb)
{
    if (firstRun)
        initSchema();
}

ShareDataManager::ShareDataManager(const QString &path, bool &firstRun) :
    cdbFilename(path)
{
    cdb = QSqlDatabase::addDatabase("QSQLITE");
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

bool ShareDataManager::initSchema(void)
{
    bool success = false;
    QSqlQuery query;

    query.prepare("CREATE TABLE share (id integer primary key, created datetime default current_timestamp, pubkey text, label text, email text, url text, about text)");

    if (query.exec()) {
        success = true;
    } else {
        printf("! Unable to initialize database schema\n");
    }

    return success;
}


bool ShareDataManager::addContact(const QString &pubkey, const QString &label, const QString &email, const QString &url)
{
    bool success = false;
    QSqlQuery query;

    query.prepare("INSERT INTO share (pubkey, label, email, url) VALUES (:pubkey, :label, :email, :url)");
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

bool ShareDataManager::deleteContact(const QString &pubkey)
{
    bool success = false;
    QSqlQuery query;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    query.prepare("SELECT id FROM share WHERE pubkey=(:pubkey)");
    query.bindValue(":pubkey", pubkey);

    if (query.exec()) {
        int idField = query.record().indexOf("id");
//        printf("idField = %d\n", idField);
        if (query.next()) {
            query.prepare("DELETE FROM share WHERE pubkey=(:pubkey)");
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

bool ShareDataManager::updateContact(const int id, const QString &pubkey, const QString &label, const QString &email, const QString &url)
{
    bool success = false;
    QString     sql;
    QSqlQuery   query;

    printf("id = \"%d\"\n", id);

    query.prepare("SELECT id FROM share WHERE id=(:id)");
    query.bindValue(":id", id);

    if (query.exec()) {
        int idField = query.record().indexOf("id");
//        printf("idField = %d\n", idField);
        if (query.next()) {
            QString idx = query.value(idField).toString();
//            printf("idx = %s\n", idx.toStdString().c_str());
            sql = "UPDATE share SET pubkey=(:pubkey), label=(:label), email=(:email), url=(:url)";
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


bool ShareDataManager::readContact(const QString &pubkey,  ShareDataEntry &contact)
{
    bool success = false;
    QSqlQuery query;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    query.prepare("SELECT id, label, email, url FROM share WHERE pubkey=(:pubkey)");
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

bool ShareDataManager::readContactAttVal(const QString &pubkey,  const QString &att, QString &val) const
{
    bool success = false;
    QSqlQuery query;
    QString sql;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

    sql = "SELECT " + att + " FROM share where pubkey=(:pubkey)";
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

bool ShareDataManager::allContacts(QList<ShareDataEntry> &share, const QString &sortBy)
{
    bool success = false;
    QString   sql;
    QSqlQuery query;

//    printf("pubkey = \"%s\"\n", pubkey.toStdString().c_str());

///    printf("allshare sort by : %s\n", sortBy.toStdString().c_str());

    sql = QString("SELECT id, pubkey, label, email, url FROM share ORDER BY ") + sortBy;
    query.prepare(sql);

    if (query.exec()) {
        while (query.next()) {
            ShareDataEntry *entry = new ShareDataEntry;

            entry->id = query.value(0).toInt();
            entry->pubkey = query.value(1).toString();
            entry->label = query.value(2).toString();
            entry->email = query.value(3).toString();
            entry->url = query.value(4).toString();
            share.append(*entry);
//          printf("%d | %s | %s\n", entry->id, entry->pubkey.toStdString().c_str(), entry->label.toStdString().c_str());
            success = true;
        }
//        printf("QList size : %d\n", share.size());
//        foreach (ShareDataEntry *entry, share) {
//            printf("%d | %s | %s\n", entry->id, entry->pubkey.toStdString().c_str(), entry->label.toStdString().c_str());
//        }
    } else {
        printf("! Unable to read contact from database\n");
    }

    return success;
}

float ShareDataManager::getBalance(const QString &pubkey)
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


