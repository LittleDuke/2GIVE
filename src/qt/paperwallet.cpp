// Copyright 2016 Strength in Numbers Foundation

#include "paperwallet.h"

#include <QBuffer>
#include <QFile>
#include <QDir>
#include <QTextStream>
#include <QPixmap>
#include <QUrl>

#include <qrencode.h>

#include <boost/filesystem.hpp>

#include <curl/curl.h>

//extern const boost::filesystem::path &GetDataDir(bool fNetSpecific = true);


PaperWallet::PaperWallet(const QString &filename, const QString &addr, const QString &key, const QString &value, const QString &generated) :
    fileName(filename),
    address(addr),
    privateKey(key),
    amount(value),
    date(generated)
{
    addressURL = "2GIVE:" + address;
    privateKeyURL = "2GIVE:" + privateKey;

    setTemplate("default.html");
}

PaperWallet::PaperWallet(GiftCardDataEntry card)
{
    fileName = card.filename;
    address = card.pubkey;
    privateKey = card.privkey;
    amount = QString::number(card.balance);
    date = card.generated;
    label = card.label;

    addressURL = "2GIVE:" + address;
    privateKeyURL = "2GIVE:" + privateKey;

    setTemplate("default.html");
}

PaperWallet::~PaperWallet()
{

}

bool PaperWallet::setTemplate(const QString &filename)
{
    QString fqnTemplate;


    boost::filesystem::path pathSrc = GetDataDir() / "templates";

    //    printf("pathSrc : %s\n", pathSrc.c_str());

    if (boost::filesystem::is_directory(pathSrc))
        fqnTemplate = QString::fromStdString(pathSrc.string()) + QDir::separator() + filename;
    else
        return false;

//    printf("fqnTemplate : %s\n", fqnTemplate.toStdString().c_str());

    QFile file(fqnTemplate);

    if (file.exists()) {
        templateName = fqnTemplate;
        return true;
    }
    return false;
}

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

bool PaperWallet::updateTemplates(void)
{
    QString  fqnTemplate;
    CURL     *curl;
    CURLcode res;
    FILE     *fp;
    char *url = "http://2Give.Info/templates/default.html";

    boost::filesystem::path pathSrc = GetDataDir() / "templates";

//    printf("pathSrc : %s\n", pathSrc.c_str());

    if (!boost::filesystem::is_directory(pathSrc))
        if (!boost::filesystem::create_directory(pathSrc))
            return false;

    fqnTemplate = QString::fromStdString(pathSrc.string()) + QDir::separator() + "default.html";

    curl = curl_easy_init();
    if (curl) {
        fp = fopen(fqnTemplate.toStdString().c_str(), "wb");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        res = curl_easy_perform(curl);
        /* always cleanup */
        curl_easy_cleanup(curl);
        fclose(fp);
    } else
        return false;

    if (res == CURLE_OK)
        return true;
    else
        return false;
}

bool PaperWallet::genWallet()
{
    QRcode      *codePublic,
                *codePrivate;
    QImage      scaledPublic,
                scaledPrivate;
    QByteArray  byteArrayPublic,
                byteArrayPrivate;
    QBuffer     bufferPublic(&byteArrayPublic),
                bufferPrivate(&byteArrayPrivate);
    QString     htmlTemplate;

    unsigned char *p;


    if ((addressURL != "") && (privateKeyURL != "")) {
        codePublic = QRcode_encodeString(addressURL.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
        if (!codePublic) {
            return false;
        }
        publicImage = QImage(codePublic->width + 8, codePublic->width + 8, QImage::Format_RGB32);
        publicImage.fill(0xffffff);
        p = codePublic->data;
        for (int y = 0; y < codePublic->width; y++) {
            for (int x = 0; x < codePublic->width; x++) {
                publicImage.setPixel(x + 4, y + 4, ((*p & 1) ? 0x0 : 0xffffff));
                p++;
            }
        }

        QRcode_free(codePublic);

        scaledPublic = publicImage.scaledToHeight(256);
        scaledPublic.save(&bufferPublic, "PNG");
        QString publicImageBase64 = QString::fromLatin1(byteArrayPublic.toBase64().data());

        codePrivate = QRcode_encodeString(privateKeyURL.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
        if (!codePrivate) {
            return false;
        }
        privateImage = QImage(codePrivate->width + 8, codePrivate->width + 8, QImage::Format_RGB32);
        privateImage.fill(0xffffff);
        p = codePrivate->data;
        for (int y = 0; y < codePrivate->width; y++) {
            for (int x = 0; x < codePrivate->width; x++) {
                privateImage.setPixel(x + 4, y + 4, ((*p & 1) ? 0x0 : 0xffffff));
                p++;
            }
        }
        QRcode_free(codePrivate);

        scaledPrivate = privateImage.scaledToHeight(256);
        scaledPrivate.save(&bufferPrivate, "PNG");
        QString privateImageBase64 = QString::fromLatin1(byteArrayPrivate.toBase64().data());

        QFile templateFile(templateName);
        if (templateFile.open(QIODevice::ReadOnly)) {
            QTextStream templateStream(&templateFile);
            htmlTemplate = templateStream.readAll();

            htmlTemplate.replace(QString("#PUBLIC_KEY_IMAGE#"), publicImageBase64);
            htmlTemplate.replace(QString("#PUBLIC_KEY_ADDRESS#"), address);
            htmlTemplate.replace(QString("#PRIVATE_KEY_IMAGE#"), privateImageBase64);
            htmlTemplate.replace(QString("#PRIVATE_KEY_ADDRESS#"), privateKey);
            htmlTemplate.replace(QString("#DATE_GENERATED#"), date);
            htmlTemplate.replace(QString("#BALANCE#"), amount);
            htmlTemplate.replace(QString("#LABEL#"), label);
        }

        if (!fileName.isNull()) {
            printf("fileName = %s\n", fileName.toStdString().c_str());

            QFile file(fileName);
            if (file.open(QIODevice::ReadWrite)) {
                QTextStream stream(&file);
                stream << htmlTemplate;
                stream << endl;
            }
        }


       return true;
    }
    return false;
}

