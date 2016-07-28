// Copyright 2016 Strength in Numbers Foundation


#ifndef PAPERWALLET_H
#define PAPERWALLET_H

#include "giftcarddatamanager.h"

#include <QDialog>
#include <QImage>

class PaperWallet
{
public:
    explicit PaperWallet(const QString &filename, const QString &addr, const QString &key, const QString &value = "0.0", const QString &generated = "");
    explicit PaperWallet(GiftCardDataEntry card);

    ~PaperWallet();

    bool setTemplate(const QString &filename);
    bool updateTemplates(void);

    bool genWallet();

private slots:

private:
    QString templateName;
    QString fileName;
    QString address;
    QString addressURL;
    QString privateKey;
    QString privateKeyURL;
    QString amount;
    QString date;
    QString label;
    QImage  publicImage;
    QImage  privateImage;
};

#endif // PAPERWALLET_H
