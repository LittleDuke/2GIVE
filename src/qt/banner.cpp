/**
 * ek
 **/
#include <string>
#include <QtGui>
#include <QtNetwork>
#include <QUrl>
#include <QDesktopServices>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include "util.h"
#include "banner.h"

const std::string BANNER_URL = "http://givecoin.io/";
//const std::string BANNER_URL = "http://springboard.sol/";
const std::string FILE_TXT = "banner.txt";
const std::string FILE_IMG = "banner.png";
const std::string FILE_TMP = ".banner.tmp";

enum {IDLE, GET_IMG, GET_TXT };

Banner::Banner(QWidget * parent) : QLabel(parent)
{
  tmpPath = GetDataDir() / "banners";

  if (!boost::filesystem::is_directory(tmpPath))
    boost::filesystem::create_directory(tmpPath);

  state = IDLE;

  timer = new QTimer(this);
  connect(timer, SIGNAL(timeout()), this, SLOT(updateBanner()));
  timer->start(0);

  setCursor(Qt::PointingHandCursor);
}

Banner::~Banner() {
  delete timer;
}

void Banner::enterEvent ( QEvent * event ) {}
void Banner::leaveEvent ( QEvent * event ) {}
void Banner::mouseMoveEvent ( QMouseEvent * event ) {}
void Banner::mousePressEvent ( QMouseEvent * event ) {}
void Banner::mouseReleaseEvent ( QMouseEvent * event )
{
  QDesktopServices::openUrl(url);
} 

void Banner::download(int s)
{
  QUrl u;

  if (state != IDLE)
    return;

  state = s; 
  if(state == GET_IMG)
  {
    u = QString((BANNER_URL + FILE_IMG).c_str());
  }
  else
  {
    u = QString((BANNER_URL + FILE_TXT).c_str());
  }

  boost::filesystem::path tmpfile = tmpPath / FILE_TMP;

  file = new QFile(QString(tmpfile.c_str()));
  if (!file->open(QIODevice::WriteOnly)) {
    delete file;
    file = 0;
    timer->start(BANNER_DELAY);
    return;
  }

  reply = qnam.get(QNetworkRequest(u));
  connect(reply, SIGNAL(finished()),
          this, SLOT(httpFinished()));
  connect(reply, SIGNAL(readyRead()),
          this, SLOT(httpReadyRead()));
  connect(reply, SIGNAL(downloadProgress(qint64,qint64)),
          this, SLOT(updateDataReadProgress(qint64,qint64)));  
}

void Banner::updateBanner()
{
  if (boost::filesystem::exists(tmpPath / FILE_TXT) &&
      boost::filesystem::exists(tmpPath / FILE_IMG))
  {
    QImage image((tmpPath / FILE_IMG).c_str());
    setPixmap(QPixmap::fromImage(image));

    QFile inputFile((tmpPath / FILE_TXT).c_str());
    if (inputFile.open(QIODevice::ReadOnly))
    {
       QTextStream in(&inputFile);
       while ( !in.atEnd() )
       {
          QString line = in.readLine();
          url = QUrl(line, QUrl::TolerantMode);
       }
       inputFile.close();
    }
  }
  download(GET_IMG);
  timer->start(BANNER_DELAY);

}

void Banner::httpFinished()
{
  file->flush();
  file->close();

  if(state == GET_IMG)
  { 
    boost::filesystem::rename(tmpPath / FILE_TMP, tmpPath / FILE_IMG);
    state = IDLE;
    download(GET_TXT);
  }
  else
  {
    boost::filesystem::rename(tmpPath / FILE_TMP, tmpPath / FILE_TXT);
    updateBanner();
    state = IDLE;
  }
}

void Banner::httpReadyRead()
{
  if (file)
    file->write(reply->readAll());
}

void Banner::updateDataReadProgress(qint64 bytesRead, qint64 totalBytes) {}
