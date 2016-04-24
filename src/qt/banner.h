//#include <QWidget>
//#include <QLabel>
#include <QtGui>
#include <QNetworkAccessManager>
#include <QUrl>
#include <QFile>

#include <boost/filesystem.hpp>

class Banner : public QLabel
{
  Q_OBJECT

public:
  Banner(QWidget * parent = 0);
  ~Banner();

protected slots:
  virtual void enterEvent ( QEvent * event );
  virtual void leaveEvent ( QEvent * event );
  virtual void mouseMoveEvent ( QMouseEvent * event );
  virtual void mousePressEvent ( QMouseEvent * event );
  virtual void mouseReleaseEvent ( QMouseEvent * event );

private slots:
  void updateBanner();
  void download(int state);
  //void cancelDownload();
  void httpFinished();
  void httpReadyRead();
  void updateDataReadProgress(qint64 bytesRead, qint64 totalBytes);

private:
  QUrl url;
  QNetworkAccessManager qnam;
  QNetworkReply *reply;
  QFile *file;
  QTimer * timer;

  boost::filesystem::path tmpPath;

  int state;
};

#define BANNER_DELAY 10000 // ms
