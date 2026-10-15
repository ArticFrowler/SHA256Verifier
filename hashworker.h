#ifndef HASHWORKER_H
#define HASHWORKER_H

#include <QObject>
#include <QString>
#include <QCryptographicHash>

class HashWorker : public QObject
{
    Q_OBJECT

public:
    explicit HashWorker(const QString &filePath, QCryptographicHash::Algorithm algorithm, QObject *parent = nullptr);


signals:
    void progressChanged(int perctantage);

    void hashFinished(const QString &checksum);

    void hashFailed(const QString &errorMessage);

private:
    QString m_filePath;
    QCryptographicHash::Algorithm m_algoritm;

public slots:
    void process();
};

#endif // HASHWORKER_H
