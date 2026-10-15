#include "hashworker.h"

#include <QByteArray>
#include <QFile>
#include <QThread>

HashWorker::HashWorker(const QString &filePath, QCryptographicHash::Algorithm algorithm, QObject *parent)
    : QObject(parent), m_filePath(filePath), m_algoritm(algorithm){

}

void HashWorker::process() {

    QFile file(m_filePath);

    if (!file.open(QIODevice::ReadOnly)) {
        emit hashFailed(file.errorString());
        return;
    }

    QCryptographicHash hash(m_algoritm);

    constexpr qint64 chunkSize = 1024 * 1024;

    const qint64 totalBytes = file.size();
    qint64 bytesProcessed = 0;

    int lastPercentage = 0;
    emit progressChanged(0);

    while (!file.atEnd()) {
        if (QThread::currentThread()->isInterruptionRequested()) {
            emit hashFailed("Hash calculation cancelled");
            return;
        }

        const QByteArray chunk = file.read(chunkSize);

        if (file.error() != QFileDevice::NoError || chunk.isEmpty()) {
            emit hashFailed("File read failed or file changed: " + file.errorString());
            return;
        }

        hash.addData(chunk);

        bytesProcessed += chunk.size();

        if (totalBytes > 0) {
            const int percentage = qBound(0, static_cast<int>((100.0 * bytesProcessed) / totalBytes), 100);

            if (percentage != lastPercentage) {
                lastPercentage = percentage;
                emit progressChanged(percentage);
            }
        }
    }

    if (bytesProcessed != totalBytes) {
        emit hashFailed("File size changed during hashing.");
        return;
    }

    const QString checksum = QString::fromLatin1(hash.result().toHex());

    emit progressChanged(100);
    emit hashFinished(checksum);
}
