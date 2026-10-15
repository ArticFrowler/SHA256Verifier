#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QCryptographicHash>
#include <QPixmap>
#include <QList>

class QLineEdit;
class QResizeEvent;
class QThread;
class QPushButton;

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class QProgressBar;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void resizeEvent(QResizeEvent *event) override;
    void dragEnterEvent(QDragEnterEvent *event) override;
    void dropEvent(QDropEvent *event) override;

private:
    Ui::MainWindow *ui;

    QString m_selectedFilePath;
    QPixmap m_previewPixmap;
    QList<QLineEdit *> m_hashOutputs;

    void selectFile();
    void updatePreview();

    void verifyChecksum();

    void loadFile(const QString &path);

    void calculateHash(QCryptographicHash::Algorithm algorithm, QLineEdit *output, const QString &expected = {});

    QString computeHash(const QString &filePath, QCryptographicHash::Algorithm alogrithm);

    QProgressBar *m_progressBar = nullptr;

    QThread *m_hashThread = nullptr;

    QList<QPushButton *> m_hashButtons;

private slots:

};

#endif // MAINWINDOW_H
