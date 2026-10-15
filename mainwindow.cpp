#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "hashworker.h"


#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFile>
#include <QFileIconProvider>
#include <QFileInfo>
#include <QImageReader>
#include <QLineEdit>
#include <QLocale>
#include <QMessageBox>
#include <QMimeData>
#include <QMimeDatabase>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QSizePolicy>
#include <QStatusBar>
#include <QThread>
#include <QUrl>


MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    m_progressBar = new QProgressBar(this);
    ui->algorithmComboBox->clear();
    setAcceptDrops(true);

    //Progress Bar
    m_progressBar->setRange(0, 100);
    m_progressBar->setValue(0);
    m_progressBar->setFixedWidth(170);
    m_progressBar->setTextVisible(true);

    statusBar()->addPermanentWidget(m_progressBar);

    m_progressBar->hide();

    //Configure SHA combo box
    ui->algorithmComboBox->addItem("SHA-1", static_cast<int>(QCryptographicHash::Sha1));
    ui->algorithmComboBox->addItem("SHA-224", static_cast<int>(QCryptographicHash::Sha224));
    ui->algorithmComboBox->addItem("SHA-256", static_cast<int>(QCryptographicHash::Sha256));
    ui->algorithmComboBox->addItem("SHA-384", static_cast<int>(QCryptographicHash::Sha384));
    ui->algorithmComboBox->addItem("SHA-512", static_cast<int>(QCryptographicHash::Sha512));
    ui->algorithmComboBox->addItem("SHA3-256", static_cast<int>(QCryptographicHash::Sha3_256));
    ui->algorithmComboBox->addItem("SHA3-512", static_cast<int>(QCryptographicHash::Sha3_512));

    auto resetVerification = [this]() {
        ui->verificationStatus->setText("Not Verified");
        ui->verificationStatus->setStyleSheet("");
    };

    //Configure Image preview
    ui->previewLabel->setAlignment(Qt::AlignCenter);
    ui->previewLabel->setScaledContents(false);
    ui->previewLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    ui->previewLabel->setText("Select a file");

    //File Selection Button
    connect(ui->selectFileButton, &QPushButton::clicked, this, &MainWindow::selectFile);

    //Ties each button to its algorithm and output
    struct HashControl {
        QPushButton *button;
        QLineEdit *output;
        QCryptographicHash::Algorithm algorithm;
    };

    const HashControl controls[] ={
        {ui->sha1Button, ui->sha1Output, QCryptographicHash::Sha1},
        {ui->sha224Button, ui->sha224Output, QCryptographicHash::Sha224},
        {ui->sha256Button, ui->sha256Output, QCryptographicHash::Sha256},
        {ui->sha384Button, ui->sha384Output, QCryptographicHash::Sha384},
        {ui->sha512Button, ui->sha512Output, QCryptographicHash::Sha512},
        {ui->sha3256Button, ui->sha3256Output, QCryptographicHash::Sha3_256},
        {ui->sha3512Button, ui->sha3512Output, QCryptographicHash::Sha3_512}
    };

    connect(ui->verifyButton, &QPushButton::clicked, this, &MainWindow::verifyChecksum);

    //Rest verification status if input or drop down changes
    connect(ui->expectedChecksum, &QLineEdit::textChanged, this, resetVerification);
    connect(ui->algorithmComboBox, &QComboBox::currentTextChanged, this, resetVerification);

    //Connect all hash buttons to one function
    for (const auto &control : controls) {
        control.output->setReadOnly(true);
        control.output->setAcceptDrops(false);

        control.output->setPlaceholderText("Not calculated");

        m_hashOutputs.append(control.output);
        m_hashButtons.append(control.button);

        connect(control.button, &QPushButton::clicked, this, [this, algorithm = control.algorithm, output = control.output]()
                {

            statusBar()->showMessage("Calculating checksum");

            calculateHash(algorithm, output);
        });
    }

    statusBar()->showMessage("Select a file to begin");
}

MainWindow::~MainWindow()
{
    if (m_hashThread != nullptr) {
        m_hashThread->requestInterruption();
        m_hashThread->quit();
        m_hashThread->wait();
    }

    delete ui;
}


void MainWindow::selectFile() {
    const QString path = QFileDialog::getOpenFileName(
        this, "Select a File.", m_selectedFilePath.isEmpty() ? QString() : QFileInfo(m_selectedFilePath).absolutePath());

    if (path.isEmpty())
        return;

    loadFile(path);


}

void MainWindow::loadFile(const QString &path) {
    if (m_hashThread != nullptr) {
        return;
    }

    QFileInfo info(path);

    if (!info.isFile() || !info.isReadable()) {
        QMessageBox::warning(this, "File Error", "The selected file cannot be read");
        return;
    }

    //Store the selected file
    m_selectedFilePath = info.absoluteFilePath();

    //Populate the metadata labels
    ui->fileNameLabel->setText(info.fileName());
    ui->fileSizeLabel->setText(QLocale().formattedDataSize(info.size()));
    ui->filePathLabel->setText(info.absolutePath());
    QMimeDatabase mimeDatabase;
    ui->fileTypeLabel->setText(mimeDatabase.mimeTypeForFile(info).name());
    ui->modifiedLabel->setText(QLocale().toString(info.lastModified(), QLocale::ShortFormat));
    ui->createdLabel->setText(QLocale().toString(info.birthTime(), QLocale::ShortFormat));

    //Clear Results from previously selected file
    for (QLineEdit *output : m_hashOutputs) {
        output->clear();
    }

    //Read icon preview when supported
    QFileIconProvider iconProvider;

    QIcon fileIcon = iconProvider.icon(info);

    //Store the file icon as a pixmap
    m_previewPixmap = fileIcon.pixmap(128,128);

    //Update Preview Label
    updatePreview();

    ui->verificationStatus->setText("Not Verified");
    ui->verificationStatus->setStyleSheet("");

    statusBar()->showMessage("Selected: " + info.fileName(), 3000);
}

void MainWindow::updatePreview() {
    if (m_selectedFilePath.isEmpty()) {
        ui->previewLabel->setText("Select a file");
        return;
    }

    if (m_previewPixmap.isNull()) {
        ui->previewLabel->setText("no image preview available");
        return;
    }

    const QSize size = ui->previewLabel->contentsRect().size();

    if (size.isEmpty())
        return;

    ui->previewLabel->setPixmap(m_previewPixmap.scaled(size, Qt::KeepAspectRatio, Qt::SmoothTransformation));
}

void MainWindow::resizeEvent(QResizeEvent *event) {
    QMainWindow::resizeEvent(event);
    updatePreview();
}

//Calculate Hash method
void MainWindow::calculateHash(QCryptographicHash::Algorithm algorithm, QLineEdit *output, const QString &expected){
    //Require a selected file
    //If the file has not been selected, populate message box with message
    if (m_selectedFilePath.isEmpty()){
        QMessageBox::information(this, "No File Selected", "Please select a file");
        return;
    }

    if (m_hashThread != nullptr) {
        return;
    }

    if (output != nullptr) {
        output->clear();
    } else {
        ui->verificationStatus->setText("Calculating...");

        ui->verificationStatus->setStyleSheet("");
    }

    m_progressBar->setValue(0);
    m_progressBar->show();

    for (QPushButton *button : m_hashButtons) {
        button->setEnabled(false);
    }

    ui->selectFileButton->setEnabled(false);
    ui->verifyButton->setEnabled(false);
    ui->expectedChecksum->setEnabled(false);
    ui->algorithmComboBox->setEnabled(false);

    QThread *thread = new QThread(this);

    HashWorker *worker = new HashWorker(m_selectedFilePath, algorithm);

    m_hashThread = thread;

    worker->moveToThread(thread);

    //Sets the hash process to its thread
    connect(thread, &QThread::started, worker, &HashWorker::process);

    //Connects hash worker progress to the UI progress bar
    connect(worker, &HashWorker::progressChanged, m_progressBar, &QProgressBar::setValue);

    //Connects the success of the hash worker to the UI
    connect(worker, &HashWorker::hashFinished, this, [this, output, expected](const QString &checksum) {
        if (output != nullptr) {
            output->setText(checksum);

            statusBar()->showMessage("Checksum calculated successfully", 3000);
            return;
        }

        const bool matches = expected.compare(checksum, Qt::CaseInsensitive) == 0;

        if (matches) {
            ui->verificationStatus->setText("✓ Verified");
            ui->verificationStatus->setStyleSheet("color: #16a34a; font-weight: bold;");
        } else {
            ui->verificationStatus->setText("🗴 Mismatch");
            ui->verificationStatus->setStyleSheet("color: #dc2626; font-weight: bold;");
        }

        statusBar()->showMessage("Checksum calculated successfully", 3000);
    });

    //Connects hash worker to error reporting.
    connect(worker, &HashWorker::hashFailed, this, [this, output](const QString &message) {
        if (output == nullptr) {
            ui->verificationStatus->setText("Verification could not complete");
            ui->verificationStatus->setStyleSheet("");
        }

        QMessageBox::warning(this, "Hash Error", message);
    });

    //Handles the finishing/failing of the hash worker
    connect(worker, &HashWorker::hashFinished, thread, &QThread::quit);
    connect(worker, &HashWorker::hashFailed, thread, &QThread::quit);

    //When the thread and worker have finished this sets the thread as safe to delete
    connect(thread, &QThread::finished, worker, &QObject::deleteLater);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);

    connect(thread, &QThread::finished, this, [this]() {
        m_hashThread = nullptr;

        for (QPushButton *button : m_hashButtons) {
            button->setEnabled(true);
        }

        ui->selectFileButton->setEnabled(true);
        ui->verifyButton->setEnabled(true);
        ui->expectedChecksum->setEnabled(true);
        ui->algorithmComboBox->setEnabled(true);

        m_progressBar->hide();
    });

    thread->start();

    /*
    output->setText(result);

    //Updates the status bar to display the completion status of the hash
    statusBar()->showMessage("Checksum calculated successfully", 3000);
    */
}

void MainWindow::verifyChecksum() {
    const QString expected = ui->expectedChecksum->text().trimmed();

    const auto algorithm = static_cast<QCryptographicHash::Algorithm>(ui->algorithmComboBox->currentData().toInt());

    const int requiredLength = QCryptographicHash::hashLength(algorithm) * 2;

    if (m_selectedFilePath.isEmpty()) {
        ui->verificationStatus->setText("Select a file first");
        return;
    }

    if (expected.isEmpty()) {
        ui->verificationStatus->setText("Enter a checksum");
        return;
    }

    if (expected.length() != requiredLength) {
        ui->verificationStatus->setText("Invalid Checksum Length");
        return;
    }

    const QRegularExpression hexPattern("^[0-9a-fA-F]+$");

    if (!hexPattern.match(expected).hasMatch()) {
        ui->verificationStatus->setText("Invalid checksum characters");
        return;
    }

    calculateHash(algorithm, nullptr, expected);
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event) {
    const QList<QUrl> urls = event->mimeData()->urls();

    if (urls.size() == 1 && urls.first().isLocalFile() && QFileInfo(urls.first().toLocalFile()).isFile()) {
            event->acceptProposedAction();
        } else {
        event->ignore();
    }
}

void MainWindow::dropEvent(QDropEvent *event) {
    const QList<QUrl> urls = event->mimeData()->urls();

    if (urls.size() != 1 || ! urls.first().isLocalFile()) {
        event->ignore();
        return;
    }

    const QString filePath = urls.first().toLocalFile();

    if (!QFileInfo(filePath).isFile()){
        event->ignore();
        return;
    }

    loadFile(filePath);

    event->acceptProposedAction();
}