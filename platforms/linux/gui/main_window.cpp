#include "main_window.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QKeySequence>
#include <QLineEdit>
#include <QMessageBox>
#include <QShortcut>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>

#include "zd/theme.hpp"
#include "zd/ui_model.hpp"

namespace zd {
namespace linux_gui {

namespace {

// Update an existing QTableWidgetItem in place or allocate one if absent (avoids recreating
// thousands of items every tick).
QTableWidgetItem* setCellText(QTableWidget* tbl, int row, int col, const QString& text) {
    QTableWidgetItem* item = tbl->item(row, col);
    if (item == nullptr) {
        item = new QTableWidgetItem(text);
        tbl->setItem(row, col, item);
    } else if (item->text() != text) {
        item->setText(text);
    }
    return item;
}

// High-contrast badge styling (>= 6.5:1 on both light and dark system themes).
void styleWarnBadge(QTableWidgetItem* item, bool active) {
    if (active) {
        item->setBackground(QColor(255, 243, 205));
        item->setForeground(QColor(122, 62, 0));
    } else {
        item->setData(Qt::BackgroundRole, QVariant());
        item->setData(Qt::ForegroundRole, QVariant());
    }
}

void styleAllowedBadge(QTableWidgetItem* item, bool active) {
    if (active) {
        item->setBackground(QColor(220, 252, 231));
        item->setForeground(QColor(20, 83, 45));
    } else {
        item->setData(Qt::BackgroundRole, QVariant());
        item->setData(Qt::ForegroundRole, QVariant());
    }
}

}  // namespace

MainWindow::MainWindow(linux_app::AppController& app, QWidget* parent)
    : QMainWindow(parent), app_(app) {
    setWindowTitle("pwnagotchi-zeroday — Linux");
    resize(1080, 660);

    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);

    // --- Top strip: pet screen + status + controls ---
    auto* top = new QHBoxLayout();
    pet_ = new PetWidget(central);
    top->addWidget(pet_, 3);

    auto* statusBox = new QVBoxLayout();
    auto* statusHeader = new QHBoxLayout();
    status_ = new QLabel("booting…", central);
    status_->setTextFormat(Qt::PlainText);
    status_->setStyleSheet("font-weight:bold; font-size:14px;");
    secMoodLabel_ = new QLabel("SEC: CALM", central);
    secMoodLabel_->setTextFormat(Qt::PlainText);
    secMoodLabel_->setStyleSheet(
        "font-weight:bold; padding:2px 6px; border-radius:4px; background:#145a32; color:#ffffff;");
    lastSecMoodStyled_ = static_cast<int>(sec::SecMood::Calm);
    statusHeader->addWidget(status_, 1);
    statusHeader->addWidget(secMoodLabel_, 0);

    phrase_ = new QLabel("", central);
    phrase_->setTextFormat(Qt::PlainText);
    phrase_->setWordWrap(true);
    engineLabel_ = new QLabel("", central);
    engineLabel_->setTextFormat(Qt::PlainText);
    statusBox->addLayout(statusHeader);
    statusBox->addWidget(phrase_);
    statusBox->addWidget(engineLabel_);

    auto* btnRow = new QHBoxLayout();
    auto* scanBtn = new QPushButton("&Scan", central);
    monitorBtn_ = new QPushButton("Start &Monitor", central);
    auto* prevThemeBtn = new QPushButton("◀ Theme", central);
    prevThemeBtn->setAccessibleName("Previous Theme");
    auto* themeBtn = new QPushButton("Theme ▶", central);
    themeBtn->setAccessibleName("Next Theme");
    auto* viewBtn = new QPushButton("&View", central);
    auto* loadBtn = new QPushButton("&Load…", central);
    auto* saveBtn = new QPushButton("Sa&ve…", central);
    btnRow->addWidget(scanBtn);
    btnRow->addWidget(monitorBtn_);
    btnRow->addWidget(prevThemeBtn);
    btnRow->addWidget(themeBtn);
    btnRow->addWidget(viewBtn);
    btnRow->addWidget(loadBtn);
    btnRow->addWidget(saveBtn);
    statusBox->addLayout(btnRow);

    // Channel control strip for monitor mode.
    auto* chRow = new QHBoxLayout();
    auto* chLabel = new QLabel("Monitor &channel:", central);
    channelSpin_ = new QSpinBox(central);
    channelSpin_->setRange(1, 177);
    channelSpin_->setValue(6);
    channelSpin_->setAccessibleName("Monitor Channel");
    chLabel->setBuddy(channelSpin_);
    channelBtn_ = new QPushButton("Set Channel", central);
    channelBtn_->setEnabled(false);
    chRow->addWidget(chLabel);
    chRow->addWidget(channelSpin_);
    chRow->addWidget(channelBtn_);
    chRow->addStretch(1);
    statusBox->addLayout(chRow);

    // --- Authorization / offensive panel ---
    auto* authGroup = new QGroupBox("Offensive controls (authorized use only)", central);
    auto* authLayout = new QVBoxLayout(authGroup);
    authBanner_ = new QLabel(central);
    authBanner_->setTextFormat(Qt::PlainText);
    authBanner_->setWordWrap(true);
    authCheck_ = new QCheckBox("I am authorized to transmit against the allow-listed targets",
                               central);
    auto* allowBtn = new QPushButton("&Allow / Remove BSSID", central);
    deauthBtn_ = new QPushButton("&Deauth selected…", central);
    deauthBtn_->setStyleSheet("font-weight:bold;");
    deauthBtn_->setEnabled(false);
    authLayout->addWidget(authBanner_);
    authLayout->addWidget(authCheck_);
    auto* authBtnRow = new QHBoxLayout();
    authBtnRow->addWidget(allowBtn);
    authBtnRow->addWidget(deauthBtn_);
    authLayout->addLayout(authBtnRow);
    statusBox->addWidget(authGroup);

    channelsLabel_ = new QLabel(central);
    channelsLabel_->setTextFormat(Qt::PlainText);
    channelsLabel_->setWordWrap(true);
    channelsLabel_->setStyleSheet("font-family:monospace;");
    statusBox->addWidget(channelsLabel_);
    statusBox->addStretch(1);

    top->addLayout(statusBox, 2);
    root->addLayout(top, 2);

    // --- Bottom: tabbed network + station tables & defensive alerts ---
    auto* split = new QSplitter(Qt::Horizontal, central);

    tabs_ = new QTabWidget(split);
    table_ = new QTableWidget(0, 9, tabs_);
    table_->setHorizontalHeaderLabels(
        {"BSSID", "SSID", "CH", "dBm", "ENC", "WPS", "Clients", "Capture", "Allowed"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tabs_->addTab(table_, "Networks (0)");

    stationsTable_ = new QTableWidget(0, 5, tabs_);
    stationsTable_->setHorizontalHeaderLabels(
        {"Station MAC", "Associated BSSID", "Probes", "Risk", "Probed SSIDs"});
    stationsTable_->horizontalHeader()->setStretchLastSection(true);
    stationsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    stationsTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    stationsTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tabs_->addTab(stationsTable_, "Stations / Probes (0)");

    split->addWidget(tabs_);

    auto* alertBox = new QWidget(split);
    auto* alertLayout = new QVBoxLayout(alertBox);
    auto* alertTitle = new QLabel("Defensive alerts", alertBox);
    alerts_ = new QListWidget(alertBox);
    alerts_->setAccessibleName("Defensive alerts list");
    alertTitle->setBuddy(alerts_);
    alertLayout->addWidget(alertTitle);
    alertLayout->addWidget(alerts_);
    split->addWidget(alertBox);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 2);
    root->addWidget(split, 3);

    setCentralWidget(central);
    statusBar()->showMessage(QString("Audit log: %1").arg(QString::fromStdString(app_.auditPath())));

    // --- Wiring & Keyboard Shortcuts ---
    connect(scanBtn, &QPushButton::clicked, this, &MainWindow::onScan);
    connect(monitorBtn_, &QPushButton::clicked, this, &MainWindow::onToggleMonitor);
    connect(channelBtn_, &QPushButton::clicked, this, &MainWindow::onSetChannel);
    connect(prevThemeBtn, &QPushButton::clicked, this, &MainWindow::onPrevTheme);
    connect(themeBtn, &QPushButton::clicked, this, &MainWindow::onCycleTheme);
    connect(viewBtn, &QPushButton::clicked, this, &MainWindow::onCycleView);
    connect(loadBtn, &QPushButton::clicked, this, &MainWindow::onLoadSession);
    connect(saveBtn, &QPushButton::clicked, this, &MainWindow::onSaveSession);
    connect(authCheck_, &QCheckBox::toggled, this, &MainWindow::onAuthToggled);
    connect(allowBtn, &QPushButton::clicked, this, &MainWindow::onAllowSelected);
    connect(deauthBtn_, &QPushButton::clicked, this, &MainWindow::onDeauthSelected);

    connect(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_O), this), &QShortcut::activated,
            this, &MainWindow::onLoadSession);
    connect(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_S), this), &QShortcut::activated,
            this, &MainWindow::onSaveSession);
    connect(new QShortcut(QKeySequence(Qt::Key_F5), this), &QShortcut::activated,
            this, &MainWindow::onScan);

    timer_ = new QTimer(this);
    connect(timer_, &QTimer::timeout, this, &MainWindow::onTick);
    timer_->start(100);

    if (app_.secState().targets.empty()) {
        app_.requestScan();
    }
    refreshStatus();
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (timer_ != nullptr) {
        timer_->stop();
    }
    if (app_.monitoring() || app_.asyncBusy()) {
        statusBar()->showMessage("Stopping monitor mode and restoring interface…");
        app_.shutdown();
    }
    QMainWindow::closeEvent(event);
}

void MainWindow::onTick() {
    app_.step();
    pollAsyncResult();
    pet_->setFrame(app_.petFrame(ScreenDimensions{240, 135}));
    pet_->setSecMood(app_.secMood());
    refreshNetworks(false);
    refreshStations();
    refreshAlerts();
    refreshChannels();
    refreshStatus();
}

void MainWindow::pollAsyncResult() {
    if (auto r = app_.takeLastAsyncResult()) {
        statusBar()->showMessage(QString::fromStdString(r->message), 6000);
    }
}

void MainWindow::refreshStatus() {
    const AppState& ps = app_.petState();
    const QString statusText = QString("%1  ·  mood %2  ·  battery %3%%")
                                   .arg(themeSpec(ps.theme).name)
                                   .arg(faceForMood(ps.mood).moodLabel)
                                   .arg(ps.batteryPercent);
    if (status_->text() != statusText) {
        status_->setText(statusText);
    }
    const sec::SecMood sm = app_.secMood();
    const int smInt = static_cast<int>(sm);
    if (smInt != lastSecMoodStyled_) {
        lastSecMoodStyled_ = smInt;
        secMoodLabel_->setText(QString("SEC: %1").arg(sec::secMoodLabel(sm)));
        if (sm == sec::SecMood::Alarmed) {
            secMoodLabel_->setStyleSheet(
                "font-weight:bold; padding:2px 6px; border-radius:4px; background:#b00000; color:#ffffff;");
        } else if (sm == sec::SecMood::Watchful) {
            secMoodLabel_->setStyleSheet(
                "font-weight:bold; padding:2px 6px; border-radius:4px; background:#8a5200; color:#ffffff;");
        } else {
            secMoodLabel_->setStyleSheet(
                "font-weight:bold; padding:2px 6px; border-radius:4px; background:#145a32; color:#ffffff;");
        }
    }
    const QString phraseText = QString::fromStdString(ps.phrase);
    if (phrase_->text() != phraseText) {
        phrase_->setText(phraseText);
    }
    const QString engText = QString("Interface %1 · %2")
                                .arg(QString::fromStdString(app_.interfaceName()))
                                .arg(app_.monitoring()
                                         ? QString::fromStdString(app_.engineLabel())
                                         : QString("recon (active scan only)"));
    if (engineLabel_->text() != engText) {
        engineLabel_->setText(engText);
    }
    const bool busy = app_.asyncBusy();
    const auto pending = app_.pendingActionKind();
    QString monitorText = app_.monitoring() ? "Stop &Monitor" : "Start &Monitor";
    if (pending == linux_app::AsyncActionKind::StartMonitor) {
        monitorText = "Starting…";
    } else if (pending == linux_app::AsyncActionKind::StopMonitor) {
        monitorText = "Stopping…";
    }
    if (monitorBtn_->text() != monitorText) {
        monitorBtn_->setText(monitorText);
    }
    monitorBtn_->setEnabled(!busy);
    channelBtn_->setEnabled(!busy && app_.monitoring());

    const auto& auth = app_.authorization();
    const bool deauthReady =
        !busy && app_.monitoring() && auth.operatorConfirmed &&
        (auth.allowAll || !auth.allowedBssids.empty());
    deauthBtn_->setEnabled(deauthReady);
    if (!auth.operatorConfirmed) {
        deauthBtn_->setToolTip("Disabled: confirm authorization first.");
    } else if (!auth.allowAll && auth.allowedBssids.empty()) {
        deauthBtn_->setToolTip("Disabled: allow-list a target BSSID first.");
    } else if (!app_.monitoring()) {
        deauthBtn_->setToolTip("Disabled: start monitor mode first.");
    } else {
        deauthBtn_->setToolTip("Send authorized deauth frames to the selected allow-listed BSSID.");
    }

    const int authStateCode = auth.operatorConfirmed ? 1 : 0;
    if (auth.operatorConfirmed) {
        const QString banner = QString("ARMED — allow-list holds %1 BSSID(s). Transmit permitted "
                                       "only against those.")
                                   .arg(auth.allowedBssids.size());
        if (authBanner_->text() != banner) {
            authBanner_->setText(banner);
        }
    } else {
        const QString banner =
            "Safe (passive): transmit disabled. Confirm authorization AND allow-list a BSSID "
            "you own/are authorized to test to enable deauth.";
        if (authBanner_->text() != banner) {
            authBanner_->setText(banner);
        }
    }
    if (authStateCode != lastAuthStyled_) {
        lastAuthStyled_ = authStateCode;
        if (auth.operatorConfirmed) {
            authBanner_->setStyleSheet(
                "background:#145a32; color:#ffffff; padding:4px 6px; border-radius:4px;");
        } else {
            authBanner_->setStyleSheet(
                "background:#7f1d1d; color:#ffffff; padding:4px 6px; border-radius:4px;");
        }
    }
}

void MainWindow::refreshNetworks(bool force) {
    const auto& sec = app_.secState();
    if (!force && sec.revision == lastNetworksRev_) {
        return;
    }
    lastNetworksRev_ = sec.revision;
    const auto targets = sec::targetsByStrength(sec);
    const auto& auth = app_.authorization();
    tabs_->setTabText(0, QString("Networks (%1)").arg(targets.size()));
    const std::string selBssid = selectedBssid();
    table_->setRowCount(static_cast<int>(targets.size()));
    int selRow = -1;
    for (int i = 0; i < static_cast<int>(targets.size()); ++i) {
        const auto& t = targets[static_cast<std::size_t>(i)];
        setCellText(table_, i, 0, QString::fromStdString(t.bssid));
        setCellText(table_, i, 1,
                    t.ssid.empty() ? QString("<hidden>") : QString::fromStdString(t.ssid));
        setCellText(table_, i, 2, QString::number(t.channel));
        setCellText(table_, i, 3, QString::number(t.rssi));
        setCellText(table_, i, 4, QString(sec::encryptionLabel(t.enc)));
        QTableWidgetItem* wpsItem = setCellText(table_, i, 5, t.wps ? QString("WPS*") : QString("-"));
        styleWarnBadge(wpsItem, t.wps);
        setCellText(table_, i, 6, QString::number(t.clientCount));
        setCellText(table_, i, 7,
                    t.handshake ? QString("HANDSHAKE") : (t.pmkid ? QString("PMKID") : QString("-")));
        const bool isAllowed = auth.isAllowed(t.bssid);
        QTableWidgetItem* alwItem =
            setCellText(table_, i, 8, isAllowed ? QString("YES") : QString("-"));
        styleAllowedBadge(alwItem, isAllowed);
        if (t.bssid == selBssid) {
            selRow = i;
        }
    }
    if (selRow >= 0 && table_->currentRow() != selRow) {
        table_->selectRow(selRow);
    }
}

void MainWindow::refreshStations() {
    const auto& sec = app_.secState();
    if (sec.revision == lastStationsRev_) {
        return;
    }
    lastStationsRev_ = sec.revision;
    const auto stations = sec::stationsByActivity(sec);
    tabs_->setTabText(1, QString("Stations / Probes (%1)").arg(stations.size()));
    stationsTable_->setRowCount(static_cast<int>(stations.size()));
    for (int i = 0; i < static_cast<int>(stations.size()); ++i) {
        const auto& st = stations[static_cast<std::size_t>(i)];
        const bool weak = sec::hasWeakOrDefaultProbe(st);
        QString probedList;
        for (std::size_t k = 0; k < st.probedSsids.size(); ++k) {
            if (k != 0u) {
                probedList += ", ";
            }
            probedList += QString::fromStdString(st.probedSsids[k]);
        }
        if (probedList.isEmpty()) {
            probedList = "<wildcard>";
        }
        setCellText(stationsTable_, i, 0, QString::fromStdString(st.mac));
        setCellText(stationsTable_, i, 1,
                    st.lastBssid.empty() ? QString("-") : QString::fromStdString(st.lastBssid));
        setCellText(stationsTable_, i, 2, QString::number(st.probeCount));
        QTableWidgetItem* riskItem =
            setCellText(stationsTable_, i, 3, weak ? QString("WEAK / DEFAULT") : QString("-"));
        styleWarnBadge(riskItem, weak);
        setCellText(stationsTable_, i, 4, probedList);
    }
}

void MainWindow::refreshAlerts() {
    const auto& sec = app_.secState();
    const auto& alerts = sec.alerts;
    if (sec.totalAlertsEmitted <= lastTotalAlerts_ || alerts.empty()) {
        return;
    }
    const std::uint32_t unseen = sec.totalAlertsEmitted - lastTotalAlerts_;
    const std::size_t count =
        (unseen < alerts.size()) ? static_cast<std::size_t>(unseen) : alerts.size();
    const std::size_t start = alerts.size() - count;
    for (std::size_t i = start; i < alerts.size(); ++i) {
        const auto& al = alerts[i];
        auto* item = new QListWidgetItem(
            QString("[%1] %2  %3  %4")
                .arg(al.nowMs)
                .arg(sec::alertKindLabel(al.kind))
                .arg(QString::fromStdString(al.bssid))
                .arg(QString::fromStdString(sec::sanitizePrintableText(al.message, 160u))));
        if (al.severity == sec::Severity::Critical) {
            item->setBackground(QColor(254, 226, 226));
            item->setForeground(QColor(153, 27, 27));
        } else if (al.severity == sec::Severity::Warn) {
            item->setBackground(QColor(255, 243, 205));
            item->setForeground(QColor(122, 62, 0));
        }
        alerts_->addItem(item);
    }
    while (alerts_->count() > static_cast<int>(sec::kMaxAlerts)) {
        delete alerts_->takeItem(0);
    }
    alerts_->scrollToBottom();
    lastTotalAlerts_ = sec.totalAlertsEmitted;
}

void MainWindow::refreshChannels() {
    const auto& sec = app_.secState();
    if (sec.revision == lastChannelsRev_) {
        return;
    }
    lastChannelsRev_ = sec.revision;
    const auto dist = sec::channelDistribution(sec);
    QString band24;
    QString band5;
    for (const auto& c : dist) {
        const QString part = QString("ch%1×%2 ").arg(c.channel).arg(c.count);
        if (c.band == sec::Band::Band24GHz) {
            band24 += part;
        } else if (c.band == sec::Band::Band5GHz) {
            band5 += part;
        }
    }
    channelsLabel_->setText(QString("2.4GHz: %1\n5GHz: %2")
                                .arg(band24.isEmpty() ? QString("-") : band24)
                                .arg(band5.isEmpty() ? QString("-") : band5));
}

std::string MainWindow::selectedBssid() const {
    const int row = table_->currentRow();
    if (row < 0 || table_->item(row, 0) == nullptr) {
        return {};
    }
    return table_->item(row, 0)->text().toStdString();
}

void MainWindow::onScan() { app_.requestScan(); }

void MainWindow::onToggleMonitor() {
    const auto r = app_.monitoring() ? app_.stopMonitor() : app_.startMonitor();
    statusBar()->showMessage(QString::fromStdString(r.message), 5000);
    if (!r.ok) {
        QMessageBox::warning(this, "Monitor mode", QString::fromStdString(r.message));
    }
}

void MainWindow::onSetChannel() {
    const auto r = app_.setChannel(channelSpin_->value());
    statusBar()->showMessage(QString::fromStdString(r.message), 5000);
    if (!r.ok) {
        QMessageBox::warning(this, "Set channel", QString::fromStdString(r.message));
    }
}

void MainWindow::onPrevTheme() { app_.dispatchPet(CycleThemeEvent{linux_app::nowMs(), -1}); }
void MainWindow::onCycleTheme() { app_.dispatchPet(CycleThemeEvent{linux_app::nowMs(), +1}); }
void MainWindow::onCycleView() { app_.dispatchPet(CyclePageEvent{linux_app::nowMs(), +1}); }

void MainWindow::onLoadSession() {
    const QString path = QFileDialog::getOpenFileName(
        this, "Load Recorded Session", QString(), "ZeroDay Session (*.zds *.log *.txt);;All Files (*)");
    if (path.isEmpty()) {
        return;
    }
    const auto r = app_.loadSession(path.toStdString());
    statusBar()->showMessage(QString::fromStdString(r.message), 6000);
    if (!r.ok) {
        QMessageBox::warning(this, "Load Session", QString::fromStdString(r.message));
        return;
    }
    alerts_->clear();
    lastTotalAlerts_ = 0;
    lastNetworksRev_ = UINT64_MAX;
    lastStationsRev_ = UINT64_MAX;
    lastChannelsRev_ = UINT64_MAX;
    onTick();
}

void MainWindow::onSaveSession() {
    const QString path = QFileDialog::getSaveFileName(
        this, "Save Session", "session.zds", "ZeroDay Session (*.zds *.log *.txt);;All Files (*)");
    if (path.isEmpty()) {
        return;
    }
    const auto r = app_.saveSession(path.toStdString());
    statusBar()->showMessage(QString::fromStdString(r.message), 6000);
    if (!r.ok) {
        QMessageBox::warning(this, "Save Session", QString::fromStdString(r.message));
    }
}

void MainWindow::onAuthToggled(bool on) {
    app_.confirmAuthorization(on);
    refreshStatus();
}

void MainWindow::onAllowSelected() {
    const std::string bssid = selectedBssid();
    if (bssid.empty()) {
        QMessageBox::information(this, "Allow-list", "Select a network row first.");
        return;
    }
    const bool added = app_.toggleAllowBssid(bssid);
    statusBar()->showMessage(
        QString(added ? "Allow-listed %1" : "Removed %1 from allow-list")
            .arg(QString::fromStdString(bssid)),
        4000);
    refreshNetworks(true);
    refreshStatus();
}

void MainWindow::onDeauthSelected() {
    const std::string bssid = selectedBssid();
    if (bssid.empty()) {
        QMessageBox::information(this, "Deauth", "Select a network row first.");
        return;
    }
    // Pre-flight the gate so the operator sees exactly why if it would be refused.
    const sec::AuthDecision decision = sec::authorize(app_.authorization(), bssid);
    if (decision != sec::AuthDecision::Allowed) {
        QMessageBox::critical(
            this, "Transmit blocked",
            QString("Deauth against %1 is blocked:\n\n%2\n\nConfirm authorization and allow-list "
                    "this BSSID first.")
                .arg(QString::fromStdString(bssid))
                .arg(sec::authDecisionLabel(decision)));
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle("Deauthentication — authorized target");
    auto* form = new QFormLayout(&dlg);
    auto* warn = new QLabel(
        "This transmits deauthentication frames. Use only on networks you own or are explicitly "
        "authorized to test. This action is logged.",
        &dlg);
    warn->setWordWrap(true);
    warn->setStyleSheet("background:#7f1d1d; color:#ffffff; padding:6px; border-radius:4px;");
    form->addRow(warn);
    auto* bssidEdit = new QLineEdit(QString::fromStdString(bssid), &dlg);
    bssidEdit->setReadOnly(true);
    auto* clientEdit = new QLineEdit(&dlg);
    clientEdit->setPlaceholderText("optional client MAC (blank = broadcast)");
    auto* countSpin = new QSpinBox(&dlg);
    countSpin->setRange(1, 1000);
    countSpin->setValue(16);
    form->addRow("Target BSSID", bssidEdit);
    form->addRow("Client", clientEdit);
    form->addRow("Frame count", countSpin);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    buttons->button(QDialogButtonBox::Ok)->setText("Transmit");
    form->addRow(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted) {
        return;
    }
    const std::string client = clientEdit->text().toStdString();
    if (!client.empty() && !sec::isValidMac(client)) {
        QMessageBox::warning(this, "Deauth",
                             QString("'%1' doesn't look like a MAC address.")
                                 .arg(QString::fromStdString(client)));
        return;
    }
    if (!app_.monitoring()) {
        QMessageBox::information(
            this, "Deauth",
            "Start monitor mode first (it has to come up before a target can be hit).");
        return;
    }
    const auto r = app_.requestDeauth(bssid, client, static_cast<uint32_t>(countSpin->value()));
    statusBar()->showMessage(QString::fromStdString(r.message), 6000);
    if (!r.ok) {
        QMessageBox::warning(this, "Deauth", QString::fromStdString(r.message));
        return;
    }
}

}  // namespace linux_gui
}  // namespace zd
