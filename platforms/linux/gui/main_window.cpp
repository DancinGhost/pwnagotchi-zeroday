#include "main_window.hpp"

#include <QAbstractItemView>
#include <QColor>
#include <QComboBox>
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
#include <QSignalBlocker>
#include <QSpinBox>
#include <QSplitter>
#include <QStatusBar>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <unordered_set>

#include "zd/report.hpp"
#include "zd/theme.hpp"
#include "zd/ui_model.hpp"
#include "zd/wifi_analysis.hpp"

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

bool containsLower(const std::string& haystack, const std::string& lowerNeedle) {
    if (lowerNeedle.empty()) {
        return true;
    }
    return zd::toLowerAscii(haystack).find(lowerNeedle) != std::string::npos;
}

}  // namespace

MainWindow::MainWindow(linux_app::AppController& app, QWidget* parent)
    : QMainWindow(parent), app_(app) {
    setWindowTitle("pwnagotchi-zeroday — Linux");
    resize(1120, 690);

    auto* central = new QWidget(this);
    auto* root = new QVBoxLayout(central);

    // --- Top strip: pet screen + status + controls ---
    auto* top = new QHBoxLayout();
    pet_ = new PetWidget(central);
    pet_->setEventCallback([this](const AppEvent& ev) {
        app_.dispatchPet(ev);
        pet_->setFrame(app_.petFrame(kPetDims));
        refreshStatus();
    });
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
    prevThemeBtn->setToolTip("Previous Theme ([)");
    auto* themeBtn = new QPushButton("Theme ▶", central);
    themeBtn->setAccessibleName("Next Theme");
    themeBtn->setToolTip("Next Theme (])");
    auto* viewBtn = new QPushButton("&View", central);
    modeBtn_ = new QPushButton("&Mode: RECON", central);
    modeBtn_->setToolTip("Cycle OpsMode (RECON / DEFENSE / OFFENSE) (M)");
    btnRow->addWidget(scanBtn);
    btnRow->addWidget(monitorBtn_);
    btnRow->addWidget(prevThemeBtn);
    btnRow->addWidget(themeBtn);
    btnRow->addWidget(viewBtn);
    btnRow->addWidget(modeBtn_);
    statusBox->addLayout(btnRow);

    auto* toolsRow = new QHBoxLayout();
    auto* loadBtn = new QPushButton("&Load…", central);
    auto* saveBtn = new QPushButton("Sa&ve…", central);
    recordBtn_ = new QPushButton("&Record…", central);
    auto* pcapBtn = new QPushButton("&PCAP…", central);
    auto* exportBtn = new QPushButton("&Export…", central);
    bleBtn_ = new QPushButton("&BLE Scan", central);
    bleBtn_->setEnabled(app_.bleAvailable());
    clearThreatBtn_ = new QPushButton("Clear &Threat", central);
    toolsRow->addWidget(loadBtn);
    toolsRow->addWidget(saveBtn);
    toolsRow->addWidget(recordBtn_);
    toolsRow->addWidget(pcapBtn);
    toolsRow->addWidget(exportBtn);
    toolsRow->addWidget(bleBtn_);
    toolsRow->addWidget(clearThreatBtn_);
    statusBox->addLayout(toolsRow);

    // Channel control strip, hopper & table freeze toggle.
    auto* chRow = new QHBoxLayout();
    auto* chLabel = new QLabel("Monitor &channel:", central);
    channelSpin_ = new QSpinBox(central);
    channelSpin_->setRange(1, 177);
    channelSpin_->setValue(6);
    channelSpin_->setAccessibleName("Monitor Channel");
    chLabel->setBuddy(channelSpin_);
    channelBtn_ = new QPushButton("Set C&hannel", central);
    channelBtn_->setEnabled(false);
    hopCheck_ = new QCheckBox("&Hop ch", central);
    hopCheck_->setToolTip("Automatically hop 2.4 GHz channels with 3s EAPOL handshake hold");
    hopCheck_->setChecked(app_.channelHopEnabled());
    freezeSortCheck_ = new QCheckBox("&Freeze sort", central);
    freezeSortCheck_->setToolTip("Preserve table row order during live scans");
    chRow->addWidget(chLabel);
    chRow->addWidget(channelSpin_);
    chRow->addWidget(channelBtn_);
    chRow->addWidget(hopCheck_);
    chRow->addStretch(1);
    chRow->addWidget(freezeSortCheck_);
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
    auto* trustBtn = new QPushButton("Tr&ust BSSID", central);
    deauthBtn_ = new QPushButton("&Deauth selected…", central);
    deauthBtn_->setStyleSheet("font-weight:bold;");
    deauthBtn_->setEnabled(false);
    authLayout->addWidget(authBanner_);
    authLayout->addWidget(authCheck_);
    auto* authBtnRow = new QHBoxLayout();
    authBtnRow->addWidget(allowBtn);
    authBtnRow->addWidget(trustBtn);
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

    // --- Bottom: filter bar + tabbed tables (Networks / Stations / RF Guard) & alerts ---
    auto* split = new QSplitter(Qt::Horizontal, central);

    auto* leftPane = new QWidget(split);
    auto* leftLayout = new QVBoxLayout(leftPane);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    filterEdit_ = new QLineEdit(leftPane);
    filterEdit_->setPlaceholderText("Filter SSID, BSSID, probed SSID, BLE or Sub-GHz…");
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setAccessibleName("Table search filter");
    leftLayout->addWidget(filterEdit_);

    tabs_ = new QTabWidget(leftPane);
    table_ = new QTableWidget(0, 10, tabs_);
    table_->setAccessibleName("Discovered WiFi networks");
    table_->setHorizontalHeaderLabels(
        {"BSSID", "SSID", "CH", "dBm", "ENC", "WPS", "Clients", "Capture", "Trusted", "Allowed"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tabs_->addTab(table_, "Networks (0)");

    stationsTable_ = new QTableWidget(0, 5, tabs_);
    stationsTable_->setAccessibleName("Observed WiFi stations and probe requests");
    stationsTable_->setHorizontalHeaderLabels(
        {"Station MAC", "Associated BSSID", "Probes", "Risk", "Probed SSIDs"});
    stationsTable_->horizontalHeader()->setStretchLastSection(true);
    stationsTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    stationsTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    stationsTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tabs_->addTab(stationsTable_, "Stations / Probes (0)");

    rfGuardTable_ = new QTableWidget(0, 6, tabs_);
    rfGuardTable_->setAccessibleName("BLE and Sub-GHz RF Guard detections");
    rfGuardTable_->setHorizontalHeaderLabels(
        {"Band", "Addr / Freq", "Name / Protocol", "RSSI", "Status", "Seen / Burst"});
    rfGuardTable_->horizontalHeader()->setStretchLastSection(true);
    rfGuardTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    rfGuardTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    rfGuardTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tabs_->addTab(rfGuardTable_, "RF Guard (0)");

    leftLayout->addWidget(tabs_);
    split->addWidget(leftPane);

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
    connect(hopCheck_, &QCheckBox::toggled, this, [this](bool on) {
        app_.setChannelHopEnabled(on);
    });
    connect(prevThemeBtn, &QPushButton::clicked, this, &MainWindow::onPrevTheme);
    connect(themeBtn, &QPushButton::clicked, this, &MainWindow::onCycleTheme);
    connect(viewBtn, &QPushButton::clicked, this, &MainWindow::onCycleView);
    connect(modeBtn_, &QPushButton::clicked, this, &MainWindow::onCycleMode);
    connect(loadBtn, &QPushButton::clicked, this, &MainWindow::onLoadSession);
    connect(saveBtn, &QPushButton::clicked, this, &MainWindow::onSaveSession);
    connect(recordBtn_, &QPushButton::clicked, this, &MainWindow::onToggleRecord);
    connect(pcapBtn, &QPushButton::clicked, this, &MainWindow::onSelectPcap);
    connect(exportBtn, &QPushButton::clicked, this, &MainWindow::onExportReport);
    connect(bleBtn_, &QPushButton::clicked, this, &MainWindow::onBleScan);
    connect(clearThreatBtn_, &QPushButton::clicked, this, &MainWindow::onClearThreat);
    connect(filterEdit_, &QLineEdit::textChanged, this, &MainWindow::onFilterChanged);
    connect(authCheck_, &QCheckBox::toggled, this, &MainWindow::onAuthToggled);
    connect(allowBtn, &QPushButton::clicked, this, &MainWindow::onAllowSelected);
    connect(trustBtn, &QPushButton::clicked, this, &MainWindow::onTrustSelected);
    connect(deauthBtn_, &QPushButton::clicked, this, &MainWindow::onDeauthSelected);

    connect(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_O), this), &QShortcut::activated,
            this, &MainWindow::onLoadSession);
    connect(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_S), this), &QShortcut::activated,
            this, &MainWindow::onSaveSession);
    connect(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_E), this), &QShortcut::activated,
            this, &MainWindow::onExportReport);
    connect(new QShortcut(QKeySequence(Qt::CTRL | Qt::Key_F), this), &QShortcut::activated,
            filterEdit_, QOverload<>::of(&QLineEdit::setFocus));
    connect(new QShortcut(QKeySequence(Qt::Key_F5), this), &QShortcut::activated,
            this, &MainWindow::onScan);
    connect(new QShortcut(QKeySequence(Qt::Key_BracketLeft), this), &QShortcut::activated,
            this, &MainWindow::onPrevTheme);
    connect(new QShortcut(QKeySequence(Qt::Key_BracketRight), this), &QShortcut::activated,
            this, &MainWindow::onCycleTheme);
    connect(new QShortcut(QKeySequence(Qt::Key_T), this), &QShortcut::activated,
            this, &MainWindow::onCycleTheme);
    connect(new QShortcut(QKeySequence(Qt::SHIFT | Qt::Key_T), this), &QShortcut::activated,
            this, &MainWindow::onPrevTheme);
    connect(new QShortcut(QKeySequence(Qt::Key_V), this), &QShortcut::activated,
            this, &MainWindow::onCycleView);
    connect(new QShortcut(QKeySequence(Qt::Key_M), this), &QShortcut::activated,
            this, &MainWindow::onCycleMode);
    connect(new QShortcut(QKeySequence(Qt::Key_1), this), &QShortcut::activated, this, [this]() {
        app_.dispatchPet(SetPageEvent{linux_app::nowMs(), ScreenPage::PetFace});
        pet_->setFrame(app_.petFrame(kPetDims));
    });
    connect(new QShortcut(QKeySequence(Qt::Key_2), this), &QShortcut::activated, this, [this]() {
        app_.dispatchPet(SetPageEvent{linux_app::nowMs(), ScreenPage::NearbyRadar});
        pet_->setFrame(app_.petFrame(kPetDims));
    });
    connect(new QShortcut(QKeySequence(Qt::Key_3), this), &QShortcut::activated, this, [this]() {
        app_.dispatchPet(SetPageEvent{linux_app::nowMs(), ScreenPage::ChannelSpectrum});
        pet_->setFrame(app_.petFrame(kPetDims));
    });
    connect(new QShortcut(QKeySequence(Qt::Key_4), this), &QShortcut::activated, this, [this]() {
        app_.dispatchPet(SetPageEvent{linux_app::nowMs(), ScreenPage::RfGuard});
        pet_->setFrame(app_.petFrame(kPetDims));
    });

    timer_ = new QTimer(this);
    connect(timer_, &QTimer::timeout, this, &MainWindow::onTick);
    timer_->start(100);

    if (app_.secState().targets.empty()) {
        app_.requestScan();
    } else {
        refreshNetworks(true);
        refreshStations(true);
        refreshRfGuard(true);
        refreshChannels(true);
        refreshAlerts();
    }
    pet_->setFrame(app_.petFrame(kPetDims));
    pet_->setSecMood(app_.secMood());
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
    pet_->setFrame(app_.petFrame(kPetDims));
    pet_->setSecMood(app_.secMood());
    const std::uint32_t now = linux_app::nowMs();
    if ((now - lastTableRefreshMs_) >= 500u) {
        lastTableRefreshMs_ = now;
        refreshNetworks(false);
        refreshStations(false);
        refreshRfGuard(false);
        refreshChannels(false);
    }
    refreshAlerts();
    refreshStatus();
}

void MainWindow::pollAsyncResult() {
    if (auto r = app_.takeLastAsyncResult()) {
        statusBar()->showMessage(QString::fromStdString(r->message), 6000);
    }
}

void MainWindow::refreshStatus() {
    const AppState& ps = app_.petState();
    const QString statusText = QString("%1  ·  [%2]  ·  Lv.%3 (HI:%4)  ·  mood %5  ·  battery %6%")
                                   .arg(themeSpec(ps.theme).name)
                                   .arg(opsModeLabel(ps.opsMode))
                                   .arg(ps.level)
                                   .arg(ps.highScore)
                                   .arg(faceForMood(ps.mood).moodLabel)
                                   .arg(ps.batteryPercent);
    if (status_->text() != statusText) {
        status_->setText(statusText);
    }
    const QString modeText = QString("&Mode: %1").arg(opsModeLabel(ps.opsMode));
    if (modeBtn_ != nullptr && modeBtn_->text() != modeText) {
        modeBtn_->setText(modeText);
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
    const QString recText = app_.recording() ? "Stop &Rec" : "&Record…";
    if (recordBtn_->text() != recText) {
        recordBtn_->setText(recText);
    }
    if (clearThreatBtn_ != nullptr) {
        clearThreatBtn_->setEnabled(!ps.lastThreatLabel.empty());
    }

    const auto& auth = app_.authorization();
    if (authCheck_->isChecked() != auth.operatorConfirmed) {
        QSignalBlocker blocker(authCheck_);
        authCheck_->setChecked(auth.operatorConfirmed);
    }
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
                "background:#991b1b; color:#ffffff; font-weight:bold; padding:4px 6px; border-radius:4px;");
        } else {
            authBanner_->setStyleSheet(
                "background:#145a32; color:#ffffff; padding:4px 6px; border-radius:4px;");
        }
    }
}

void MainWindow::refreshNetworks(bool force) {
    const auto& sec = app_.secState();
    if (!force && sec.revision == lastNetworksRev_) {
        return;
    }
    lastNetworksRev_ = sec.revision;
    if (freezeSortCheck_ != nullptr && freezeSortCheck_->isChecked() && !displayedTargets_.empty()) {
        std::vector<sec::WifiTarget> updated;
        updated.reserve(sec.targets.size());
        std::unordered_set<std::string> seenBssids;
        seenBssids.reserve(displayedTargets_.size() + 8u);
        for (const auto& prev : displayedTargets_) {
            if (const sec::WifiTarget* cur = sec::findTarget(sec, prev.bssid)) {
                updated.push_back(*cur);
                seenBssids.insert(prev.bssid);
            }
        }
        for (const auto& cur : sec.targets) {
            if (seenBssids.find(cur.bssid) == seenBssids.end()) {
                updated.push_back(cur);
            }
        }
        displayedTargets_ = std::move(updated);
    } else {
        displayedTargets_ = sec::targetsByStrength(sec);
    }
    const std::string needle =
        (filterEdit_ != nullptr) ? zd::toLowerAscii(filterEdit_->text().trimmed().toStdString())
                                 : std::string{};
    std::vector<const sec::WifiTarget*> visible;
    visible.reserve(displayedTargets_.size());
    for (const auto& t : displayedTargets_) {
        if (containsLower(t.bssid, needle) || containsLower(t.ssid, needle) ||
            containsLower(sec::encryptionLabel(t.enc), needle)) {
            visible.push_back(&t);
        }
    }
    const auto& auth = app_.authorization();
    tabs_->setTabText(0, QString("Networks (%1)").arg(visible.size()));
    const std::string selBssid = selectedBssid();
    table_->setRowCount(static_cast<int>(visible.size()));
    int selRow = -1;
    for (int i = 0; i < static_cast<int>(visible.size()); ++i) {
        const auto& t = *visible[static_cast<std::size_t>(i)];
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
        const bool isTrusted = sec::isTrustedBssid(sec, t.bssid);
        QTableWidgetItem* truItem =
            setCellText(table_, i, 8, isTrusted ? QString("TRUSTED") : QString("-"));
        styleAllowedBadge(truItem, isTrusted);
        const bool isAllowed = auth.isAllowed(t.bssid);
        QTableWidgetItem* alwItem =
            setCellText(table_, i, 9, isAllowed ? QString("YES") : QString("-"));
        styleAllowedBadge(alwItem, isAllowed);
        if (t.bssid == selBssid) {
            selRow = i;
        }
    }
    if (selRow >= 0 && table_->currentRow() != selRow) {
        table_->selectRow(selRow);
    }
}

void MainWindow::refreshStations(bool force) {
    const auto& sec = app_.secState();
    if (!force && sec.revision == lastStationsRev_) {
        return;
    }
    lastStationsRev_ = sec.revision;
    const std::string needle =
        (filterEdit_ != nullptr) ? zd::toLowerAscii(filterEdit_->text().trimmed().toStdString())
                                 : std::string{};
    const auto allStations = sec::stationsByActivity(sec);
    std::vector<const sec::Station*> visible;
    visible.reserve(allStations.size());
    for (const auto& st : allStations) {
        bool match = containsLower(st.mac, needle) || containsLower(st.lastBssid, needle);
        if (!match) {
            for (const auto& s : st.probedSsids) {
                if (containsLower(s, needle)) {
                    match = true;
                    break;
                }
            }
        }
        if (match) {
            visible.push_back(&st);
        }
    }
    tabs_->setTabText(1, QString("Stations / Probes (%1)").arg(visible.size()));
    stationsTable_->setRowCount(static_cast<int>(visible.size()));
    for (int i = 0; i < static_cast<int>(visible.size()); ++i) {
        const auto& st = *visible[static_cast<std::size_t>(i)];
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

void MainWindow::refreshRfGuard(bool force) {
    if (rfGuardTable_ == nullptr) {
        return;
    }
    const auto& sec = app_.secState();
    if (!force && sec.revision == lastRfGuardRev_) {
        return;
    }
    lastRfGuardRev_ = sec.revision;
    const std::string needle =
        (filterEdit_ != nullptr) ? zd::toLowerAscii(filterEdit_->text().trimmed().toStdString())
                                 : std::string{};

    struct RfRow {
        QString band;
        QString addr;
        QString name;
        int32_t rssi;
        QString status;
        uint32_t count;
        bool alert;
    };
    std::vector<RfRow> rows;
    rows.reserve(sec.bleTargets.size() + sec.subGhzCaptures.size());
    for (const auto& b : sec.bleTargets) {
        const std::string dispName = b.name.empty() ? "-" : b.name;
        const std::string status = zd::bleThreatLabel(b.threat);
        if (!containsLower(b.mac, needle) && !containsLower(dispName, needle) &&
            !containsLower(status, needle) && !containsLower("ble", needle)) {
            continue;
        }
        rows.push_back({"BLE", QString::fromStdString(b.mac), QString::fromStdString(dispName),
                        b.rssi, QString::fromStdString(status), b.seenCount,
                        b.threat != zd::BleThreatKind::None});
    }
    for (const auto& sc : sec.subGhzCaptures) {
        const std::string freq = zd::formatFreqMhz(sc.freqKhz);
        const std::string status =
            sc.continuousCarrier ? "JAMMING!" : (sc.burstCount >= 5u ? "REPLAY!" : "OK");
        if (!containsLower(freq, needle) && !containsLower(sc.protocol, needle) &&
            !containsLower(status, needle) && !containsLower("subghz", needle)) {
            continue;
        }
        rows.push_back({"Sub-GHz", QString::fromStdString(freq),
                        QString::fromStdString(sc.protocol.empty() ? "-" : sc.protocol), sc.rssi,
                        QString::fromStdString(status), sc.burstCount,
                        sc.continuousCarrier || sc.burstCount >= 5u});
    }

    tabs_->setTabText(2, QString("RF Guard (%1)").arg(rows.size()));
    rfGuardTable_->setRowCount(static_cast<int>(rows.size()));
    for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
        const auto& r = rows[static_cast<std::size_t>(i)];
        setCellText(rfGuardTable_, i, 0, r.band);
        setCellText(rfGuardTable_, i, 1, r.addr);
        setCellText(rfGuardTable_, i, 2, r.name);
        setCellText(rfGuardTable_, i, 3, QString::number(r.rssi));
        QTableWidgetItem* stItem = setCellText(rfGuardTable_, i, 4, r.status);
        styleWarnBadge(stItem, r.alert);
        setCellText(rfGuardTable_, i, 5, QString::number(r.count));
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

void MainWindow::refreshChannels(bool force) {
    const auto& sec = app_.secState();
    if (!force && sec.revision == lastChannelsRev_) {
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

void MainWindow::resolveSelectedTarget(std::string& bssidOut, std::string& stationOut) const {
    bssidOut.clear();
    stationOut.clear();
    if (tabs_ != nullptr && tabs_->currentIndex() == 1) {
        const int row = stationsTable_->currentRow();
        if (row >= 0 && stationsTable_->item(row, 0) != nullptr) {
            stationOut = stationsTable_->item(row, 0)->text().toStdString();
            if (stationsTable_->item(row, 1) != nullptr) {
                const std::string assoc = stationsTable_->item(row, 1)->text().toStdString();
                if (assoc != "-" && sec::isValidMac(assoc)) {
                    bssidOut = assoc;
                }
            }
        }
        return;
    }
    bssidOut = selectedBssid();
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

void MainWindow::onPrevTheme() {
    app_.dispatchPet(CycleThemeEvent{linux_app::nowMs(), -1});
    pet_->setFrame(app_.petFrame(kPetDims));
    refreshStatus();
}
void MainWindow::onCycleTheme() {
    app_.dispatchPet(CycleThemeEvent{linux_app::nowMs(), +1});
    pet_->setFrame(app_.petFrame(kPetDims));
    refreshStatus();
}
void MainWindow::onCycleView() {
    app_.dispatchPet(CyclePageEvent{linux_app::nowMs(), +1});
    pet_->setFrame(app_.petFrame(kPetDims));
}
void MainWindow::onCycleMode() {
    app_.cycleOpsMode();
    pet_->setFrame(app_.petFrame(kPetDims));
    refreshStatus();
}

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
    lastRfGuardRev_ = UINT64_MAX;
    lastChannelsRev_ = UINT64_MAX;
    displayedTargets_.clear();
    refreshNetworks(true);
    refreshStations(true);
    refreshRfGuard(true);
    refreshChannels(true);
    onTick();
}

void MainWindow::onToggleRecord() {
    if (app_.recording()) {
        const auto r = app_.startRecording("");
        statusBar()->showMessage(QString::fromStdString(r.message), 5000);
        refreshStatus();
        return;
    }
    const QString path = QFileDialog::getSaveFileName(
        this, "Record Live Session", "live_session.zds", "ZeroDay Session (*.zds *.log *.txt);;All Files (*)");
    if (path.isEmpty()) {
        return;
    }
    const auto r = app_.startRecording(path.toStdString());
    statusBar()->showMessage(QString::fromStdString(r.message), 6000);
    if (!r.ok) {
        QMessageBox::warning(this, "Record Session", QString::fromStdString(r.message));
    }
    refreshStatus();
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

void MainWindow::onSelectPcap() {
    const QString path = QFileDialog::getSaveFileName(
        this, "Set Live PCAP Capture File", "capture.pcap", "PCAP Capture (*.pcap *.cap);;All Files (*)");
    if (path.isEmpty()) {
        return;
    }
    app_.setPcapDumpPath(path.toStdString());
    statusBar()->showMessage(QString("PCAP capture path set: %1").arg(path), 6000);
}

void MainWindow::onExportReport() {
    const QString path = QFileDialog::getSaveFileName(
        this, "Export Assessment Report", "zeroday_report.md",
        "Markdown Report (*.md);;CSV Report (*.csv);;HTML Report (*.html)");
    if (path.isEmpty()) {
        return;
    }
    const auto r = app_.exportReport(path.toStdString());
    statusBar()->showMessage(QString::fromStdString(r.message), 6000);
    if (!r.ok) {
        QMessageBox::warning(this, "Export Report", QString::fromStdString(r.message));
    }
}

void MainWindow::onBleScan() {
    const auto r = app_.requestBleScan();
    statusBar()->showMessage(QString::fromStdString(r.message), 5000);
}

void MainWindow::onClearThreat() {
    app_.clearThreat();
    pet_->setFrame(app_.petFrame(kPetDims));
    refreshStatus();
}

void MainWindow::onTrustSelected() {
    std::string bssid;
    std::string station;
    resolveSelectedTarget(bssid, station);
    if (bssid.empty()) {
        QMessageBox::information(this, "Trusted BSSID", "Select a network row (or associated station) first.");
        return;
    }
    const bool trusted = app_.toggleTrustBssid(bssid);
    statusBar()->showMessage(
        QString(trusted ? "Trusted BSSID %1" : "Untrusted BSSID %1").arg(QString::fromStdString(bssid)),
        4000);
    refreshNetworks(true);
}

void MainWindow::onFilterChanged() {
    lastNetworksRev_ = UINT64_MAX;
    lastStationsRev_ = UINT64_MAX;
    lastRfGuardRev_ = UINT64_MAX;
    refreshNetworks(true);
    refreshStations(true);
    refreshRfGuard(true);
}

void MainWindow::onAuthToggled(bool on) {
    app_.confirmAuthorization(on);
    refreshStatus();
}

void MainWindow::onAllowSelected() {
    std::string bssid;
    std::string station;
    resolveSelectedTarget(bssid, station);
    if (bssid.empty()) {
        const QString msg = (tabs_ != nullptr && tabs_->currentIndex() == 1)
                                ? QString("Select an associated station (or switch to the Networks tab).")
                                : QString("Select a network row first.");
        QMessageBox::information(this, "Allow-list", msg);
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
    std::string bssid;
    std::string prefillClient;
    resolveSelectedTarget(bssid, prefillClient);
    if (bssid.empty()) {
        const QString msg = (tabs_ != nullptr && tabs_->currentIndex() == 1)
                                ? QString("Select an associated station (or switch to the Networks tab).")
                                : QString("Select a network row first.");
        QMessageBox::information(this, "Deauth", msg);
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
    warn->setStyleSheet("background:#991b1b; color:#ffffff; padding:6px; border-radius:4px;");
    form->addRow(warn);
    auto* bssidEdit = new QLineEdit(QString::fromStdString(bssid), &dlg);
    bssidEdit->setReadOnly(true);

    const sec::WifiTarget* targetAp = sec::findTarget(app_.secState(), bssid);
    if (targetAp != nullptr && targetAp->channel > 0 && app_.monitoring()) {
        auto* tuneRow = new QHBoxLayout();
        auto* chInfo = new QLabel(QString("AP channel: %1").arg(targetAp->channel), &dlg);
        auto* tuneBtn = new QPushButton(QString("Tune to ch %1").arg(targetAp->channel), &dlg);
        const int targetCh = targetAp->channel;
        connect(tuneBtn, &QPushButton::clicked, this, [this, targetCh, tuneBtn]() {
            channelSpin_->setValue(targetCh);
            const auto r = app_.setChannel(targetCh);
            statusBar()->showMessage(QString::fromStdString(r.message), 4000);
            tuneBtn->setEnabled(false);
        });
        tuneRow->addWidget(chInfo);
        tuneRow->addWidget(tuneBtn);
        form->addRow("Channel", tuneRow);
    }

    auto* clientCombo = new QComboBox(&dlg);
    clientCombo->setEditable(true);
    clientCombo->addItem("");
    for (const sec::Station& st : app_.secState().stations) {
        if (st.lastBssid == bssid) {
            clientCombo->addItem(QString::fromStdString(st.mac));
        }
    }
    if (!prefillClient.empty()) {
        clientCombo->setCurrentText(QString::fromStdString(prefillClient));
    } else if (clientCombo->lineEdit() != nullptr) {
        clientCombo->lineEdit()->setPlaceholderText("optional client MAC (blank = broadcast)");
    }

    auto* countSpin = new QSpinBox(&dlg);
    countSpin->setRange(1, 1000);
    countSpin->setValue(16);
    form->addRow("Target BSSID", bssidEdit);
    form->addRow("Client", clientCombo);
    form->addRow("Frame count", countSpin);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    buttons->button(QDialogButtonBox::Ok)->setText("Transmit");
    form->addRow(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted) {
        return;
    }
    const std::string client = clientCombo->currentText().trimmed().toStdString();
    if (!sec::isValidClientTarget(client)) {
        QMessageBox::warning(this, "Deauth",
                             QString("'%1' is not a valid unicast/broadcast MAC address.")
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
