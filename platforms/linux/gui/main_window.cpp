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
    auto* viewBtn = new QPushButton("V&iew", central);
    modeBtn_ = new QPushButton("M&ode: RECON", central);
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
    auto* exportBtn = new QPushButton("E&xport…", central);
    hc22000Btn_ = new QPushButton("&HC22000…", central);
    hc22000Btn_->setToolTip("Export validated crackable handshakes/PMKIDs for hashcat -m 22000");
    wardriveBtn_ = new QPushButton("&Wardrive…", central);
    bleBtn_ = new QPushButton("&BT Scan", central);
    bleBtn_->setEnabled(app_.bleAvailable());
    subGhzBtn_ = new QPushButton("&Sub-GHz", central);
    subGhzBtn_->setToolTip("Start / stop rtl_433 Sub-GHz ISM-band listener");
    subGhzBtn_->setEnabled(app_.subGhzAvailable());
    bleAutoCheck_ = new QCheckBox("BT Au&to", central);
    bleAutoCheck_->setToolTip("Periodically scan nearby Bluetooth / BLE devices every 15s");
    bleAutoCheck_->setEnabled(app_.bleAvailable());
    bleAutoCheck_->setChecked(app_.bleAutoEnabled());
    notifyCheck_ = new QCheckBox("&Notify", central);
    notifyCheck_->setToolTip("Send desktop notifications on critical security alerts");
    notifyCheck_->setChecked(app_.notificationsEnabled());
    clearThreatBtn_ = new QPushButton("&Clear Threat", central);
    toolsRow->addWidget(loadBtn);
    toolsRow->addWidget(saveBtn);
    toolsRow->addWidget(recordBtn_);
    toolsRow->addWidget(pcapBtn);
    toolsRow->addWidget(exportBtn);
    toolsRow->addWidget(hc22000Btn_);
    toolsRow->addWidget(wardriveBtn_);
    toolsRow->addWidget(bleBtn_);
    toolsRow->addWidget(subGhzBtn_);
    toolsRow->addWidget(bleAutoCheck_);
    toolsRow->addWidget(notifyCheck_);
    toolsRow->addWidget(clearThreatBtn_);
    statusBox->addLayout(toolsRow);

    // Channel control strip, hopper, hotkey lock & table freeze toggle.
    auto* chRow = new QHBoxLayout();
    auto* chLabel = new QLabel("Cha&nnel:", central);
    channelSpin_ = new QSpinBox(central);
    channelSpin_->setRange(1, 177);
    channelSpin_->setValue(6);
    channelSpin_->setAccessibleName("Monitor Channel");
    chLabel->setBuddy(channelSpin_);
    channelBtn_ = new QPushButton("S&et Ch", central);
    channelBtn_->setEnabled(false);
    hopCheck_ = new QCheckBox("&Hop ch", central);
    hopCheck_->setToolTip("Automatically hop channels with 3s EAPOL handshake hold");
    hopCheck_->setChecked(app_.channelHopEnabled());
    hop5GhzCheck_ = new QCheckBox("&5 GHz", central);
    hop5GhzCheck_->setToolTip("Include 5 GHz UNII channels in automatic channel hopping");
    hop5GhzCheck_->setChecked(app_.hop5Ghz());
    adaptiveHopCheck_ = new QCheckBox("A&daptive", central);
    adaptiveHopCheck_->setToolTip("Use UCB1 multi-armed bandit adaptive dwell on productive channels");
    adaptiveHopCheck_->setChecked(app_.adaptiveHop());
    hotkeysCheck_ = new QCheckBox("Hot&keys", central);
    hotkeysCheck_->setToolTip("Toggle single-key shortcuts (T, V, M, [, ], 1-5) so typing never misfires");
    hotkeysCheck_->setChecked(true);
    freezeSortCheck_ = new QCheckBox("&Freeze sort", central);
    freezeSortCheck_->setToolTip("Preserve table row order during live scans");
    chRow->addWidget(chLabel);
    chRow->addWidget(channelSpin_);
    chRow->addWidget(channelBtn_);
    chRow->addWidget(hopCheck_);
    chRow->addWidget(hop5GhzCheck_);
    chRow->addWidget(adaptiveHopCheck_);
    chRow->addWidget(hotkeysCheck_);
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
    pmkidBtn_ = new QPushButton("&PMKID probe…", central);
    pmkidBtn_->setEnabled(false);
    pmkidBtn_->setToolTip("Clientless PMKID probe (WPA2 only). Complements deauth; WPA3-SAE/PMF "
                          "targets have no PMKID — use deauth there.");
    authLayout->addWidget(authBanner_);
    authLayout->addWidget(authCheck_);
    auto* authBtnRow = new QHBoxLayout();
    authBtnRow->addWidget(allowBtn);
    authBtnRow->addWidget(trustBtn);
    authBtnRow->addWidget(deauthBtn_);
    authBtnRow->addWidget(pmkidBtn_);
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
        {"BSSID", "SSID", "CH", "dBm", "ENC", "WPS/PMF", "Clients", "Capture", "Trusted", "Allowed"});
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tabs_->addTab(table_, "Networks (0)");

    bleTable_ = new QTableWidget(0, 7, tabs_);
    bleTable_->setAccessibleName("Discovered Bluetooth devices");
    bleTable_->setHorizontalHeaderLabels(
        {"MAC", "Name", "dBm", "Signal", "Vendor", "Service", "Status / Seen"});
    bleTable_->horizontalHeader()->setStretchLastSection(true);
    bleTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    bleTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    bleTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tabs_->addTab(bleTable_, "Bluetooth (0)");

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
    connect(hop5GhzCheck_, &QCheckBox::toggled, this, [this](bool on) {
        app_.setHop5Ghz(on);
    });
    connect(adaptiveHopCheck_, &QCheckBox::toggled, this, [this](bool on) {
        app_.setAdaptiveHop(on);
    });
    connect(bleAutoCheck_, &QCheckBox::toggled, this, [this](bool on) {
        app_.setBleAutoEnabled(on);
    });
    connect(notifyCheck_, &QCheckBox::toggled, this, [this](bool on) {
        app_.setNotificationsEnabled(on);
    });
    connect(hotkeysCheck_, &QCheckBox::toggled, this, [this](bool on) {
        for (QShortcut* sc : singleKeyShortcuts_) {
            if (sc != nullptr) {
                sc->setEnabled(on);
            }
        }
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
    connect(hc22000Btn_, &QPushButton::clicked, this, &MainWindow::onExportHandshakes);
    connect(wardriveBtn_, &QPushButton::clicked, this, &MainWindow::onToggleWardrive);
    connect(bleBtn_, &QPushButton::clicked, this, &MainWindow::onBleScan);
    connect(subGhzBtn_, &QPushButton::clicked, this, &MainWindow::onToggleSubGhz);
    connect(clearThreatBtn_, &QPushButton::clicked, this, &MainWindow::onClearThreat);
    connect(filterEdit_, &QLineEdit::textChanged, this, &MainWindow::onFilterChanged);
    connect(authCheck_, &QCheckBox::toggled, this, &MainWindow::onAuthToggled);
    connect(allowBtn, &QPushButton::clicked, this, &MainWindow::onAllowSelected);
    connect(trustBtn, &QPushButton::clicked, this, &MainWindow::onTrustSelected);
    connect(deauthBtn_, &QPushButton::clicked, this, &MainWindow::onDeauthSelected);
    connect(pmkidBtn_, &QPushButton::clicked, this, &MainWindow::onPmkidSelected);

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

    auto addSingleShortcut = [this](const QKeySequence& seq) -> QShortcut* {
        auto* sc = new QShortcut(seq, this);
        singleKeyShortcuts_.push_back(sc);
        return sc;
    };
    connect(addSingleShortcut(QKeySequence(Qt::Key_BracketLeft)), &QShortcut::activated,
            this, &MainWindow::onPrevTheme);
    connect(addSingleShortcut(QKeySequence(Qt::Key_BracketRight)), &QShortcut::activated,
            this, &MainWindow::onCycleTheme);
    connect(addSingleShortcut(QKeySequence(Qt::Key_T)), &QShortcut::activated,
            this, &MainWindow::onCycleTheme);
    connect(addSingleShortcut(QKeySequence(Qt::SHIFT | Qt::Key_T)), &QShortcut::activated,
            this, &MainWindow::onPrevTheme);
    connect(addSingleShortcut(QKeySequence(Qt::Key_V)), &QShortcut::activated,
            this, &MainWindow::onCycleView);
    connect(addSingleShortcut(QKeySequence(Qt::Key_M)), &QShortcut::activated,
            this, &MainWindow::onCycleMode);
    connect(addSingleShortcut(QKeySequence(Qt::Key_1)), &QShortcut::activated, this, [this]() {
        app_.dispatchPet(SetPageEvent{linux_app::nowMs(), ScreenPage::PetFace});
        pet_->setFrame(app_.petFrame(kPetDims));
    });
    connect(addSingleShortcut(QKeySequence(Qt::Key_2)), &QShortcut::activated, this, [this]() {
        app_.dispatchPet(SetPageEvent{linux_app::nowMs(), ScreenPage::NearbyRadar});
        pet_->setFrame(app_.petFrame(kPetDims));
    });
    connect(addSingleShortcut(QKeySequence(Qt::Key_3)), &QShortcut::activated, this, [this]() {
        app_.dispatchPet(SetPageEvent{linux_app::nowMs(), ScreenPage::ChannelSpectrum});
        pet_->setFrame(app_.petFrame(kPetDims));
    });
    connect(addSingleShortcut(QKeySequence(Qt::Key_4)), &QShortcut::activated, this, [this]() {
        app_.dispatchPet(SetPageEvent{linux_app::nowMs(), ScreenPage::RfGuard});
        pet_->setFrame(app_.petFrame(kPetDims));
    });
    connect(addSingleShortcut(QKeySequence(Qt::Key_5)), &QShortcut::activated, this, [this]() {
        app_.dispatchPet(SetPageEvent{linux_app::nowMs(), ScreenPage::Captures});
        pet_->setFrame(app_.petFrame(kPetDims));
    });

    timer_ = new QTimer(this);
    connect(timer_, &QTimer::timeout, this, &MainWindow::onTick);
    timer_->start(100);

    if (app_.secState().targets.empty()) {
        app_.requestScan();
    } else {
        refreshNetworks(true);
        refreshBluetooth(true);
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
        refreshBluetooth(false);
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
    std::size_t btCount = 0u;
    if (app_.consumeBleScanFinished(&btCount)) {
        statusBar()->showMessage(
            QString("Bluetooth scan finished: %1 device(s) discovered").arg(btCount), 5000);
    }
}

void MainWindow::refreshStatus() {
    const AppState& ps = app_.petState();
    const QString statusText = QString("%1  ·  [%2]  ·  Lv.%3 (HI:%4%5)  ·  Cap:%6  ·  mood %7  ·  battery %8%")
                                   .arg(themeSpec(ps.theme).name)
                                   .arg(opsModeLabel(ps.opsMode))
                                   .arg(ps.level)
                                   .arg(ps.highScore)
                                   .arg(ps.highScoreBeaten ? "!" : "")
                                   .arg(ps.capturesSaved)
                                   .arg(faceForMood(ps.mood).moodLabel)
                                   .arg(ps.batteryPercent);
    if (status_->text() != statusText) {
        status_->setText(statusText);
    }
    const QString modeText = QString("M&ode: %1").arg(opsModeLabel(ps.opsMode));
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
    QString engText = QString("Interface %1 · %2")
                          .arg(QString::fromStdString(app_.interfaceName()))
                          .arg(app_.monitoring()
                                   ? QString::fromStdString(app_.engineLabel())
                                   : QString("recon (active scan only)"));
    if (app_.wardriving()) {
        engText += QString(" · Wardrive:%1 (%2)")
                       .arg(app_.wardriveLoggedCount())
                       .arg(app_.gpsState().hasFix
                                ? QString("GPS %1 sats").arg(app_.gpsState().satellites)
                                : QString("waiting GPS"));
    }
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
    if (wardriveBtn_ != nullptr) {
        const QString wdText = app_.wardriving() ? "Stop &Wardrive" : "&Wardrive…";
        if (wardriveBtn_->text() != wdText) {
            wardriveBtn_->setText(wdText);
        }
    }
    if (notifyCheck_ != nullptr && notifyCheck_->isChecked() != app_.notificationsEnabled()) {
        QSignalBlocker blocker(notifyCheck_);
        notifyCheck_->setChecked(app_.notificationsEnabled());
    }
    if (bleBtn_ != nullptr) {
        const bool btBusy = app_.bleScanning();
        const QString btText = btBusy ? QString("BT Scanning…") : QString("&BT Scan");
        if (bleBtn_->text() != btText) {
            bleBtn_->setText(btText);
        }
        bleBtn_->setEnabled(app_.bleAvailable() && !btBusy);
    }
    if (subGhzBtn_ != nullptr) {
        const QString sgText = app_.subGhzRunning() ? QString("Stop &Sub-GHz") : QString("&Sub-GHz");
        if (subGhzBtn_->text() != sgText) {
            subGhzBtn_->setText(sgText);
        }
        subGhzBtn_->setEnabled(app_.subGhzAvailable());
    }
    if (hc22000Btn_ != nullptr) {
        const std::size_t hsCnt = app_.collectedHandshakeCount();
        hc22000Btn_->setToolTip(
            QString("Export validated crackable handshakes/PMKIDs for hashcat -m 22000 (%1 ready)")
                .arg(hsCnt));
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
    pmkidBtn_->setEnabled(deauthReady);  // same gate (armed + allow-listed + monitoring)
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
            containsLower(sec::encryptionLabel(t.enc), needle) ||
            containsLower(sec::pmfStatusLabel(t.pmf), needle) ||
            (t.pmf != sec::PmfStatus::Disabled && containsLower("pmf", needle))) {
            visible.push_back(&t);
        }
    }
    const auto& auth = app_.authorization();
    tabs_->setTabText(0, QString("Networks (%1)").arg(visible.size()));
    const std::string selBssid = selectedBssid();
    const int prevCol = (std::max)(0, table_->currentColumn());
    table_->setRowCount(static_cast<int>(visible.size()));
    int selRow = -1;
    for (int i = 0; i < static_cast<int>(visible.size()); ++i) {
        const auto& t = *visible[static_cast<std::size_t>(i)];
        setCellText(table_, i, 0, QString::fromStdString(t.bssid));
        setCellText(table_, i, 1,
                    t.ssid.empty() ? QString("<hidden>") : QString::fromStdString(t.ssid));
        const int32_t dispCh =
            zd::is6GhzChannel(t.channel) ? (t.channel - zd::k6GhzChannelBase) : t.channel;
        setCellText(table_, i, 2, QString::number(dispCh));
        setCellText(table_, i, 3, QString::number(t.rssi));
        setCellText(table_, i, 4, QString(sec::encryptionLabel(t.enc)));
        QString secFlags;
        if (t.wps && t.pmf != sec::PmfStatus::Disabled) {
            secFlags = QString("WPS+PMF-%1").arg(sec::pmfStatusLabel(t.pmf));
        } else if (t.wps) {
            secFlags = QString("WPS*");
        } else if (t.pmf != sec::PmfStatus::Disabled) {
            secFlags = QString("PMF-%1").arg(sec::pmfStatusLabel(t.pmf));
        } else {
            secFlags = QString("-");
        }
        QTableWidgetItem* wpsItem = setCellText(table_, i, 5, secFlags);
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
    if (selRow >= 0 && (table_->currentRow() != selRow || table_->currentColumn() != prevCol)) {
        QSignalBlocker blocker(table_);
        table_->setCurrentCell(selRow, prevCol);
    }
}

void MainWindow::refreshBluetooth(bool force) {
    if (bleTable_ == nullptr) {
        return;
    }
    const auto& sec = app_.secState();
    if (!force && sec.revision == lastBleRev_) {
        return;
    }
    lastBleRev_ = sec.revision;
    const std::string needle =
        (filterEdit_ != nullptr) ? zd::toLowerAscii(filterEdit_->text().trimmed().toStdString())
                                 : std::string{};
    std::vector<const sec::BleTarget*> ranked;
    ranked.reserve(sec.bleTargets.size());
    for (const auto& b : sec.bleTargets) {
        ranked.push_back(&b);
    }
    std::sort(ranked.begin(), ranked.end(), [](const sec::BleTarget* a, const sec::BleTarget* b) {
        const bool ta = (a->threat != zd::BleThreatKind::None);
        const bool tb = (b->threat != zd::BleThreatKind::None);
        if (ta != tb) {
            return ta;
        }
        if (a->rssi != b->rssi) {
            return a->rssi > b->rssi;
        }
        return a->mac < b->mac;
    });
    std::vector<const sec::BleTarget*> visible;
    visible.reserve(ranked.size());
    for (const sec::BleTarget* bp : ranked) {
        const auto& b = *bp;
        const std::string dispName = b.name.empty() ? "Unnamed" : b.name;
        const std::string vendor = zd::bleVendorOrOuiLabel(b.companyId, b.mac);
        const std::string svc = zd::bleServiceLabel(b.serviceUuid);
        const std::string status = zd::bleThreatLabel(b.threat);
        if (containsLower(b.mac, needle) || containsLower(dispName, needle) ||
            containsLower(vendor, needle) || containsLower(svc, needle) ||
            containsLower(status, needle) || containsLower("bluetooth", needle) ||
            containsLower("ble", needle)) {
            visible.push_back(bp);
        }
    }
    const int curBleRow = bleTable_->currentRow();
    const QString prevBleMac =
        (curBleRow >= 0 && bleTable_->item(curBleRow, 0) != nullptr)
            ? bleTable_->item(curBleRow, 0)->text()
            : QString{};
    const int prevBleCol = (std::max)(0, bleTable_->currentColumn());
    tabs_->setTabText(1, QString("Bluetooth (%1)").arg(visible.size()));
    bleTable_->setRowCount(static_cast<int>(visible.size()));
    int selBleRow = -1;
    for (int i = 0; i < static_cast<int>(visible.size()); ++i) {
        const auto& b = *visible[static_cast<std::size_t>(i)];
        const std::string dispName = b.name.empty() ? "Unnamed" : b.name;
        const int bars = zd::rssiToBars(b.rssi);
        const QString barStr = QString(bars, QChar('#')) + QString(4 - bars, QChar('.'));
        const std::string vendor = zd::bleVendorOrOuiLabel(b.companyId, b.mac);
        const std::string svc = zd::bleServiceLabel(b.serviceUuid);
        const bool isThreat = (b.threat != zd::BleThreatKind::None);
        const QString statusStr =
            QString("%1 (x%2)").arg(zd::bleThreatLabel(b.threat)).arg(b.seenCount);
        const QString macStr = QString::fromStdString(b.mac);
        setCellText(bleTable_, i, 0, macStr);
        setCellText(bleTable_, i, 1, QString::fromStdString(dispName));
        setCellText(bleTable_, i, 2, QString::number(b.rssi));
        setCellText(bleTable_, i, 3, barStr);
        setCellText(bleTable_, i, 4, QString::fromStdString(vendor));
        setCellText(bleTable_, i, 5, QString::fromStdString(svc));
        QTableWidgetItem* stItem = setCellText(bleTable_, i, 6, statusStr);
        styleWarnBadge(stItem, isThreat);
        if (!prevBleMac.isEmpty() && macStr == prevBleMac) {
            selBleRow = i;
        }
    }
    if (selBleRow >= 0 &&
        (bleTable_->currentRow() != selBleRow || bleTable_->currentColumn() != prevBleCol)) {
        QSignalBlocker blocker(bleTable_);
        bleTable_->setCurrentCell(selBleRow, prevBleCol);
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
    std::vector<const sec::Station*> ranked;
    ranked.reserve(sec.stations.size());
    for (const auto& st : sec.stations) {
        ranked.push_back(&st);
    }
    std::sort(ranked.begin(), ranked.end(), [](const sec::Station* a, const sec::Station* b) {
        if (a->probeCount != b->probeCount) {
            return a->probeCount > b->probeCount;
        }
        return a->mac < b->mac;
    });
    std::vector<const sec::Station*> visible;
    visible.reserve(ranked.size());
    for (const sec::Station* stp : ranked) {
        const auto& st = *stp;
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
            visible.push_back(stp);
        }
    }
    const int curStaRow = stationsTable_->currentRow();
    const QString prevStaMac =
        (curStaRow >= 0 && stationsTable_->item(curStaRow, 0) != nullptr)
            ? stationsTable_->item(curStaRow, 0)->text()
            : QString{};
    const int prevStaCol = (std::max)(0, stationsTable_->currentColumn());
    tabs_->setTabText(2, QString("Stations / Probes (%1)").arg(visible.size()));
    stationsTable_->setRowCount(static_cast<int>(visible.size()));
    int selStaRow = -1;
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
        const QString macStr = QString::fromStdString(st.mac);
        setCellText(stationsTable_, i, 0, macStr);
        setCellText(stationsTable_, i, 1,
                    st.lastBssid.empty() ? QString("-") : QString::fromStdString(st.lastBssid));
        setCellText(stationsTable_, i, 2, QString::number(st.probeCount));
        QTableWidgetItem* riskItem =
            setCellText(stationsTable_, i, 3, weak ? QString("WEAK / DEFAULT") : QString("-"));
        styleWarnBadge(riskItem, weak);
        setCellText(stationsTable_, i, 4, probedList);
        if (!prevStaMac.isEmpty() && macStr == prevStaMac) {
            selStaRow = i;
        }
    }
    if (selStaRow >= 0 &&
        (stationsTable_->currentRow() != selStaRow ||
         stationsTable_->currentColumn() != prevStaCol)) {
        QSignalBlocker blocker(stationsTable_);
        stationsTable_->setCurrentCell(selStaRow, prevStaCol);
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
        int32_t rssi = -100;
        QString status;
        uint32_t count = 0u;
        bool alert = false;
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

    const int curRfRow = rfGuardTable_->currentRow();
    const QString prevRfKey =
        (curRfRow >= 0 && rfGuardTable_->item(curRfRow, 0) != nullptr &&
         rfGuardTable_->item(curRfRow, 1) != nullptr)
            ? (rfGuardTable_->item(curRfRow, 0)->text() + "|" +
               rfGuardTable_->item(curRfRow, 1)->text())
            : QString{};
    const int prevRfCol = (std::max)(0, rfGuardTable_->currentColumn());
    tabs_->setTabText(3, QString("RF Guard (%1)").arg(rows.size()));
    rfGuardTable_->setRowCount(static_cast<int>(rows.size()));
    int selRfRow = -1;
    for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
        const auto& r = rows[static_cast<std::size_t>(i)];
        setCellText(rfGuardTable_, i, 0, r.band);
        setCellText(rfGuardTable_, i, 1, r.addr);
        setCellText(rfGuardTable_, i, 2, r.name);
        setCellText(rfGuardTable_, i, 3, QString::number(r.rssi));
        QTableWidgetItem* stItem = setCellText(rfGuardTable_, i, 4, r.status);
        styleWarnBadge(stItem, r.alert);
        setCellText(rfGuardTable_, i, 5, QString::number(r.count));
        if (!prevRfKey.isEmpty() && (r.band + "|" + r.addr) == prevRfKey) {
            selRfRow = i;
        }
    }
    if (selRfRow >= 0 &&
        (rfGuardTable_->currentRow() != selRfRow || rfGuardTable_->currentColumn() != prevRfCol)) {
        QSignalBlocker blocker(rfGuardTable_);
        rfGuardTable_->setCurrentCell(selRfRow, prevRfCol);
    }
}

void MainWindow::refreshAlerts() {
    const auto& sec = app_.secState();
    const auto& alerts = sec.alerts;
    if (sec.totalAlertsEmitted < lastTotalAlerts_) {
        alerts_->clear();
        lastTotalAlerts_ = 0u;
    }
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
    QString band6;
    for (const auto& c : dist) {
        const int32_t dispCh =
            zd::is6GhzChannel(c.channel) ? (c.channel - zd::k6GhzChannelBase) : c.channel;
        const QString part = QString("ch%1×%2 ").arg(dispCh).arg(c.count);
        if (c.band == sec::Band::Band24GHz) {
            band24 += part;
        } else if (c.band == sec::Band::Band5GHz) {
            band5 += part;
        } else if (c.band == sec::Band::Band6GHz) {
            band6 += part;
        }
    }
    channelsLabel_->setText(QString("2.4GHz: %1\n5GHz: %2\n6GHz: %3")
                                .arg(band24.isEmpty() ? QString("-") : band24)
                                .arg(band5.isEmpty() ? QString("-") : band5)
                                .arg(band6.isEmpty() ? QString("-") : band6));
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
    if (tabs_ != nullptr && tabs_->currentIndex() == 2) {
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
    lastBleRev_ = UINT64_MAX;
    lastStationsRev_ = UINT64_MAX;
    lastRfGuardRev_ = UINT64_MAX;
    lastChannelsRev_ = UINT64_MAX;
    displayedTargets_.clear();
    refreshNetworks(true);
    refreshBluetooth(true);
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
    QString selectedFilter;
    QString path = QFileDialog::getSaveFileName(
        this, "Export Assessment Report", "zeroday_report.md",
        "Markdown Report (*.md);;CSV Report (*.csv);;HTML Report (*.html)", &selectedFilter);
    if (path.isEmpty()) {
        return;
    }
    if (!sec::reportFormatFromPath(path.toStdString()).has_value()) {
        if (selectedFilter.contains("*.csv")) {
            path += ".csv";
        } else if (selectedFilter.contains("*.html")) {
            path += ".html";
        } else {
            path += ".md";
        }
    }
    const auto r = app_.exportReport(path.toStdString());
    statusBar()->showMessage(QString::fromStdString(r.message), 6000);
    if (!r.ok) {
        QMessageBox::warning(this, "Export Report", QString::fromStdString(r.message));
    }
}

void MainWindow::onExportHandshakes() {
    if (app_.collectedHandshakeCount() == 0u) {
        statusBar()->showMessage("No crackable handshakes/PMKIDs captured yet.", 5000);
        return;
    }
    QString path = QFileDialog::getSaveFileName(
        this, "Export Hashcat 22000 Handshakes", "handshakes.hc22000",
        "Hashcat 22000 (*.hc22000 *.22000);;All Files (*)");
    if (path.isEmpty()) {
        return;
    }
    const auto r = app_.exportHandshakes(path.toStdString());
    statusBar()->showMessage(QString::fromStdString(r.message), 6000);
    if (!r.ok) {
        QMessageBox::warning(this, "Export .hc22000", QString::fromStdString(r.message));
    }
}

void MainWindow::onBleScan() {
    const auto r = app_.requestBleScan();
    statusBar()->showMessage(QString::fromStdString(r.message), 5000);
    refreshStatus();
}

void MainWindow::onToggleSubGhz() {
    const auto r = app_.subGhzRunning()
                       ? app_.stopSubGhz()
                       : app_.startSubGhz(app_.petState().subGhzFreqKhz);
    statusBar()->showMessage(QString::fromStdString(r.message), 5000);
    if (!r.ok && app_.subGhzAvailable()) {
        QMessageBox::warning(this, "Sub-GHz Listener", QString::fromStdString(r.message));
    }
    refreshStatus();
}

void MainWindow::onToggleWardrive() {
    if (app_.wardriving()) {
        app_.stopWardrive();
        statusBar()->showMessage(
            QString("Wardrive stopped (%1 APs logged)").arg(app_.wardriveLoggedCount()), 5000);
        refreshStatus();
        return;
    }
    const QString path = QFileDialog::getSaveFileName(
        this, "Start WiGLE Wardriving CSV", "wardrive.wigle.csv", "WiGLE CSV (*.csv);;All Files (*)");
    if (path.isEmpty()) {
        return;
    }
    const auto r = app_.startWardrive(path.toStdString());
    statusBar()->showMessage(QString::fromStdString(r.message), 6000);
    if (!r.ok) {
        QMessageBox::warning(this, "Wardriving", QString::fromStdString(r.message));
    }
    refreshStatus();
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
        statusBar()->showMessage("Select a network row (or associated station) first.", 5000);
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
    lastBleRev_ = UINT64_MAX;
    lastStationsRev_ = UINT64_MAX;
    lastRfGuardRev_ = UINT64_MAX;
    refreshNetworks(true);
    refreshBluetooth(true);
    refreshStations(true);
    refreshRfGuard(true);
}

void MainWindow::onAuthToggled(bool on) {
    if (on && !app_.authorization().operatorConfirmed) {
        const auto choice = QMessageBox::warning(
            this, "Confirm Offensive Authorization",
            "Arming enables active 802.11 deauthentication against allow-listed BSSIDs.\n\n"
            "Only proceed on networks you own or have explicit written authorization to assess.\n\n"
            "Arm offensive transmitter?",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (choice != QMessageBox::Yes) {
            QSignalBlocker blocker(authCheck_);
            authCheck_->setChecked(false);
            refreshStatus();
            return;
        }
    }
    app_.confirmAuthorization(on);
    refreshStatus();
}

void MainWindow::onAllowSelected() {
    std::string bssid;
    std::string station;
    resolveSelectedTarget(bssid, station);
    if (bssid.empty()) {
        const QString msg = (tabs_ != nullptr && tabs_->currentIndex() == 2)
                                ? QString("Select an associated station (or switch to the Networks tab).")
                                : QString("Select a network row first.");
        statusBar()->showMessage(msg, 5000);
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
        const QString msg = (tabs_ != nullptr && tabs_->currentIndex() == 2)
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
    QCheckBox* tuneCheck = nullptr;
    int targetCh = 0;
    if (targetAp != nullptr && targetAp->channel > 0 && app_.monitoring()) {
        targetCh = targetAp->channel;
        tuneCheck = new QCheckBox(
            QString("Auto-tune monitor interface to AP channel %1 before transmit").arg(targetCh),
            &dlg);
        tuneCheck->setChecked(true);
        form->addRow("Channel", tuneCheck);
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
    const int tuneCh = (tuneCheck != nullptr && tuneCheck->isChecked()) ? targetCh : 0;
    if (tuneCh > 0 && channelSpin_ != nullptr) {
        channelSpin_->setValue(tuneCh);
    }
    const auto r = app_.requestDeauth(
        bssid, client, static_cast<uint32_t>(countSpin->value()), tuneCh);
    statusBar()->showMessage(QString::fromStdString(r.message), 6000);
    if (!r.ok) {
        QMessageBox::warning(this, "Deauth", QString::fromStdString(r.message));
        return;
    }
}

void MainWindow::onPmkidSelected() {
    std::string bssid;
    std::string prefillClient;
    resolveSelectedTarget(bssid, prefillClient);
    if (bssid.empty()) {
        QMessageBox::information(this, "PMKID probe", "Select a network row first.");
        return;
    }
    // Same authorization gate as deauth.
    const sec::AuthDecision decision = sec::authorize(app_.authorization(), bssid);
    if (decision != sec::AuthDecision::Allowed) {
        QMessageBox::critical(
            this, "Transmit blocked",
            QString("PMKID probe against %1 is blocked:\n\n%2\n\nConfirm authorization and "
                    "allow-list this BSSID first.")
                .arg(QString::fromStdString(bssid))
                .arg(sec::authDecisionLabel(decision)));
        return;
    }
    if (!app_.monitoring()) {
        QMessageBox::information(this, "PMKID probe", "Start monitor mode first.");
        return;
    }

    QDialog dlg(this);
    dlg.setWindowTitle("Clientless PMKID probe — authorized target");
    auto* form = new QFormLayout(&dlg);
    auto* note = new QLabel(
        "Sends auth+assoc from a throwaway MAC to solicit the AP's EAPOL M1 (and any RSN "
        "PMKID) without kicking a client. WPA2 only — a WPA3-SAE/PMF target has no PMKID, so "
        "use Deauth there. This action is logged.",
        &dlg);
    note->setWordWrap(true);
    note->setStyleSheet("background:#1d4ed8; color:#ffffff; padding:6px; border-radius:4px;");
    form->addRow(note);
    auto* bssidEdit = new QLineEdit(QString::fromStdString(bssid), &dlg);
    bssidEdit->setReadOnly(true);
    form->addRow("Target BSSID", bssidEdit);
    auto* countSpin = new QSpinBox(&dlg);
    countSpin->setRange(1, 1000);
    countSpin->setValue(8);
    form->addRow("Auth/assoc attempts", countSpin);
    auto* buttons =
        new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    form->addRow(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    if (dlg.exec() != QDialog::Accepted) {
        return;
    }
    int tuneCh = 0;
    if (const sec::WifiTarget* t = sec::findTarget(app_.secState(), bssid)) {
        tuneCh = t->channel;
    }
    const auto r =
        app_.requestPmkidProbe(bssid, static_cast<uint32_t>(countSpin->value()), tuneCh);
    statusBar()->showMessage(QString::fromStdString(r.message), 6000);
    if (!r.ok) {
        QMessageBox::warning(this, "PMKID probe", QString::fromStdString(r.message));
    }
}

}  // namespace linux_gui
}  // namespace zd
