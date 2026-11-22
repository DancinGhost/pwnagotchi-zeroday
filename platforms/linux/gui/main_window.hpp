#pragma once

// Qt6 desktop dashboard for pwnagotchi-zeroday. Wraps the shared AppController: the pet
// screen, a live network table, a defensive-alerts feed, recon/monitor controls, and the
// authorization-gated offensive panel (deauth). The transmit gate lives in the pure
// SecSession; this window only exposes it and refuses to arm it without explicit operator
// confirmation + an allow-list entry.

#include <cstdint>
#include <string>
#include <vector>

#include <QCheckBox>
#include <QCloseEvent>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>

#include "../app/controller.hpp"
#include "pet_widget.hpp"

namespace zd {
namespace linux_gui {

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(linux_app::AppController& app, QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void onTick();
    void onScan();
    void onToggleMonitor();
    void onSetChannel();
    void onPrevTheme();
    void onCycleTheme();
    void onCycleView();
    void onCycleMode();
    void onLoadSession();
    void onSaveSession();
    void onToggleRecord();
    void onSelectPcap();
    void onExportReport();
    void onBleScan();
    void onClearThreat();
    void onTrustSelected();
    void onFilterChanged();
    void onAuthToggled(bool on);
    void onAllowSelected();
    void onDeauthSelected();

private:
    static constexpr ScreenDimensions kPetDims{240, 135};

    void refreshNetworks(bool force = false);
    void refreshStations(bool force = false);
    void refreshRfGuard(bool force = false);
    void refreshAlerts();
    void refreshStatus();
    void refreshChannels(bool force = false);
    void pollAsyncResult();
    std::string selectedBssid() const;
    void resolveSelectedTarget(std::string& bssidOut, std::string& stationOut) const;

    linux_app::AppController& app_;
    PetWidget* pet_ = nullptr;
    QLabel* status_ = nullptr;
    QLabel* secMoodLabel_ = nullptr;
    QLabel* phrase_ = nullptr;
    QLabel* engineLabel_ = nullptr;
    QLabel* authBanner_ = nullptr;
    QLabel* channelsLabel_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QTabWidget* tabs_ = nullptr;
    QTableWidget* table_ = nullptr;
    QTableWidget* stationsTable_ = nullptr;
    QTableWidget* rfGuardTable_ = nullptr;
    QListWidget* alerts_ = nullptr;
    QCheckBox* authCheck_ = nullptr;
    QCheckBox* freezeSortCheck_ = nullptr;
    QCheckBox* hopCheck_ = nullptr;
    QPushButton* monitorBtn_ = nullptr;
    QPushButton* modeBtn_ = nullptr;
    QPushButton* recordBtn_ = nullptr;
    QPushButton* bleBtn_ = nullptr;
    QPushButton* clearThreatBtn_ = nullptr;
    QSpinBox* channelSpin_ = nullptr;
    QPushButton* channelBtn_ = nullptr;
    QPushButton* deauthBtn_ = nullptr;
    QTimer* timer_ = nullptr;
    std::vector<sec::WifiTarget> displayedTargets_;
    std::uint32_t lastTotalAlerts_ = 0;
    std::uint32_t lastTableRefreshMs_ = 0;
    std::uint64_t lastNetworksRev_ = UINT64_MAX;
    std::uint64_t lastStationsRev_ = UINT64_MAX;
    std::uint64_t lastRfGuardRev_ = UINT64_MAX;
    std::uint64_t lastChannelsRev_ = UINT64_MAX;
    int lastSecMoodStyled_ = -1;
    int lastAuthStyled_ = -1;
};

}  // namespace linux_gui
}  // namespace zd
