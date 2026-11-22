// Offscreen Qt6 GUI widget/window verification tests (`QT_QPA_PLATFORM=offscreen`).
// Validates auth banner safe/ARMED styling, session replay population, allow-listing,
// SecMood accessibility descriptions, and UI responsiveness without hardware devices.

#include <QApplication>
#include <QCheckBox>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QTabWidget>
#include <QTableWidget>
#include <QTemporaryDir>
#include <cassert>
#include <iostream>
#include <vector>

#include "../../platforms/linux/app/controller.hpp"
#include "../../platforms/linux/backend/cli_backend.hpp"
#include "../../platforms/linux/gui/main_window.hpp"
#include "../../platforms/linux/gui/pet_widget.hpp"
#include "zd/secops.hpp"

int main(int argc, char** argv) {
    QApplication app(argc, argv);

    QTemporaryDir tmpDir;
    assert(tmpDir.isValid());
    qputenv("HOME", tmpDir.path().toUtf8());
    const std::string sessPath = tmpDir.filePath("gui_test.zds").toStdString();

    const std::vector<zd::sec::SecEvent> events = {
        zd::sec::ApObserved{1000u, "02:aa:bb:cc:dd:01", "CorpNet", 6, -42,
                            zd::sec::Encryption::Wpa2, false},
        zd::sec::ApObserved{1100u, "02:aa:bb:cc:dd:02", "CorpNet", 6, -45,
                            zd::sec::Encryption::Open, false},  // triggers OpenDowngrade / Alarmed
        zd::sec::ProbeRequestObserved{1200u, "02:11:22:33:44:55", "linksys"},
        zd::sec::ClientObserved{1300u, "02:aa:bb:cc:dd:01", "02:11:22:33:44:55"},
    };
    assert(zd::linux_backend::saveEventsToFile(sessPath, events));

    zd::linux_app::AppController ctrl("wlan0");
    ctrl.boot(77u);
    const auto loadRes = ctrl.loadSession(sessPath);
    assert(loadRes.ok);

    zd::linux_gui::MainWindow win(ctrl);
    win.show();
    QApplication::processEvents();

    // 1. Auth banner must start disarmed (safe) with green background (#145a32), never red.
    QCheckBox* authCheck = nullptr;
    for (QCheckBox* cb : win.findChildren<QCheckBox*>()) {
        if (cb->text().contains("authorized to transmit")) {
            authCheck = cb;
            break;
        }
    }
    assert(authCheck != nullptr);
    assert(!authCheck->isChecked());

    QLabel* authBanner = nullptr;
    QLabel* secMoodLabel = nullptr;
    for (QLabel* lbl : win.findChildren<QLabel*>()) {
        if (lbl->text().contains("Safe (passive):")) {
            authBanner = lbl;
        }
        if (lbl->text().startsWith("SEC:")) {
            secMoodLabel = lbl;
        }
    }
    assert(authBanner != nullptr);
    assert(authBanner->styleSheet().contains("#145a32"));
    assert(secMoodLabel != nullptr);
    assert(secMoodLabel->text().contains("ALARMED"));  // OpenDowngrade stays Alarmed in replay

    // Arming flips auth banner to crimson (#991b1b).
    authCheck->setChecked(true);
    QApplication::processEvents();
    assert(authBanner->text().contains("ARMED"));
    assert(authBanner->styleSheet().contains("#991b1b"));
    authCheck->setChecked(false);
    QApplication::processEvents();

    // 2. Network table, station table, RF Guard tab & defensive alert list populated.
    QTabWidget* tabs = win.findChild<QTabWidget*>();
    assert(tabs != nullptr);
    assert(tabs->count() == 3);
    auto* netTable = qobject_cast<QTableWidget*>(tabs->widget(0));
    auto* staTable = qobject_cast<QTableWidget*>(tabs->widget(1));
    auto* rfTable = qobject_cast<QTableWidget*>(tabs->widget(2));
    assert(netTable != nullptr && staTable != nullptr && rfTable != nullptr);
    assert(netTable->rowCount() == 2);
    assert(staTable->rowCount() == 1);
    assert(!netTable->accessibleName().isEmpty());
    assert(!staTable->accessibleName().isEmpty());

    // Live filter narrows visible network rows, then restores on clear.
    QLineEdit* filterEdit = nullptr;
    for (QLineEdit* le : win.findChildren<QLineEdit*>()) {
        if (le->placeholderText().contains("Filter")) {
            filterEdit = le;
            break;
        }
    }
    assert(filterEdit != nullptr);
    filterEdit->setText("dd:02");
    QApplication::processEvents();
    assert(netTable->rowCount() == 1);
    filterEdit->clear();
    QApplication::processEvents();
    assert(netTable->rowCount() == 2);

    // RF Guard tab populates BLE + Sub-GHz observations & threat banner clears on button click.
    ctrl.ingestBle({zd::BleDevice{"7a:3c:91:04:88:12", "Tracker_Tag", -52, 0x004Cu, 0u, true,
                                  zd::BleThreatKind::AirTagTracker}});
    ctrl.ingestSubGhz(zd::SubGhzSignal{433920u, -48, "OOK", 6u, zd::SubGhzAnomaly::ReplayBurst});
    ctrl.loadSession(sessPath);
    ctrl.ingestBle({zd::BleDevice{"7a:3c:91:04:88:12", "Tracker_Tag", -52, 0x004Cu, 0u, true,
                                  zd::BleThreatKind::AirTagTracker}});
    win.show();
    // Force a refresh tick via filter toggle so RF Guard tab mirrors current state immediately.
    filterEdit->setText(" ");
    filterEdit->clear();
    QApplication::processEvents();
    assert(rfTable->rowCount() >= 1);

    const auto lists = win.findChildren<QListWidget*>();
    assert(lists.size() == 1);
    assert(lists[0]->count() >= 1);

    // 3. Selecting a station row allows its Associated BSSID & Trust BSSID persists cleanly.
    tabs->setCurrentIndex(1);
    staTable->selectRow(0);
    QPushButton* allowBtn = nullptr;
    QPushButton* trustBtn = nullptr;
    QPushButton* clearThreatBtn = nullptr;
    for (QPushButton* btn : win.findChildren<QPushButton*>()) {
        if (btn->text().contains("Allow / Remove BSSID")) {
            allowBtn = btn;
        } else if (btn->text().contains("ust BSSID")) {
            trustBtn = btn;
        } else if (btn->text().contains("Clear") && btn->text().contains("Threat")) {
            clearThreatBtn = btn;
        }
    }
    assert(allowBtn != nullptr && trustBtn != nullptr && clearThreatBtn != nullptr);
    allowBtn->click();
    trustBtn->click();
    QApplication::processEvents();
    assert(ctrl.authorization().isAllowed("02:aa:bb:cc:dd:01"));
    assert(zd::sec::isTrustedBssid(ctrl.secState(), "02:aa:bb:cc:dd:01"));
    assert(!ctrl.petState().lastThreatLabel.empty());
    assert(clearThreatBtn->isEnabled());
    clearThreatBtn->click();
    QApplication::processEvents();
    assert(ctrl.petState().lastThreatLabel.empty());

    // 4. PetWidget exposes SecMood in accessibleDescription.
    auto* pet = win.findChild<zd::linux_gui::PetWidget*>();
    assert(pet != nullptr);
    assert(pet->accessibleDescription().contains("ALARMED"));

    std::cout << "[linux-gui] Qt6 offscreen UI tests passed\n";
    return 0;
}
