#pragma once

// Re-export the canonical portable 802.11 / radiotap decoder from `zd/dot11_decode.hpp`
// into `zd::linux_backend` so existing callers keep working without duplicating code.

#include "zd/dot11_decode.hpp"

namespace zd {
namespace linux_backend {

using zd::dot11::macToString;
using zd::dot11::RadiotapInfo;
using zd::dot11::parseRadiotap;
using zd::dot11::encryptionFromRsn;
using zd::dot11::pmfFromRsn;
using zd::dot11::parseTaggedParams;
using zd::dot11::eapolKeyPayloadOffset;
using zd::dot11::looksLikeEapol;
using zd::dot11::classifyEapolKeyMessage;
using zd::dot11::carriesPmkid;
using zd::dot11::decodeDot11;
using zd::dot11::decodeRadiotapFrame;

}  // namespace linux_backend
}  // namespace zd
