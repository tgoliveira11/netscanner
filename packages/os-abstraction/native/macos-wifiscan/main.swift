import CoreWLAN
import Foundation

struct WifiApOut: Encodable {
  let ssid: String
  let bssid: String?
  let channel: Int?
  let rssi: Int?
  let security: String?
  let band: String?
  let channelWidthMhz: Int?
  let isConnected: Bool?
}

struct WifiScanOut: Encodable {
  let currentSsid: String?
  let currentBssid: String?
  let currentChannel: Int?
  let currentBand: String?
  let aps: [WifiApOut]
}

func bandLabel(_ channel: CWChannel?) -> String? {
  guard let channel else { return nil }
  switch channel.channelBand {
  case .band2GHz: return "2.4"
  case .band5GHz: return "5"
  case .band6GHz: return "6"
  @unknown default: return nil
  }
}

func channelWidthMhz(_ channel: CWChannel?) -> Int? {
  guard let channel else { return nil }
  switch channel.channelWidth {
  case .width20MHz: return 20
  case .width40MHz: return 40
  case .width80MHz: return 80
  case .width160MHz: return 160
  @unknown default: return nil
  }
}

func securityLabel(_ network: CWNetwork) -> String? {
  var parts: [String] = []
  if network.supportsSecurity(.wpa3Enterprise) { parts.append("wpa3 enterprise") }
  if network.supportsSecurity(.wpa3Personal) { parts.append("wpa3 personal") }
  if network.supportsSecurity(.wpa2Enterprise) { parts.append("wpa2 enterprise") }
  if network.supportsSecurity(.wpa2Personal) { parts.append("wpa2 personal") }
  if network.supportsSecurity(.wpaPersonal) { parts.append("wpa personal") }
  if network.supportsSecurity(.dynamicWEP) { parts.append("wep") }
  if network.supportsSecurity(.none), parts.isEmpty { parts.append("open") }
  return parts.isEmpty ? nil : parts.joined(separator: ", ")
}

func displaySsid(_ raw: String?, channel: Int?) -> String {
  let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
  if !trimmed.isEmpty { return trimmed }
  if let channel { return "(SSID hidden · ch \(channel))" }
  return "(SSID hidden)"
}

func normalizeBssid(_ raw: String?) -> String? {
  let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
  return trimmed.isEmpty ? nil : trimmed.lowercased()
}

guard let iface = CWWiFiClient.shared().interface() else {
  let empty = WifiScanOut(currentSsid: nil, currentBssid: nil, currentChannel: nil, currentBand: nil, aps: [])
  if let json = try? String(data: JSONEncoder().encode(empty), encoding: .utf8) { print(json) } else { print("{\"aps\":[]}") }
  exit(0)
}

let connectedSsidRaw = iface.ssid()?.trimmingCharacters(in: .whitespacesAndNewlines)
let connectedSsid = (connectedSsidRaw?.isEmpty == false) ? connectedSsidRaw : nil
let connectedBssid = normalizeBssid(iface.bssid())
let connectedChannel = iface.wlanChannel()?.channelNumber
let connectedBand = bandLabel(iface.wlanChannel())

do {
  let networks = try iface.scanForNetworks(withSSID: nil)
  var aps: [WifiApOut] = []
  for network in networks {
    let channel = network.wlanChannel?.channelNumber
    let bssidRaw = network.bssid?.trimmingCharacters(in: .whitespacesAndNewlines)
    let bssid = (bssidRaw?.isEmpty == false) ? bssidRaw : nil
    let isConnected: Bool? = {
      if let connectedBssid, let bssid, normalizeBssid(bssid) == connectedBssid { return true }
      if connectedBssid == nil, let connectedSsid, network.ssid == connectedSsid { return true }
      return nil
    }()
    aps.append(
      WifiApOut(
        ssid: displaySsid(network.ssid, channel: channel),
        bssid: bssid,
        channel: channel,
        rssi: network.rssiValue,
        security: securityLabel(network),
        band: bandLabel(network.wlanChannel),
        channelWidthMhz: channelWidthMhz(network.wlanChannel),
        isConnected: isConnected == true ? true : nil
      )
    )
  }
  let out = WifiScanOut(
    currentSsid: connectedSsid,
    currentBssid: connectedBssid,
    currentChannel: connectedChannel,
    currentBand: connectedBand,
    aps: aps
  )
  let data = try JSONEncoder().encode(out)
  if let json = String(data: data, encoding: .utf8) {
    print(json)
  } else {
    print("{\"aps\":[]}")
  }
} catch {
  fputs("CoreWLAN scan failed: \(error)\n", stderr)
  exit(1)
}
