// VPN事業者と共有基盤のASNを識別する。VPN該当性は既知VPN表で独立して判定する。
// 参照: https://github.com/X4BNet/lists_vpn/blob/main/input/vpn/ASN.txt
// https://github.com/ipverse/as-metadata
package bootstrap

// vpnProviderPresets はVPN用途を含む事業者の候補。ASN全域をVPN扱いせず、ブランドも保証しない。
var vpnProviderPresets = []networkPreset{
	{"m247-as9009", "M247（AS9009・VPN共有基盤/用途混在）", "unknown", "M247", "0", 9009},
	{"packethub-as136787", "PacketHub / NordVPN系（AS136787・用途混在）", "unknown", "PacketHub", "0", 136787},
	{"packethub-as207137", "PacketHub / NordVPN系（AS207137・用途混在）", "unknown", "PacketHub", "0", 207137},
	{"cyberzone-as209854", "Cyberzone / Surfshark系（AS209854・用途混在）", "unknown", "Cyberzone", "0", 209854},
	{"proton-as208172", "Proton / Proton VPN系（AS208172・用途混在）", "unknown", "Proton", "0", 208172},
	{"mullvad-as216025", "Mullvad VPN（AS216025・用途未確定）", "unknown", "Mullvad", "0", 216025},
	{"checkpoint-as398391", "Check Point（AS398391・用途混在）", "unknown", "CheckPoint", "0", 398391},
}
