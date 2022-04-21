package org.pcap4j.packet.namednumber;

import java.util.HashMap;
import java.util.Map;

public class DhcpV4Options extends NamedNumber<Byte, DhcpV4Options> {
  /** Subnet Mask: 1 */
  public static final DhcpV4Options Subnet_Mask = new DhcpV4Options((byte) 1, "Subnet Mask");

  /** Time Offset: 2 */
  public static final DhcpV4Options Time_Offset = new DhcpV4Options((byte) 2, "Time Offset");

  /** Router: 3 */
  public static final DhcpV4Options Router = new DhcpV4Options((byte) 3, "Router");

  /** Time Server: 4 */
  public static final DhcpV4Options Time_Server = new DhcpV4Options((byte) 4, "Time Server");

  /** Name Server: 5 */
  public static final DhcpV4Options Name_Server = new DhcpV4Options((byte) 5, "Name Server");

  /** Domain Server: 6 */
  public static final DhcpV4Options Domain_Server = new DhcpV4Options((byte) 6, "Domain Server");

  /** Log Server: 7 */
  public static final DhcpV4Options Log_Server = new DhcpV4Options((byte) 7, "Log Server");

  /** Quotes Server: 8 */
  public static final DhcpV4Options Quotes_Server = new DhcpV4Options((byte) 8, "Quotes Server");

  /** LPR Server: 9 */
  public static final DhcpV4Options LPR_Server = new DhcpV4Options((byte) 9, "LPR Server");

  /** Impress Server: 10 */
  public static final DhcpV4Options Impress_Server = new DhcpV4Options((byte) 10, "Impress Server");

  /** RLP Server: 11 */
  public static final DhcpV4Options RLP_Server = new DhcpV4Options((byte) 11, "RLP Server");

  /** Hostname: 12 */
  public static final DhcpV4Options Hostname = new DhcpV4Options((byte) 12, "Hostname");

  /** Boot File Size: 13 */
  public static final DhcpV4Options Boot_File_Size = new DhcpV4Options((byte) 13, "Boot File Size");

  /** Merit Dump File: 14 */
  public static final DhcpV4Options Merit_Dump_File = new DhcpV4Options((byte) 14, "Merit Dump File");

  /** Domain Name: 15 */
  public static final DhcpV4Options Domain_Name = new DhcpV4Options((byte) 15, "Domain Name");

  /** Swap Server: 16 */
  public static final DhcpV4Options Swap_Server = new DhcpV4Options((byte) 16, "Swap Server");

  /** Root Path: 17 */
  public static final DhcpV4Options Root_Path = new DhcpV4Options((byte) 17, "Root Path");

  /** Extension File: 18 */
  public static final DhcpV4Options Extension_File = new DhcpV4Options((byte) 18, "Extension File");

  /** Forward On/Off: 19 */
  public static final DhcpV4Options Forward_On_Off = new DhcpV4Options((byte) 19, "Forward On/Off");

  /** SrcRte On/Off: 20 */
  public static final DhcpV4Options SrcRte_On_Off = new DhcpV4Options((byte) 20, "SrcRte On/Off");

  /** Policy Filter: 21 */
  public static final DhcpV4Options Policy_Filter = new DhcpV4Options((byte) 21, "Policy Filter");

  /** Max DG Assembly: 22 */
  public static final DhcpV4Options Max_DG_Assembly = new DhcpV4Options((byte) 22, "Max DG Assembly");

  /** Default IP TTL: 23 */
  public static final DhcpV4Options Default_IP_TTL = new DhcpV4Options((byte) 23, "Default IP TTL");

  /** MTU Timeout: 24 */
  public static final DhcpV4Options MTU_Timeout = new DhcpV4Options((byte) 24, "MTU Timeout");

  /** MTU Plateau: 25 */
  public static final DhcpV4Options MTU_Plateau = new DhcpV4Options((byte) 25, "MTU Plateau");

  /** MTU Interface: 26 */
  public static final DhcpV4Options MTU_Interface = new DhcpV4Options((byte) 26, "MTU Interface");

  /** MTU Subnet: 27 */
  public static final DhcpV4Options MTU_Subnet = new DhcpV4Options((byte) 27, "MTU Subnet");

  /** Broadcast Address: 28 */
  public static final DhcpV4Options Broadcast_Address = new DhcpV4Options((byte) 28, "Broadcast Address");

  /** Mask Discovery: 29 */
  public static final DhcpV4Options Mask_Discovery = new DhcpV4Options((byte) 29, "Mask Discovery");

  /** Mask Supplier: 30 */
  public static final DhcpV4Options Mask_Supplier = new DhcpV4Options((byte) 30, "Mask Supplier");

  /** Router Discovery: 31 */
  public static final DhcpV4Options Router_Discovery = new DhcpV4Options((byte) 31, "Router Discovery");

  /** Router Request: 32 */
  public static final DhcpV4Options Router_Request = new DhcpV4Options((byte) 32, "Router Request");

  /** Static Route: 33 */
  public static final DhcpV4Options Static_Route = new DhcpV4Options((byte) 33, "Static Route");

  /** Trailers: 34 */
  public static final DhcpV4Options Trailers = new DhcpV4Options((byte) 34, "Trailers");

  /** ARP Timeout: 35 */
  public static final DhcpV4Options ARP_Timeout = new DhcpV4Options((byte) 35, "ARP Timeout");

  /** Ethernet: 36 */
  public static final DhcpV4Options Ethernet = new DhcpV4Options((byte) 36, "Ethernet");

  /** Default TCP TTL: 37 */
  public static final DhcpV4Options Default_TCP_TTL = new DhcpV4Options((byte) 37, "Default TCP TTL");

  /** Keepalive Time: 38 */
  public static final DhcpV4Options Keepalive_Time = new DhcpV4Options((byte) 38, "Keepalive Time");

  /** Keepalive Data: 39 */
  public static final DhcpV4Options Keepalive_Data = new DhcpV4Options((byte) 39, "Keepalive Data");

  /** NIS Domain: 40 */
  public static final DhcpV4Options NIS_Domain = new DhcpV4Options((byte) 40, "NIS Domain");

  /** NIS Servers: 41 */
  public static final DhcpV4Options NIS_Servers = new DhcpV4Options((byte) 41, "NIS Servers");

  /** NTP Servers: 42 */
  public static final DhcpV4Options NTP_Servers = new DhcpV4Options((byte) 42, "NTP Servers");

  /** Vendor Specific: 43 */
  public static final DhcpV4Options Vendor_Specific = new DhcpV4Options((byte) 43, "Vendor Specific");

  /** NETBIOS Name Srv: 44 */
  public static final DhcpV4Options NETBIOS_Name_Srv = new DhcpV4Options((byte) 44, "NETBIOS Name Srv");

  /** NETBIOS Dist Srv: 45 */
  public static final DhcpV4Options NETBIOS_Dist_Srv = new DhcpV4Options((byte) 45, "NETBIOS Dist Srv");

  /** NETBIOS Node Type: 46 */
  public static final DhcpV4Options NETBIOS_Node_Type = new DhcpV4Options((byte) 46, "NETBIOS Node Type");

  /** NETBIOS Scope: 47 */
  public static final DhcpV4Options NETBIOS_Scope = new DhcpV4Options((byte) 47, "NETBIOS Scope");

  /** X Window Font: 48 */
  public static final DhcpV4Options X_Window_Font = new DhcpV4Options((byte) 48, "X Window Font");

  /** X Window Manager: 49 */
  public static final DhcpV4Options X_Window_Manager = new DhcpV4Options((byte) 49, "X Window Manager");

  /** Address Request: 50 */
  public static final DhcpV4Options Address_Request = new DhcpV4Options((byte) 50, "Address Request");

  /** Address Time: 51 */
  public static final DhcpV4Options Address_Time = new DhcpV4Options((byte) 51, "Address Time");

  /** Overload: 52 */
  public static final DhcpV4Options Overload = new DhcpV4Options((byte) 52, "Overload");

  /** DHCP Msg Type: 53 */
  public static final DhcpV4Options DHCP_Msg_Type = new DhcpV4Options((byte) 53, "DHCP Msg Type");

  /** DHCP Server Id: 54 */
  public static final DhcpV4Options DHCP_Server_Id = new DhcpV4Options((byte) 54, "DHCP Server Id");

  /** Parameter List: 55 */
  public static final DhcpV4Options Parameter_List = new DhcpV4Options((byte) 55, "Parameter List");

  /** DHCP Message: 56 */
  public static final DhcpV4Options DHCP_Message = new DhcpV4Options((byte) 56, "DHCP Message");

  /** DHCP Max Msg Size: 57 */
  public static final DhcpV4Options DHCP_Max_Msg_Size = new DhcpV4Options((byte) 57, "DHCP Max Msg Size");

  /** Renewal Time: 58 */
  public static final DhcpV4Options Renewal_Time = new DhcpV4Options((byte) 58, "Renewal Time");

  /** Rebinding Time: 59 */
  public static final DhcpV4Options Rebinding_Time = new DhcpV4Options((byte) 59, "Rebinding Time");

  /** Class Id: 60 */
  public static final DhcpV4Options Class_Id = new DhcpV4Options((byte) 60, "Class Id");

  /** Client Id: 61 */
  public static final DhcpV4Options Client_Id = new DhcpV4Options((byte) 61, "Client Id");

  /** NetWare/IP Domain: 62 */
  public static final DhcpV4Options NetWare_IP_Domain = new DhcpV4Options((byte) 62, "NetWare/IP Domain");

  /** NetWare/IP Option: 63 */
  public static final DhcpV4Options NetWare_IP_Option = new DhcpV4Options((byte) 63, "NetWare/IP Option");

  /** NIS-Domain-Name: 64 */
  public static final DhcpV4Options NIS_Domain_Name = new DhcpV4Options((byte) 64, "NIS-Domain-Name");

  /** NIS-Server-Addr: 65 */
  public static final DhcpV4Options NIS_Server_Addr = new DhcpV4Options((byte) 65, "NIS-Server-Addr");

  /** Server-Name: 66 */
  public static final DhcpV4Options Server_Name = new DhcpV4Options((byte) 66, "Server-Name");

  /** Bootfile-Name: 67 */
  public static final DhcpV4Options Bootfile_Name = new DhcpV4Options((byte) 67, "Bootfile-Name");

  /** Home-Agent-Addrs: 68 */
  public static final DhcpV4Options Home_Agent_Addrs = new DhcpV4Options((byte) 68, "Home-Agent-Addrs");

  /** SMTP-Server: 69 */
  public static final DhcpV4Options SMTP_Server = new DhcpV4Options((byte) 69, "SMTP-Server");

  /** POP3-Server: 70 */
  public static final DhcpV4Options POP3_Server = new DhcpV4Options((byte) 70, "POP3-Server");

  /** NNTP-Server: 71 */
  public static final DhcpV4Options NNTP_Server = new DhcpV4Options((byte) 71, "NNTP-Server");

  /** WWW-Server: 72 */
  public static final DhcpV4Options WWW_Server = new DhcpV4Options((byte) 72, "WWW-Server");

  /** Finger-Server: 73 */
  public static final DhcpV4Options Finger_Server = new DhcpV4Options((byte) 73, "Finger-Server");

  /** IRC-Server: 74 */
  public static final DhcpV4Options IRC_Server = new DhcpV4Options((byte) 74, "IRC-Server");

  /** StreetTalk-Server: 75 */
  public static final DhcpV4Options StreetTalk_Server = new DhcpV4Options((byte) 75, "StreetTalk-Server");

  /** STDA-Server: 76 */
  public static final DhcpV4Options STDA_Server = new DhcpV4Options((byte) 76, "STDA-Server");

  /** User-Class: 77 */
  public static final DhcpV4Options User_Class = new DhcpV4Options((byte) 77, "User-Class");

  /** Directory Agent: 78 */
  public static final DhcpV4Options Directory_Agent = new DhcpV4Options((byte) 78, "Directory Agent");

  /** Service Scope: 79 */
  public static final DhcpV4Options option79 = new DhcpV4Options((byte) 79, "Service Scope");

  /** Rapid Commit: 80 */
  public static final DhcpV4Options option80 = new DhcpV4Options((byte) 80, "Rapid Commit");

  /** Client FQDN: 81 */
  public static final DhcpV4Options option81 = new DhcpV4Options((byte) 81, "Client FQDN");

  /** Relay Agent Information: 82 */
  public static final DhcpV4Options option82 = new DhcpV4Options((byte) 82, "Relay Agent Information");

  /** iSNS: 83 */
  public static final DhcpV4Options option83 = new DhcpV4Options((byte) 83, "iSNS");

  /** NDS Servers: 85 */
  public static final DhcpV4Options option85 = new DhcpV4Options((byte) 85, "NDS Servers");

  /** NDS Tree Name: 86 */
  public static final DhcpV4Options option86 = new DhcpV4Options((byte) 86, "NDS Tree Name");

  /** NDS Context: 87 */
  public static final DhcpV4Options option87 = new DhcpV4Options((byte) 87, "NDS Context");

  /** BCMCS Controller Domain Name list: 88 */
  public static final DhcpV4Options option88 = new DhcpV4Options((byte) 88, "BCMCS Controller Domain Name list");

  /** BCMCS Controller IPv4 address option: 89 */
  public static final DhcpV4Options option89 = new DhcpV4Options((byte) 89, "BCMCS Controller IPv4 address option");

  /** Authentication: 90 */
  public static final DhcpV4Options option90 = new DhcpV4Options((byte) 90, "Authentication");

  /** client-last-transaction-time option: 91 */
  public static final DhcpV4Options option91 = new DhcpV4Options((byte) 91, "client-last-transaction-time option");

  /** associated-ip option: 92 */
  public static final DhcpV4Options option92 = new DhcpV4Options((byte) 92, "associated-ip option");

  /** Client System: 93 */
  public static final DhcpV4Options option93 = new DhcpV4Options((byte) 93, "Client System");

  /** Client NDI: 94 */
  public static final DhcpV4Options option94 = new DhcpV4Options((byte) 94, "Client NDI");

  /** LDAP: 95 */
  public static final DhcpV4Options option95 = new DhcpV4Options((byte) 95, "LDAP");

  /** UUID/GUID: 97 */
  public static final DhcpV4Options option97 = new DhcpV4Options((byte) 97, "UUID/GUID");

  /** User-Auth: 98 */
  public static final DhcpV4Options option98 = new DhcpV4Options((byte) 98, "User-Auth");

  /** GEOCONF_CIVIC: 99 */
  public static final DhcpV4Options option99 = new DhcpV4Options((byte) 99, "GEOCONF_CIVIC");

  /** PCode: 100 */
  public static final DhcpV4Options option100 = new DhcpV4Options((byte) 100, "PCode");

  /** TCode: 101 */
  public static final DhcpV4Options option101 = new DhcpV4Options((byte) 101, "TCode");

  /** IPv6-Only Preferred: 108 */
  public static final DhcpV4Options option108 = new DhcpV4Options((byte) 108, "IPv6-Only Preferred");

  /** OPTION_DHCP4O6_S46_SADDR: 109 */
  public static final DhcpV4Options option109 = new DhcpV4Options((byte) 109, "OPTION_DHCP4O6_S46_SADDR");

  /** Netinfo Address: 112 */
  public static final DhcpV4Options option112 = new DhcpV4Options((byte) 112, "Netinfo Address");

  /** Netinfo Tag: 113 */
  public static final DhcpV4Options option113 = new DhcpV4Options((byte) 113, "Netinfo Tag");

  /** DHCP Captive-Portal: 114 */
  public static final DhcpV4Options option114 = new DhcpV4Options((byte) 114, "DHCP Captive-Portal");

  /** Auto-Config: 116 */
  public static final DhcpV4Options option116 = new DhcpV4Options((byte) 116, "Auto-Config");

  /** Name Service Search: 117 */
  public static final DhcpV4Options option117 = new DhcpV4Options((byte) 117, "Name Service Search");

  /** Subnet Selection Option: 118 */
  public static final DhcpV4Options option118 = new DhcpV4Options((byte) 118, "Subnet Selection Option");

  /** Domain Search: 119 */
  public static final DhcpV4Options option119 = new DhcpV4Options((byte) 119, "Domain Search");

  /** SIP Servers DHCP Option: 120 */
  public static final DhcpV4Options option120 = new DhcpV4Options((byte) 120, "SIP Servers DHCP Option");

  /** Classless Static Route Option: 121 */
  public static final DhcpV4Options option121 = new DhcpV4Options((byte) 121, "Classless Static Route Option");

  /** CCC: 122 */
  public static final DhcpV4Options option122 = new DhcpV4Options((byte) 122, "CCC");

  /** GeoConf Option: 123 */
  public static final DhcpV4Options option123 = new DhcpV4Options((byte) 123, "GeoConf Option");

  /** V-I Vendor Class: 124 */
  public static final DhcpV4Options option124 = new DhcpV4Options((byte) 124, "V-I Vendor Class");

  /** V-I Vendor-Specific Information: 125 */
  public static final DhcpV4Options option125 = new DhcpV4Options((byte) 125, "V-I Vendor-Specific Information");

  /** PXE - ETHERBOOT - FULL SECURITY - TFTP SERVER IP: 128 */
  public static final DhcpV4Options option128 = new DhcpV4Options((byte) 128, "Multiple options");

  /** PXE - Kernel options - Call Server IP address: 129 */
  public static final DhcpV4Options option129 = new DhcpV4Options((byte) 129, "Multiple options");

  /** PXE - Ethernet interface: 130 */
  public static final DhcpV4Options option130 = new DhcpV4Options((byte) 130, "Multiple options");

  /** PXE - Remote statistics server IP: 131 */
  public static final DhcpV4Options option131 = new DhcpV4Options((byte) 131, "Multiple options");

  /** PXE - IEEE 802.1Q VLAN ID: 132 */
  public static final DhcpV4Options option132 = new DhcpV4Options((byte) 132, "Multiple options");

  /** PXE - IEEE 802.1D/p Layer 2 Priority: 133 */
  public static final DhcpV4Options option133 = new DhcpV4Options((byte) 133, "Multiple options");

  /** PXE - Diffserv Code Point (DSCP) for VoIP: 134 */
  public static final DhcpV4Options option134 = new DhcpV4Options((byte) 134, "Multiple options");

  /** PXE- HTTP Proxy for phone-specific applications: 135 */
  public static final DhcpV4Options option135 = new DhcpV4Options((byte) 135, "Multiple options");

  /** OPTION_PANA_AGENT: 136 */
  public static final DhcpV4Options option136 = new DhcpV4Options((byte) 136, "OPTION_PANA_AGENT");

  /** OPTION_V4_LOST: 137 */
  public static final DhcpV4Options option137 = new DhcpV4Options((byte) 137, "OPTION_V4_LOST");

  /** OPTION_CAPWAP_AC_V4: 138 */
  public static final DhcpV4Options option138 = new DhcpV4Options((byte) 138, "OPTION_CAPWAP_AC_V4");

  /** OPTION-IPv4_Address-MoS: 139 */
  public static final DhcpV4Options option139 = new DhcpV4Options((byte) 139, "OPTION-IPv4_Address-MoS");

  /** OPTION-IPv4_FQDN-MoS: 140 */
  public static final DhcpV4Options option140 = new DhcpV4Options((byte) 140, "OPTION-IPv4_FQDN-MoS");

  /** SIP UA Configuration Service Domains: 141 */
  public static final DhcpV4Options option141 = new DhcpV4Options((byte) 141, "SIP UA Configuration Service Domains");

  /** OPTION-IPv4_Address-ANDSF: 142 */
  public static final DhcpV4Options option142 = new DhcpV4Options((byte) 142, "OPTION-IPv4_Address-ANDSF");

  /** OPTION_V4_SZTP_REDIRECT: 143 */
  public static final DhcpV4Options option143 = new DhcpV4Options((byte) 143, "OPTION_V4_SZTP_REDIRECT");

  /** GeoLoc: 144 */
  public static final DhcpV4Options option144 = new DhcpV4Options((byte) 144, "GeoLoc");

  /** FORCERENEW_NONCE_CAPABLE: 145 */
  public static final DhcpV4Options option145 = new DhcpV4Options((byte) 145, "FORCERENEW_NONCE_CAPABLE");

  /** RDNSS Selection: 146 */
  public static final DhcpV4Options option146 = new DhcpV4Options((byte) 146, "RDNSS Selection");

  /** OPTION_V4_DOTS_RI: 147 */
  public static final DhcpV4Options option147 = new DhcpV4Options((byte) 147, "OPTION_V4_DOTS_RI");

  /** OPTION_V4_DOTS_ADDRESS: 148 */
  public static final DhcpV4Options option148 = new DhcpV4Options((byte) 148, "OPTION_V4_DOTS_ADDRESS");

  /** TFTP server address - Etherboot - GRUB configuration path name: 150 */
  public static final DhcpV4Options option150 = new DhcpV4Options((byte) 150, "Multiple options");

  /** status-code: 151 */
  public static final DhcpV4Options option151 = new DhcpV4Options((byte) 151, "status-code");

  /** base-time: 152 */
  public static final DhcpV4Options option152 = new DhcpV4Options((byte) 152, "base-time");

  /** start-time-of-state: 153 */
  public static final DhcpV4Options option153 = new DhcpV4Options((byte) 153, "start-time-of-state");

  /** query-start-time: 154 */
  public static final DhcpV4Options option154 = new DhcpV4Options((byte) 154, "query-start-time");

  /** query-end-time: 155 */
  public static final DhcpV4Options option155 = new DhcpV4Options((byte) 155, "query-end-time");

  /** dhcp-state: 156 */
  public static final DhcpV4Options option156 = new DhcpV4Options((byte) 156, "dhcp-state");

  /** data-source: 157 */
  public static final DhcpV4Options option157 = new DhcpV4Options((byte) 157, "data-source");

  /** OPTION_V4_PCP_SERVER: 158 */
  public static final DhcpV4Options option158 = new DhcpV4Options((byte) 158, "OPTION_V4_PCP_SERVER");

  /** OPTION_V4_PORTPARAMS: 159 */
  public static final DhcpV4Options option159 = new DhcpV4Options((byte) 159, "OPTION_V4_PORTPARAMS");

  /** OPTION_MUD_URL_V4: 161 */
  public static final DhcpV4Options option161 = new DhcpV4Options((byte) 161, "OPTION_MUD_URL_V4");

  /** Etherboot (Tentatively Assigned - 2005-06-23): 175 */
  public static final DhcpV4Options option175 = new DhcpV4Options((byte) 175, "Etherboot (Tentatively Assigned - 2005-06-23)");

  /** IP Telephone (Tentatively Assigned - 2005-06-23): 176 */
  public static final DhcpV4Options option176 = new DhcpV4Options((byte) 176, "IP Telephone (Tentatively Assigned - 2005-06-23)");

  /** Etherboot (Tentatively Assigned - 2005-06-23) - PacketCable and CableHome: 177 */
  public static final DhcpV4Options option177 = new DhcpV4Options((byte) 177, "Multiple Options");

  /** PXELINUX Magic: 208 */
  public static final DhcpV4Options option208 = new DhcpV4Options((byte) 208, "PXELINUX Magic");

  /** Configuration File: 209 */
  public static final DhcpV4Options option209 = new DhcpV4Options((byte) 209, "Configuration File");

  /** Path Prefix: 210 */
  public static final DhcpV4Options option210 = new DhcpV4Options((byte) 210, "Path Prefix");

  /** Reboot Time: 211 */
  public static final DhcpV4Options option211 = new DhcpV4Options((byte) 211, "Reboot Time");

  /** OPTION_6RD: 212 */
  public static final DhcpV4Options option212 = new DhcpV4Options((byte) 212, "OPTION_6RD");

  /** OPTION_V4_ACCESS_DOMAIN: 213 */
  public static final DhcpV4Options option213 = new DhcpV4Options((byte) 213, "OPTION_V4_ACCESS_DOMAIN");

  /** Subnet Allocation Option: 220 */
  public static final DhcpV4Options option220 = new DhcpV4Options((byte) 220, "Subnet Allocation Option");

  /** Virtual Subnet Selection (VSS) Option: 221 */
  public static final DhcpV4Options option221 = new DhcpV4Options((byte) 221, "Virtual Subnet Selection (VSS) Option");

  /** End: 255 */
  public static final DhcpV4Options END = new DhcpV4Options((byte) 255, "End");

  private static final Map<Byte, DhcpV4Options> registry = new HashMap<Byte, DhcpV4Options>(30);

  static{
    registry.put(Subnet_Mask.value(), Subnet_Mask);
    registry.put(Time_Offset.value(), Time_Offset);
    registry.put(Router.value(), Router);
    registry.put(Time_Server.value(), Time_Server);
    registry.put(Name_Server.value(), Name_Server);
    registry.put(Domain_Server.value(), Domain_Server);
    registry.put(Log_Server.value(), Log_Server);
    registry.put(Quotes_Server.value(), Quotes_Server);
    registry.put(LPR_Server.value(), LPR_Server);
    registry.put(Impress_Server.value(), Impress_Server);
    registry.put(RLP_Server.value(), RLP_Server);
    registry.put(Hostname.value(), Hostname);
    registry.put(Boot_File_Size.value(), Boot_File_Size);
    registry.put(Merit_Dump_File.value(), Merit_Dump_File);
    registry.put(Domain_Name.value(), Domain_Name);
    registry.put(Swap_Server.value(), Swap_Server);
    registry.put(Root_Path.value(), Root_Path);
    registry.put(Extension_File.value(), Extension_File);
    registry.put(Forward_On_Off.value(), Forward_On_Off);
    registry.put(SrcRte_On_Off.value(), SrcRte_On_Off);
    registry.put(Policy_Filter.value(), Policy_Filter);
    registry.put(Max_DG_Assembly.value(), Max_DG_Assembly);
    registry.put(Default_IP_TTL.value(), Default_IP_TTL);
    registry.put(MTU_Timeout.value(), MTU_Timeout);
    registry.put(MTU_Plateau.value(), MTU_Plateau);
    registry.put(MTU_Interface.value(), MTU_Interface);
    registry.put(MTU_Subnet.value(), MTU_Subnet);
    registry.put(Broadcast_Address.value(), Broadcast_Address);
    registry.put(Mask_Discovery.value(), Mask_Discovery);
    registry.put(Mask_Supplier.value(), Mask_Supplier);
    registry.put(Router_Discovery.value(), Router_Discovery);
    registry.put(Router_Request.value(), Router_Request);
    registry.put(Static_Route.value(), Static_Route);
    registry.put(Trailers.value(), Trailers);
    registry.put(ARP_Timeout.value(), ARP_Timeout);
    registry.put(Ethernet.value(), Ethernet);
    registry.put(Default_TCP_TTL.value(), Default_TCP_TTL);
    registry.put(Keepalive_Time.value(), Keepalive_Time);
    registry.put(Keepalive_Data.value(), Keepalive_Data);
    registry.put(NIS_Domain.value(), NIS_Domain);
    registry.put(NIS_Servers.value(), NIS_Servers);
    registry.put(NTP_Servers.value(), NTP_Servers);
    registry.put(Vendor_Specific.value(), Vendor_Specific);
    registry.put(NETBIOS_Name_Srv.value(), NETBIOS_Name_Srv);
    registry.put(NETBIOS_Dist_Srv.value(), NETBIOS_Dist_Srv);
    registry.put(NETBIOS_Node_Type.value(), NETBIOS_Node_Type);
    registry.put(NETBIOS_Scope.value(), NETBIOS_Scope);
    registry.put(X_Window_Font.value(), X_Window_Font);
    registry.put(X_Window_Manager.value(), X_Window_Manager);
    registry.put(Address_Request.value(), Address_Request);
    registry.put(Address_Time.value(), Address_Time);
    registry.put(Overload.value(), Overload);
    registry.put(DHCP_Msg_Type.value(), DHCP_Msg_Type);
    registry.put(DHCP_Server_Id.value(), DHCP_Server_Id);
    registry.put(Parameter_List.value(), Parameter_List);
    registry.put(DHCP_Message.value(), DHCP_Message);
    registry.put(DHCP_Max_Msg_Size.value(), DHCP_Max_Msg_Size);
    registry.put(Renewal_Time.value(), Renewal_Time);
    registry.put(Rebinding_Time.value(), Rebinding_Time);
    registry.put(Class_Id.value(), Class_Id);
    registry.put(Client_Id.value(), Client_Id);
    registry.put(NetWare_IP_Domain.value(), NetWare_IP_Domain);
    registry.put(NetWare_IP_Option.value(), NetWare_IP_Option);
    registry.put(NIS_Domain_Name.value(), NIS_Domain_Name);
    registry.put(NIS_Server_Addr.value(), NIS_Server_Addr);
    registry.put(Server_Name.value(), Server_Name);
    registry.put(Bootfile_Name.value(), Bootfile_Name);
    registry.put(Home_Agent_Addrs.value(), Home_Agent_Addrs);
    registry.put(SMTP_Server.value(), SMTP_Server);
    registry.put(POP3_Server.value(), POP3_Server);
    registry.put(NNTP_Server.value(), NNTP_Server);
    registry.put(WWW_Server.value(), WWW_Server);
    registry.put(Finger_Server.value(), Finger_Server);
    registry.put(IRC_Server.value(), IRC_Server);
    registry.put(StreetTalk_Server.value(), StreetTalk_Server);
    registry.put(STDA_Server.value(), STDA_Server);
    registry.put(User_Class.value(), User_Class);
    registry.put(Directory_Agent.value(), Directory_Agent);
    registry.put(option79.value(), option79);
    registry.put(option80.value(), option80);
    registry.put(option81.value(), option81);
    registry.put(option82.value(), option82);
    registry.put(option83.value(), option83);
    registry.put(option85.value(), option85);
    registry.put(option86.value(), option86);
    registry.put(option87.value(), option87);
    registry.put(option88.value(), option88);
    registry.put(option89.value(), option89);
    registry.put(option90.value(), option90);
    registry.put(option91.value(), option91);
    registry.put(option92.value(), option92);
    registry.put(option93.value(), option93);
    registry.put(option94.value(), option94);
    registry.put(option95.value(), option95);
    registry.put(option97.value(), option97);
    registry.put(option98.value(), option98);
    registry.put(option99.value(), option99);
    registry.put(option100.value(), option100);
    registry.put(option101.value(), option101);
    registry.put(option108.value(), option108);
    registry.put(option109.value(), option109);
    registry.put(option112.value(), option112);
    registry.put(option113.value(), option113);
    registry.put(option114.value(), option114);
    registry.put(option116.value(), option116);
    registry.put(option117.value(), option117);
    registry.put(option118.value(), option118);
    registry.put(option119.value(), option119);
    registry.put(option120.value(), option120);
    registry.put(option121.value(), option121);
    registry.put(option122.value(), option122);
    registry.put(option123.value(), option123);
    registry.put(option124.value(), option124);
    registry.put(option125.value(), option125);
    registry.put(option128.value(), option128);
    registry.put(option129.value(), option129);
    registry.put(option130.value(), option130);
    registry.put(option131.value(), option131);
    registry.put(option132.value(), option132);
    registry.put(option133.value(), option133);
    registry.put(option134.value(), option134);
    registry.put(option135.value(), option135);
    registry.put(option136.value(), option136);
    registry.put(option137.value(), option137);
    registry.put(option138.value(), option138);
    registry.put(option139.value(), option139);
    registry.put(option140.value(), option140);
    registry.put(option141.value(), option141);
    registry.put(option142.value(), option142);
    registry.put(option143.value(), option143);
    registry.put(option144.value(), option144);
    registry.put(option145.value(), option145);
    registry.put(option146.value(), option146);
    registry.put(option147.value(), option147);
    registry.put(option148.value(), option148);
    registry.put(option150.value(), option150);
    registry.put(option151.value(), option151);
    registry.put(option152.value(), option152);
    registry.put(option153.value(), option153);
    registry.put(option154.value(), option154);
    registry.put(option155.value(), option155);
    registry.put(option156.value(), option156);
    registry.put(option157.value(), option157);
    registry.put(option158.value(), option158);
    registry.put(option159.value(), option159);
    registry.put(option161.value(), option161);
    registry.put(option175.value(), option175);
    registry.put(option176.value(), option176);
    registry.put(option177.value(), option177);
    registry.put(option208.value(), option208);
    registry.put(option209.value(), option209);
    registry.put(option210.value(), option210);
    registry.put(option211.value(), option211);
    registry.put(option212.value(), option212);
    registry.put(option213.value(), option213);
    registry.put(option220.value(), option220);
    registry.put(option221.value(), option221);
    registry.put(END.value(), END);
  }

  public DhcpV4Options(Byte value, String name) {
    super(value, name);
  }

  public static DhcpV4Options getInstance(Byte value) {
    if (registry.containsKey(value)) {
      return registry.get(value);
    } else {
      return new DhcpV4Options(value, "unknown");
    }
  }

  public static DhcpV4Options register(DhcpV4Options options) {
    return registry.put(options.value(), options);
  }

  @Override
  public String valueAsString() {
    return String.valueOf(value() & 0xFFFF);
  }

  @Override
  public int compareTo(DhcpV4Options o) {
    return value().compareTo(o.value());
  }
}
