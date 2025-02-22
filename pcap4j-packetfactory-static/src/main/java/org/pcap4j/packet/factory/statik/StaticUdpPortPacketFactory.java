/*_##########################################################################
  _##
  _##  Copyright (C) 2013-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory.statik;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.UdpPort;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class StaticUdpPortPacketFactory extends AbstractStaticPacketFactory<UdpPort> {

  private static final StaticUdpPortPacketFactory INSTANCE = new StaticUdpPortPacketFactory();

  private StaticUdpPortPacketFactory() {
    instantiaters.put(
        UdpPort.GTP_C,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return GtpSelector.newPacket(rawData, offset, length);
          }

          @Override
          public Class<GtpSelector> getTargetClass() {
            return GtpSelector.class;
          }
        });
    instantiaters.put(
        UdpPort.GTP_U,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return GtpSelector.newPacket(rawData, offset, length);
          }

          @Override
          public Class<GtpSelector> getTargetClass() {
            return GtpSelector.class;
          }
        });
    instantiaters.put(
        UdpPort.GTP_PRIME,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return GtpSelector.newPacket(rawData, offset, length);
          }

          @Override
          public Class<GtpSelector> getTargetClass() {
            return GtpSelector.class;
          }
        });
    instantiaters.put(
        UdpPort.DOMAIN,
        new PacketInstantiater() {
          @Override
          public Packet newInstance(byte[] rawData, int offset, int length)
              throws IllegalRawDataException {
            return DnsPacket.newPacket(rawData, offset, length);
          }

          @Override
          public Class<DnsPacket> getTargetClass() {
            return DnsPacket.class;
          }
        });
    instantiaters.put(
      UdpPort.BOOTPS,
      new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData, int offset, int length)
          throws IllegalRawDataException {
          return DhcpV4Packet.newPacket(rawData, offset, length);
        }
        @Override
        public Class<DhcpV4Packet> getTargetClass() {
          return DhcpV4Packet.class;
        }
      });
    instantiaters.put(
      UdpPort.BOOTPC,
      new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData, int offset, int length)
          throws IllegalRawDataException {
          return DhcpV4Packet.newPacket(rawData, offset, length);
        }
        @Override
        public Class<DhcpV4Packet> getTargetClass() {
          return DhcpV4Packet.class;
        }
      });
    instantiaters.put(
      UdpPort.DHCPV6_CLIENT,
      new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData, int offset, int length)
          throws IllegalRawDataException {
          return DhcpV6Packet.newPacket(rawData, offset, length);
        }
        @Override
        public Class<DhcpV6Packet> getTargetClass() {
          return DhcpV6Packet.class;
        }
      });
    instantiaters.put(
      UdpPort.DHCPV6_SERVER,
      new PacketInstantiater() {
        @Override
        public Packet newInstance(byte[] rawData, int offset, int length)
          throws IllegalRawDataException {
          return DhcpV6Packet.newPacket(rawData, offset, length);
        }
        @Override
        public Class<DhcpV6Packet> getTargetClass() {
          return DhcpV6Packet.class;
        }
      });
  }

  /** @return the singleton instance of StaticUdpPortPacketFactory. */
  public static StaticUdpPortPacketFactory getInstance() {
    return INSTANCE;
  }
}
