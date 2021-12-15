package org.pcap4j.sample;

import com.sun.jna.Platform;
import java.io.IOException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class Dissector {

    // VARIABLES
    private static final String COUNT_KEY = Loop.class.getName() + ".count";
    private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

    private static final String READ_TIMEOUT_KEY = Loop.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

    private static final String SNAPLEN_KEY = Loop.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

    private Dissector() {}

    public static void main(String[] args) throws PcapNativeException, NotOpenException {

        String filter = args.length != 0 ? args[0] : "";

//        System.out.println(COUNT_KEY + ": " + COUNT);
//        System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
//        System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
//        System.out.println("\n");

        // CHOOSE INTERFACE
        PcapNetworkInterface nif;
        try {
            nif = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        if (nif == null) {
            return;
        }

        // Writes the interface name and description
        System.out.println(nif.getName() + " (" + nif.getDescription() + ")");

        final PcapHandle handle = nif.openLive(SNAPLEN, PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        if (filter.length() != 0) {
            handle.setFilter(filter, BpfCompileMode.OPTIMIZE);
        }

        PacketListener listener = packet -> System.out.println("Packet: " + packet);

        try {

            handle.loop(COUNT, listener);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        PcapStat ps = handle.getStats();
        System.out.println("ps_recieved: " + ps.getNumPacketsReceived());
        System.out.println("ps_dropped: " + ps.getNumPacketsDropped());
        System.out.println("ps_ifdropped: " + ps.getNumPacketsDroppedByIf());
        if (Platform.isWindows()) {
            System.out.println("bs_captured: " + ps.getNumPacketsCaptured());
        }

        handle.close();
    }
}
