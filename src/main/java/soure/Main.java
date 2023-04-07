package soure;

import java.util.Optional;

public class Main {

    public static void main(String[] args) {

        EthernetListener ethernetListener = new EthernetListener();
        ethernetListener.setNicName("VMware Virtual Ethernet Adapter");

        SvDecoder svDecoder = new SvDecoder();

        ethernetListener.addListener(packet -> {
            Optional<SvPacket> svPacket = svDecoder.decode(packet);
            if (svPacket.isPresent()){
                 System.out.println(svPacket.toString());
            }
        });
        ethernetListener.start();

    }
}
