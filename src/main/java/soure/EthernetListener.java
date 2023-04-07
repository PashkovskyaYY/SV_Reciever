package soure;

import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
public class EthernetListener { //����� ��� ������������� ����� �������
    
    static {

        try {
            for (PcapNetworkInterface nic : Pcaps.findAllDevs()) {
                log.info("Found NIC: {} ", nic); // �������� ���������� � ��������� ������� ������
            }
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }
    }

     @Setter
    private String nicName;

    private PcapHandle handle; // ��� �������� ������� ����� � Java ��������� ���������� ������� ����, ������� ��������� �� ��� �����������. ����� �� ���������� pcap4j

    private final List<PacketListener> listeners = new CopyOnWriteArrayList<>();

    private final PacketListener defaultPacketListener = packet -> {
        //System.out.println(packet);
        listeners.forEach(listener -> listener.gotPacket(packet));
    };


    @SneakyThrows
    public void start(){ // ����� ������ ������� �� ������� �����
        if(handle == null){
            initializeNetworkInterface(); // ���� ���������� ����, ���������� ����� �������������

            if (handle != null){

                String filter = "ether proto 0x88ba && ether dst 01:0C:CD:04:00:01"; // ����� �������� ������ SV-������, � ����� ������� ����������
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE); // Wireshark ��������� ������� ������� ������ ���. � ������ ���������� ����� ���������� Pcap, ���. ��������� ������������� ������ � ������� �����

                Thread captureThread = new Thread(() -> { // �������� ������� ����������� � ��������� ������, �.�. �������� ����� ����� �������
                    try {
                        log.info("Starting packet capture");
                        handle.loop(0, defaultPacketListener); // ����������������: ����� ��������� ������
                    } catch (PcapNativeException e) {
                        throw new RuntimeException(e);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    } catch (NotOpenException e) {
                        throw new RuntimeException(e);
                    }
                    log.info("Packet capture finished");
                });
                captureThread.start();
            }
        }
    }

    @SneakyThrows
    private void initializeNetworkInterface() {
        Optional<PcapNetworkInterface> nic = Pcaps.findAllDevs().stream()
                .filter(i -> nicName.equals(i.getDescription()))
                .findFirst();

        if (nic.isPresent()){ // ���� ������� ����� �������, ������� �� ��� ������
            handle = nic.get().openLive(1500, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);  // ��������� ����� ��� ������, ������ ����. ������ �������, ���. ����� ��������; PROMISCUOUS ��������� ������� ����� �������� ������, ���. ��� ��� �� �������������
            log.info("Network heandler created {}", nic);
        } else {
            log.error("Network interface is not found");
        }
        // 10 - ����� ��������, ��
    }

    public void addListener(PacketListener listener){
        listeners.add(listener);
    }

}
