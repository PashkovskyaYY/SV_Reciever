package soure;

import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
public class EthernetListener { //класс для прослушивания сырых пакетов
    
    static {

        try {
            for (PcapNetworkInterface nic : Pcaps.findAllDevs()) {
                log.info("Found NIC: {} ", nic); // получаем информацию о доступных сетевых картах
            }
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }
    }

     @Setter
    private String nicName;

    private PcapHandle handle; // при открытии сетевой карты в Java создается обработчик сетевых карт, который позволяет до нее достучаться. Класс из библиотеки pcap4j

    private final List<PacketListener> listeners = new CopyOnWriteArrayList<>();

    private final PacketListener defaultPacketListener = packet -> {
        //System.out.println(packet);
        listeners.forEach(listener -> listener.gotPacket(packet));
    };


    @SneakyThrows
    public void start(){ // метод приема пакетов из сетевой карты
        if(handle == null){
            initializeNetworkInterface(); // если обработчик пуст, вызывается метод инициализации

            if (handle != null){

                String filter = "ether proto 0x88ba && ether dst 01:0C:CD:04:00:01"; // хотим получать только SV-пакеты, с таким адресом назначения
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE); // Wireshark позволяет увидеть текущий трафик ЛВС. В основе приложения лежит бибилотека Pcap, кот. позволяет перехватывать трафик с сетевой карты

                Thread captureThread = new Thread(() -> { // перехват пакетов реализуется в отдельном потоке, т.к. основной поток занят приемом
                    try {
                        log.info("Starting packet capture");
                        handle.loop(0, defaultPacketListener); // закольцованность: поток перехвата данных
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

        if (nic.isPresent()){ // если сетевая карта найдена, открыть ее для работы
            handle = nic.get().openLive(1500, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);  // открываем карту для работы, задаем макс. размер пакетов, кот. хотим получать; PROMISCUOUS позволяет сетевой карте получать пакеты, кот. для нее не предназначены
            log.info("Network heandler created {}", nic);
        } else {
            log.error("Network interface is not found");
        }
        // 10 - время ожидания, мс
    }

    public void addListener(PacketListener listener){
        listeners.add(listener);
    }

}
