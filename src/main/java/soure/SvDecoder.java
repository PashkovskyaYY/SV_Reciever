package soure;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapPacket;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Slf4j
public class SvDecoder { // преобразование данных типа PcapPacket в данные типа SvPacket, т.е. парсинг

    private static final int datasetSize = 64; // 64 байта - длина измерений

    public Optional<SvPacket> decode(PcapPacket packet){ // обертка над данными, которую будем выдавать. Нужна, чтобы не получать NullPointerException

        try {
            byte[] data = packet.getRawData(); // массив байт Hex stream
            int length = data.length; // 122 байта

            SvPacket result = new SvPacket();

            result.setMacDst(byteArrayToMac(data, 0)); // парсинг мак-адреса получателя
            result.setMacSrc(byteArrayToMac(data, 6)); // парсинг мак-адреса отправителя


            result.setAppID(Short.parseShort(Integer.toHexString(byteArrayToInt2(data, 14)))); // парсинг идентификатора приложения
            result.setSvID(byteArrayToString(data, 34)); // парсинг идентификатора SV-потока
            result.setSmpCount(byteArrayToInt2(data, 45)); // парсинг номера SV-потока
            result.setConfRef(byteArrayToInt(data, 49)); // парсинг номера ревизии
            result.setSmpSynch(byteArrayToInt1(data, 55)); // парсинг информации о синхронизации по времени


            result.getDataSet().setInstIa((byteArrayToInt(data, length - datasetSize)) / 100.0); // парсинг Ia
            result.getDataSet().setQIa(byteArrayToInt(data, length - datasetSize + 4)); // парсинг qIa
            result.getDataSet().setInstIb((byteArrayToInt(data, length - datasetSize + 8)) / 100.0); // парсинг Ib
            result.getDataSet().setQIb(byteArrayToInt(data, length - datasetSize + 12)); // парсинг qIb
            result.getDataSet().setInstIc((byteArrayToInt(data, length - datasetSize + 16)) / 100.0); // парсинг Ic
            result.getDataSet().setQIc(byteArrayToInt(data, length - datasetSize + 20)); // парсинг qIc
            result.getDataSet().setInstIn((byteArrayToInt(data, length - datasetSize + 24)) / 100.0); // парсинг In
            result.getDataSet().setQIn(byteArrayToInt(data, length - datasetSize + 28)); // парсинг qIn

            result.getDataSet().setInstUa((byteArrayToInt(data, length - datasetSize + 32)) / 100.0); // парсинг Ua
            result.getDataSet().setQUa(byteArrayToInt(data, length - datasetSize + 36)); // парсинг qUa
            result.getDataSet().setInstUb((byteArrayToInt(data, length - datasetSize + 40)) / 100.0); // парсинг Ub
            result.getDataSet().setQUb(byteArrayToInt(data, length - datasetSize + 44)); // парсинг qUb
            result.getDataSet().setInstUc((byteArrayToInt(data, length - datasetSize + 48)) / 100.0); // парсинг Uc
            result.getDataSet().setQUc(byteArrayToInt(data, length - datasetSize + 52)); // парсинг qUc
            result.getDataSet().setInstUn((byteArrayToInt(data, length - datasetSize + 56)) / 100.0); // парсинг Un
            result.getDataSet().setQUn(byteArrayToInt(data, length - datasetSize + 60)); // парсинг qUn


            return Optional.of(result);
        } catch (Exception e){log.error("Cannot parse sv packet");}

        return Optional.empty(); // пустой объект Optional
    }

    public static String byteArrayToMac(byte[] b, int offset){// вытянем мак-адреса из массива байт data, offset - смещение от начала, откуда берутся данные
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x", // приведение строки к нужному формату. Здесь преобразование байта в шестнадцатиричное отображение
                b[offset],
                b[1 + offset],
                b[2 + offset],
                b[3 + offset],
                b[4 + offset],
                b[5 + offset]
        );
    }

    public static int byteArrayToInt(byte[] b, int offset){ // метод парсинга измеренных значений SV-потока
        return b[offset + 3] & 0xFF | (b[offset + 2] & 0xFF) << 8 | (b[offset + 1] & 0xFF) << 16 | (b[offset] & 0xFF) << 24; // битовые операции. Напр, b[0] & 0xFF нулевой байт * FF чтобы отбросить лишние символы числа
    }// << 24 - сдвиг на 24 бита или 4 байта. Т.е. сдвиг каждого байта на свою позицию и логическое или


    public static int byteArrayToInt2(byte[] b, int offset){
        return b[offset + 1] & 0xFF | (b[offset] & 0xFF) << 8;
    }

    public static int byteArrayToInt1(byte[] b, int offset){
        return b[offset] & 0xFF;
    }

    public static String byteArrayToString(byte[] b, int offset){
        byte[] bytes = {b[offset], b[1 + offset], b[2 + offset], b[3 + offset], b[4 + offset], b[5 + offset],
                b[6 + offset], b[7 + offset], b[8 + offset], b[9 + offset]};
        String str = new String(bytes, StandardCharsets.UTF_8);
        return str;
    }


//    public static int byteArrayToInt(byte[] b, int start, int end){ не пошло
//        int length = end - start;
//        int result = 0;
//        for (int i = 0; i < length; i++) {
//            result += (b[length - i] & 0xFF) << 8*i;
//        }
//        return result;
//    }

}
