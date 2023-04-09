package soure;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapPacket;

import java.io.UnsupportedEncodingException;
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


            result.setAppID(Short.parseShort(Integer.toHexString(byteArrayToInt(data, 14, 15)))); // парсинг идентификатора приложения
            result.setSvID(byteArrayToString(data, 34)); // парсинг идентификатора SV-потока
            result.setSmpCount(byteArrayToInt(data, 45, 46)); // парсинг номера SV-потока
            result.setConfRef(byteArrayToInt(data, 49, 52)); // парсинг номера ревизии
            result.setSmpSynch(byteArrayToInt(data, 55, 55)); // парсинг информации о синхронизации по времени


            result.getDataSet().setInstIa((byteArrayToInt(data, 58, 61)) / 100.0); // парсинг Ia
            result.getDataSet().setQIa(byteArrayToInt(data, 62, 65)); // парсинг qIa
            result.getDataSet().setInstIb((byteArrayToInt(data, 66, 69)) / 100.0); // парсинг Ib
            result.getDataSet().setQIb(byteArrayToInt(data, 70, 73)); // парсинг qIb
            result.getDataSet().setInstIc((byteArrayToInt(data, 74, 77)) / 100.0); // парсинг Ic
            result.getDataSet().setQIc(byteArrayToInt(data, 78, 81)); // парсинг qIc
            result.getDataSet().setInstIn((byteArrayToInt(data, 82, 85)) / 100.0); // парсинг In
            result.getDataSet().setQIn(byteArrayToInt(data, 86, 89)); // парсинг qIn

            result.getDataSet().setInstUa((byteArrayToInt(data, 90, 93)) / 100.0); // парсинг Ua
            result.getDataSet().setQUa(byteArrayToInt(data, 94, 97)); // парсинг qUa
            result.getDataSet().setInstUb((byteArrayToInt(data, 98, 101)) / 100.0); // парсинг Ub
            result.getDataSet().setQUb(byteArrayToInt(data, 102, 105)); // парсинг qUb
            result.getDataSet().setInstUc((byteArrayToInt(data, 106, 109)) / 100.0); // парсинг Uc
            result.getDataSet().setQUc(byteArrayToInt(data, 110, 113)); // парсинг qUc
            result.getDataSet().setInstUn((byteArrayToInt(data, 114, 117)) / 100.0); // парсинг Un
            result.getDataSet().setQUn(byteArrayToInt(data, 118, 121)); // парсинг qUn


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

//    public static int byteArrayToInt(byte[] b, int offset){ // метод парсинга измеренных значений SV-потока
//        return b[offset + 3] & 0xFF | (b[offset + 2] & 0xFF) << 8 | (b[offset + 1] & 0xFF) << 16 | (b[offset] & 0xFF) << 24; // битовые операции. Напр, b[0] & 0xFF нулевой байт * FF чтобы отбросить лишние символы числа
//    }// << 24 - сдвиг на 24 бита или 4 байта. Т.е. сдвиг каждого байта на свою позицию и логическое или


    public static String byteArrayToString(byte[] b, int offset) throws UnsupportedEncodingException {
        byte[] bytes = {b[offset], b[1 + offset], b[2 + offset], b[3 + offset], b[4 + offset], b[5 + offset],
                b[6 + offset], b[7 + offset], b[8 + offset], b[9 + offset]};
//        String str = new String(bytes, StandardCharsets.UTF_8);
        String str = new String(bytes, "windows-1251"); // моя кодировка
        return str;
    }


    public static int byteArrayToInt(byte[] b, int start, int end){
        int length = end - start + 1;
        int result = 0;
        for (int i = 0; i < length; i++) {
            result += (b[end - i] & 0xFF) << 8*i;
        }
        return result;
    }

}
