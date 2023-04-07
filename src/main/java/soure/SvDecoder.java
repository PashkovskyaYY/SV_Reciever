package soure;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapPacket;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Slf4j
public class SvDecoder { // �������������� ������ ���� PcapPacket � ������ ���� SvPacket, �.�. �������

    private static final int datasetSize = 64; // 64 ����� - ����� ���������

    public Optional<SvPacket> decode(PcapPacket packet){ // ������� ��� �������, ������� ����� ��������. �����, ����� �� �������� NullPointerException

        try {
            byte[] data = packet.getRawData(); // ������ ���� Hex stream
            int length = data.length; // 122 �����

            SvPacket result = new SvPacket();

            result.setMacDst(byteArrayToMac(data, 0)); // ������� ���-������ ����������
            result.setMacSrc(byteArrayToMac(data, 6)); // ������� ���-������ �����������


            result.setAppID(Short.parseShort(Integer.toHexString(byteArrayToInt2(data, 14)))); // ������� �������������� ����������
            result.setSvID(byteArrayToString(data, 34)); // ������� �������������� SV-������
            result.setSmpCount(byteArrayToInt2(data, 45)); // ������� ������ SV-������
            result.setConfRef(byteArrayToInt(data, 49)); // ������� ������ �������
            result.setSmpSynch(byteArrayToInt1(data, 55)); // ������� ���������� � ������������� �� �������


            result.getDataSet().setInstIa((byteArrayToInt(data, length - datasetSize)) / 100.0); // ������� Ia
            result.getDataSet().setQIa(byteArrayToInt(data, length - datasetSize + 4)); // ������� qIa
            result.getDataSet().setInstIb((byteArrayToInt(data, length - datasetSize + 8)) / 100.0); // ������� Ib
            result.getDataSet().setQIb(byteArrayToInt(data, length - datasetSize + 12)); // ������� qIb
            result.getDataSet().setInstIc((byteArrayToInt(data, length - datasetSize + 16)) / 100.0); // ������� Ic
            result.getDataSet().setQIc(byteArrayToInt(data, length - datasetSize + 20)); // ������� qIc
            result.getDataSet().setInstIn((byteArrayToInt(data, length - datasetSize + 24)) / 100.0); // ������� In
            result.getDataSet().setQIn(byteArrayToInt(data, length - datasetSize + 28)); // ������� qIn

            result.getDataSet().setInstUa((byteArrayToInt(data, length - datasetSize + 32)) / 100.0); // ������� Ua
            result.getDataSet().setQUa(byteArrayToInt(data, length - datasetSize + 36)); // ������� qUa
            result.getDataSet().setInstUb((byteArrayToInt(data, length - datasetSize + 40)) / 100.0); // ������� Ub
            result.getDataSet().setQUb(byteArrayToInt(data, length - datasetSize + 44)); // ������� qUb
            result.getDataSet().setInstUc((byteArrayToInt(data, length - datasetSize + 48)) / 100.0); // ������� Uc
            result.getDataSet().setQUc(byteArrayToInt(data, length - datasetSize + 52)); // ������� qUc
            result.getDataSet().setInstUn((byteArrayToInt(data, length - datasetSize + 56)) / 100.0); // ������� Un
            result.getDataSet().setQUn(byteArrayToInt(data, length - datasetSize + 60)); // ������� qUn


            return Optional.of(result);
        } catch (Exception e){log.error("Cannot parse sv packet");}

        return Optional.empty(); // ������ ������ Optional
    }

    public static String byteArrayToMac(byte[] b, int offset){// ������� ���-������ �� ������� ���� data, offset - �������� �� ������, ������ ������� ������
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x", // ���������� ������ � ������� �������. ����� �������������� ����� � ����������������� �����������
                b[offset],
                b[1 + offset],
                b[2 + offset],
                b[3 + offset],
                b[4 + offset],
                b[5 + offset]
        );
    }

    public static int byteArrayToInt(byte[] b, int offset){ // ����� �������� ���������� �������� SV-������
        return b[offset + 3] & 0xFF | (b[offset + 2] & 0xFF) << 8 | (b[offset + 1] & 0xFF) << 16 | (b[offset] & 0xFF) << 24; // ������� ��������. ����, b[0] & 0xFF ������� ���� * FF ����� ��������� ������ ������� �����
    }// << 24 - ����� �� 24 ���� ��� 4 �����. �.�. ����� ������� ����� �� ���� ������� � ���������� ���


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


//    public static int byteArrayToInt(byte[] b, int start, int end){ �� �����
//        int length = end - start;
//        int result = 0;
//        for (int i = 0; i < length; i++) {
//            result += (b[length - i] & 0xFF) << 8*i;
//        }
//        return result;
//    }

}
