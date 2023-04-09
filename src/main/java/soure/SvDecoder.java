package soure;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapPacket;

import java.io.UnsupportedEncodingException;
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


            result.setAppID(Short.parseShort(Integer.toHexString(byteArrayToInt(data, 14, 15)))); // ������� �������������� ����������
            result.setSvID(byteArrayToString(data, 34)); // ������� �������������� SV-������
            result.setSmpCount(byteArrayToInt(data, 45, 46)); // ������� ������ SV-������
            result.setConfRef(byteArrayToInt(data, 49, 52)); // ������� ������ �������
            result.setSmpSynch(byteArrayToInt(data, 55, 55)); // ������� ���������� � ������������� �� �������


            result.getDataSet().setInstIa((byteArrayToInt(data, 58, 61)) / 100.0); // ������� Ia
            result.getDataSet().setQIa(byteArrayToInt(data, 62, 65)); // ������� qIa
            result.getDataSet().setInstIb((byteArrayToInt(data, 66, 69)) / 100.0); // ������� Ib
            result.getDataSet().setQIb(byteArrayToInt(data, 70, 73)); // ������� qIb
            result.getDataSet().setInstIc((byteArrayToInt(data, 74, 77)) / 100.0); // ������� Ic
            result.getDataSet().setQIc(byteArrayToInt(data, 78, 81)); // ������� qIc
            result.getDataSet().setInstIn((byteArrayToInt(data, 82, 85)) / 100.0); // ������� In
            result.getDataSet().setQIn(byteArrayToInt(data, 86, 89)); // ������� qIn

            result.getDataSet().setInstUa((byteArrayToInt(data, 90, 93)) / 100.0); // ������� Ua
            result.getDataSet().setQUa(byteArrayToInt(data, 94, 97)); // ������� qUa
            result.getDataSet().setInstUb((byteArrayToInt(data, 98, 101)) / 100.0); // ������� Ub
            result.getDataSet().setQUb(byteArrayToInt(data, 102, 105)); // ������� qUb
            result.getDataSet().setInstUc((byteArrayToInt(data, 106, 109)) / 100.0); // ������� Uc
            result.getDataSet().setQUc(byteArrayToInt(data, 110, 113)); // ������� qUc
            result.getDataSet().setInstUn((byteArrayToInt(data, 114, 117)) / 100.0); // ������� Un
            result.getDataSet().setQUn(byteArrayToInt(data, 118, 121)); // ������� qUn


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

//    public static int byteArrayToInt(byte[] b, int offset){ // ����� �������� ���������� �������� SV-������
//        return b[offset + 3] & 0xFF | (b[offset + 2] & 0xFF) << 8 | (b[offset + 1] & 0xFF) << 16 | (b[offset] & 0xFF) << 24; // ������� ��������. ����, b[0] & 0xFF ������� ���� * FF ����� ��������� ������ ������� �����
//    }// << 24 - ����� �� 24 ���� ��� 4 �����. �.�. ����� ������� ����� �� ���� ������� � ���������� ���


    public static String byteArrayToString(byte[] b, int offset) throws UnsupportedEncodingException {
        byte[] bytes = {b[offset], b[1 + offset], b[2 + offset], b[3 + offset], b[4 + offset], b[5 + offset],
                b[6 + offset], b[7 + offset], b[8 + offset], b[9 + offset]};
//        String str = new String(bytes, StandardCharsets.UTF_8);
        String str = new String(bytes, "windows-1251"); // ��� ���������
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
