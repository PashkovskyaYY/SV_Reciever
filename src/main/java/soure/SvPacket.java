package soure;

import lombok.Getter;
import lombok.Setter;

@Setter @Getter
public class SvPacket { // ����� ��� ����������������� SV-�������

    private String macDst; // MAC-����� ���������� (����������)

    private String macSrc; // MAC-����� ��������� (�����������)

    private short appID; // ������������� ����������

    private String svID; // ������������� SV-������

    private int smpCount; // ����� SV-������ (�� 0 �� 3999, �.�. 4000 �������/���)

    private int confRef;

    private int smpSynch;

    private Dataset dataSet = new Dataset();

    @Getter @Setter
    public class Dataset{

        private double instIa; // ���������� �������� ���� Ia
        private int qIa; // �������� ���� Ia
        private double instIb;
        private int qIb;
        private double instIc;
        private int qIc;
        private double instIn; // ��������
        private int qIn;

        private double instUa;
        private int qUa;
        private double instUb;
        private int qUb;
        private double instUc;
        private int qUc;
        private double instUn;
        private int qUn;

    }

    @Override
    public String toString(){
        return  "macDst = " + macDst + "   " +
                "macSrc = " + macSrc + "   " +
                "appID = " + appID + "   " +
                "svID = " + svID + "   " +
                "smpCount = " + smpCount + "   " +
                "confRef = " + confRef + "   " +
                "smpSynch = " + smpSynch + "   " +

                "instIa = " + dataSet.instIa + "   " +
                "qIa = " + dataSet.qIa + "   " +
                "instIb = " + dataSet.instIb + "   " +
                "qIb = " + dataSet.qIb + "   " +
                "instIc = " + dataSet.instIc + "   " +
                "qIc = " + dataSet.qIc + "   " +
                "instIn = " + dataSet.instIn + "   " +
                "qIn = " + dataSet.qIn + "   " +

                "instUa = " + dataSet.instUa + "   " +
                "qUa = " + dataSet.qUa + "   " +
                "instUb = " + dataSet.instUb + "   " +
                "qUb = " + dataSet.qUb + "   " +
                "instUc = " + dataSet.instUc + "   " +
                "qUc = " + dataSet.qUc + "   " +
                "instUn = " + dataSet.instUn + "   " +
                "qUn = " + dataSet.qUn
        ;
    }

}
