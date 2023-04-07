package soure;

import lombok.Getter;
import lombok.Setter;

@Setter @Getter
public class SvPacket { // класс дл€ отформатированных SV-потоков

    private String macDst; // MAC-адрес назначени€ (получател€)

    private String macSrc; // MAC-адрес источника (отправител€)

    private short appID; // идентификатор приложени€

    private String svID; // идентификатор SV-потока

    private int smpCount; // номер SV-потока (от 0 до 3999, т.к. 4000 выборок/сек)

    private int confRef;

    private int smpSynch;

    private Dataset dataSet = new Dataset();

    @Getter @Setter
    public class Dataset{

        private double instIa; // мгновенна€ величина тока Ia
        private int qIa; // качество тока Ia
        private double instIb;
        private int qIb;
        private double instIc;
        private int qIc;
        private double instIn; // нейтраль
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
