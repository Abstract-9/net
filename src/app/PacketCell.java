package app;


import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import org.pcap4j.packet.Packet;

import java.util.Date;

public class PacketCell{

    private final SimpleStringProperty proto, src, dest, info;
    private final SimpleIntegerProperty num, length;
    private final SimpleDoubleProperty time;
    private long capTime;

    PacketCell(int num, double time, String src, String dest, String proto, int length, String info){
        this.num = new SimpleIntegerProperty(num);
        this.time = new SimpleDoubleProperty(time);
        this.src = new SimpleStringProperty(src);
        this.dest = new SimpleStringProperty(dest);
        this.proto = new SimpleStringProperty(proto);
        this.length = new SimpleIntegerProperty(length);
        this.info = new SimpleStringProperty(info);
        this.capTime = System.currentTimeMillis();
    }

    public String getProto() {
        return proto.get();
    }

    public String getSrc() {
        return src.get();
    }

    public String getDest() {
        return dest.get();
    }

    public String getInfo() {
        return info.get();
    }

    public int getNum() {
        return num.get();
    }

    public int getLength() {
        return length.get();
    }

    public double getTime() {
        return time.get();
    }

    public void setProto(String proto) {
        this.proto.set(proto);
    }

    public void setSrc(String src) {
        this.src.set(src);
    }

    public void setDest(String dest) {
        this.dest.set(dest);
    }

    public void setInfo(String info) {
        this.info.set(info);
    }

    public void setNum(int num) {
        this.num.set(num);
    }

    public void setLength(int length) {
        this.length.set(length);
    }

    public void setTime(double time) {
        this.time.set(time);
    }

    Date getCapTime(){
        return new Date(capTime);
    }
}
