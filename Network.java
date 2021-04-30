// PA#1 Secure Message System - Ryan Earp - ID:07 - CIS 435 Section 01 
import java.math.BigInteger;

public class Network {

    Packet inFromSender, outToReceiver;     

    Network() {
        System.out.println("\t----- Network is created -----");
        inFromSender = new Packet(); 
        outToReceiver =  new Packet();
    }

    /**
     * @param pk
     */
    public void sendToReceiver(Packet pk) {
        inFromSender = pk;

    }

    /**
     *
     * @param error
     */
    public void setNetError(int error) {
        if (error == 0) {
            outToReceiver = inFromSender;
        } else {
            
            inFromSender.setErrorInMessage(new BigInteger(Integer.toString(error)));
            outToReceiver = inFromSender;
        }
    }

    /**
     * @return
     */       
    public Packet receiveFromSender() {
        return outToReceiver;

    }

}
