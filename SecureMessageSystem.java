// PA#1 Secure Message System - Ryan Earp - ID:07 - CIS 435 Section 01 
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Scanner;

/**
 *
 * @author Ryan Earp
 */
public class SecureMessageSystem {

    /**
     *
     * @param args
     */
    public static void main(String[] args) {

        int step = 0;

        String stepSeperator = "\t #########################################\n";
        System.out.println("Step #" + step + stepSeperator
                + "Create Network, Sender, and Receiver ------>");
        Sender amy = new Sender();
        Receiver bob = new Receiver();
        Network net = new Network();

        step++;
        System.out.println("\nStep #" + step + stepSeperator
                + "Sender sends the test packet to Network  ------>");
        Packet testPacket = amy.getMessageFromUser(new BigInteger("17"));
        System.out.println("testPacket = \n" + testPacket.toString());

        net.sendToReceiver(testPacket);

        System.out.println("||||||||||||||||||||||||||||||||||||||||||||| ");
        System.out.println("||||||||||||||||||||||||||||||||||||||||||||| ");

        net.setNetError(0);

        System.out.println("------ Assume perfect Internet with no error----- ");
        System.out.println("||||||||||||||||||||||||||||||||||||||||||||| ");
        System.out.println("||||||||||||||||||||||||||||||||||||||||||||| " + "\n");

        step++;
        System.out.println("\nStep #" + step + stepSeperator
                + "Receiver receives the test packet through network  ------>");

        Packet recvPk = bob.receive(net);
        System.out.println("receivedPacket = \n" + recvPk.toString());

    }

}
