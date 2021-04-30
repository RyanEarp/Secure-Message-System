// PA#1 Secure Message System - Ryan Earp - ID:07 - CIS 435 Section 01 
import java.math.BigInteger;

public class Receiver {

    private Packet rcvPacket;

    public Receiver() {
        System.out.println("\t----- Receiver is created -------");
        rcvPacket = new Packet();

    }

    public Packet receive(Network net) {

        System.out.println(">>>> Receiving Packet ");

        rcvPacket = net.receiveFromSender();
//RSA Components START--------------------------------------Bob's Public Key = (35,5)-------------Bob's Private Key = (35,29)-------------------------

    	BigInteger n = new BigInteger("55"); // Alice's N given to Bob (First Part of Alice's Public/Private Key)
    	int e = 3; // Alice's E (Second part of Alice's public key given to Bob)
    	BigInteger BobN = new BigInteger("35");  // Bob's N (First Part of Bob's Public/Private Key)
    	BigInteger mod13 = new BigInteger("13"); // Modulus of 13
    	BigInteger BobE = new BigInteger ("5"); // Bob's Public Key -- Alice DOES have this
    	int BobD = 29; // Bob's Private Key -- Alice DOES NOT have this.
//RSA Components END-------------------------------------------------------------------------------------------------------------------------
    	
    	System.out.println("\n" + "---Step 2-1:  Receive the packet from Internet rcvPacket ");
//Step 2: Split the Packet---------------- The packet is split up into three parts: the Cipher Message (22), the digital signature (54), and the encryptedKS (10)
    	BigInteger cipher = rcvPacket.getCipherMessage();
    	BigInteger digitalSignature = rcvPacket.getDigitalSignature();
    	BigInteger encryptedKs = rcvPacket.getEncryptedKs();
    	System.out.println("\n" + "---Step 2-2:  Split the packet" + "\n");
    	System.out.println("Receiver: Recieved cipher from the network is: " + "\n");
    	System.out.println("pk.cipher 'Ks(m)' = " + cipher + "\n");
    	System.out.println("pk.digitialSignature 'Ks(Ka-(H(m)))' = " + digitalSignature + "\n");
    	System.out.println("pk.encryptedKs  'Kb+(Ks)' = " + encryptedKs + "\n");
//---------------------------------------------------------------------------

//Step 3: Decrypt Kb+(Ks) with Receiver's private key 'Kb-'----------------------- The encryptedKS is decrypted by taking it to the power of Bob's private key (29), and finding the remainder with Bob's N as mod (35)
    	System.out.println("\n" + "---Step 2-3:  Decrypt Kb+(Ks) with Receiver's private key 'Kb-' " + "\n");
    	System.out.println("Receiver: the encryptedKs 'Kb+(Ks)' is: " + encryptedKs + "\n");
    	encryptedKs = encryptedKs.pow(BobD);
    	encryptedKs = encryptedKs.mod(BobN);
    	System.out.println("After decrypting with receiver's privateky 'Kb-', get Ks = " + encryptedKs + "\n");
//-----------------------------------------------------------------------------------------------

//Step 4: Decrypt pk.cipher, i.e, 'Ks(m)' using Ks which is gotten from step 3: ----------------- We subtract the Ks (5) from the cipher message (22). 22-5 = 17
    	System.out.println("\n" + "---Step 4: decrypt pk.cipher, i.e, 'Ks(m)' using Ks which is gotten from step 3: " + cipher + "\n"); 	
    	cipher = cipher.subtract(encryptedKs);
    	System.out.println("After decryption receiver gets message 'm' = " + cipher);
//-----------------------------------------------------------------------------------
    	
//Step 5: Decrypt Ks(Ka-(H(m))) with 'Ks' got from step 4,  Ks(Ka-(H(m)))------------------ We subtract the Ks (5) from the digital Signature (54). 54-5 = 49
    	System.out.println("\n" + "---Step 2-5:  Decrypt Ks(Ka-(H(m))) with 'Ks' got from step 4,  Ks(Ka-(H(m))) = " + digitalSignature + "\n");
    	digitalSignature = digitalSignature.subtract(encryptedKs);
    	System.out.println("and get the digital signature 'Ka-(H(m))' = " + digitalSignature + "\n");
//----------------------------------------------------------------------------------
    	
//Step 6: Decrypt 'Ka-(H(m))' from sender's public key 'Ka+()'-------------------- We decrypt the digital signature by taking it to the power of Alice's public key (3). Then, we find the remainder using Alice's public key N (54) as modulus. 
    	System.out.println("---Step 2-6:  decrypt 'Ka-(H(m))' from sender's public key 'Ka+()' " + "\n");
    	System.out.println("Sender N = " + n + ", Sender E = " + e + "\n");
    	BigInteger Hash1 = digitalSignature.pow(e);
    	Hash1 = Hash1.mod(n);
    	System.out.println("The decrypted message digest 'H(m)' = Ka+(Ka-(H(m))) = " + Hash1 + "\n");
//--------------------------------------------------------------------------------------------------------

//Step 7:  hash message m from step 4 'm'---------------- We find the hash message by finding the remainder of m(17) mod 13. This equals out to 4.
    	System.out.println("---Step 2-7:  hash message m from step 4 'm' = "  + cipher + "\n");
    	BigInteger Hash2 = cipher.mod(mod13);
    	System.out.println("The Hash result H(m) = " + Hash2 + "\n" );
//--------------------------------------------------------------------------------------------------------
   
//Step 8: Compare results from step 6 and step 7, if they match then accept otherwise discards---------- We compare Hash1 (Found in Step 6) to Hash2 (Found in Step 7). Both equal 4, so the packet's integrity is accepted.
    	System.out.println("---Step 2-8: Compare results from step 6 and step 7, if they match then accept otherwise discards" + "\n");
    	if(Hash1.equals(Hash2))
    		System.out.println("The packet has passed through the integrity checking and is accepted!" + "\n");
    	else
    	{
    		System.out.println("The packet has NOT passed through the integrity checking and is discarded");
    	}
        return rcvPacket;

    }

}
