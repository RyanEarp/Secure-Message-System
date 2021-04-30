// PA#1 Secure Message System - Ryan Earp - ID:07 - CIS 435 Section 01 
import java.math.BigInteger;
import java.security.KeyPairGenerator;

public class Sender {

    private Packet pk;

    public Sender() {
        System.out.println("\t----- Sender is Created -----");
        pk = new Packet();

    }

    public Packet getMessageFromUser(BigInteger msg) {
    	System.out.println("\n" + " ***Sender's Operations for secure message communication *** " + "\n");
    	System.out.println("---Step 1-1:  Sender generates message" + "\n" + "m = " + msg + "\n");
    	BigInteger mod13 = new BigInteger("13"); //Modulus is created and set to be "13".
//Step 2: Sender Hash Message---------------------
    	BigInteger HashedMessage = msg.mod(mod13); //Hashed Message is found by taking the remainder of 17 mod 13
    	System.out.println("---Step 1-2:  Sender hash message" + "\n" + "H(m) = " + HashedMessage + "\n");
//------------------------------------------------

//RSA Components------------------------------------------------ Alice's Public Key = (55,3)------------ Alice's Private Key = (55,27)----------------
    	int p = 5; // Alice's chosen P
    	int q = 11; // Alice's chosen Q
    	BigInteger n = new BigInteger("55"); //Found by taking (p * q). This is the first part of Alice's public key. --- Bob DOES have this.
    	int z = ((p-1)*(q-1)); // Alice's Z.
    	int e = 3; // Second Part of Alice's public key -- Bob DOES have this
    	int d = 27; // Alice's private key --- Bob DOES NOT have this
    	BigInteger BobE = new BigInteger ("5"); // Bob Public Key --- Alice DOES have this
//---------------------------------------------------------------    	

//Step 3: Sign H(m) with sender's private key and generate digital signature------------- The hashed message is taken to the power of d, then the remainder is found with mod n (in this case n = 55)
    	BigInteger Step3encryptedMessageWKey = HashedMessage.pow(d);
    	BigInteger Step3encryptedMessageWKeyMODULUS = Step3encryptedMessageWKey.mod(n);
    	System.out.println("---Step 1-3:  sign H(m) with sender's private key and generate digital signature " + "\n" + "Ka-(H(m)) = " + Step3encryptedMessageWKeyMODULUS + "\n");
//----------------------------------------------------------------------
//Step 4: Generate Session Key---------------------- A Session Key is chosen. We choose Ks = 5
    	BigInteger Ks = new BigInteger("5");
    	System.out.println("---Step 1-4: generate a session key" + "\n" + "Ks = " + Ks + "\n");
//----------------------------------------------------------------------
 
//Step 5: Encrypt Ks with receiver's public key using RSA algorithm--------------- We add Bob's Public Key (Kb = 5) to the Session Key (Ks =5). 5+5 = 10
    	BigInteger encryptWBobPublicKey = BobE.add(Ks);
    	pk.setEncryptedKs(encryptWBobPublicKey);
    	System.out.println("---Step 1-5: encrypt Ks with receiver's public key using RSA algoirthm " + "\n" + "Kb+(Ks) = " + encryptWBobPublicKey + "\n" + ">>>Set packet.encryptedKs = " + encryptWBobPublicKey + "\n");
//-----------------------------------------------------------------------
//Step 6: Encrypt message m with session key and symmetric algorithm-------------We add the Session key (ks = 5) to message m (m = 17). 5 + 17 = 22. Then we set packet.encryptedKs to equal the new value: 22
    	System.out.println("---Step 1-6: encrypt message m with session key and symmetric algorithm" + "\n");
    	BigInteger encryptMessageWKs = msg.add(Ks);
        pk.setCipherMessage(encryptMessageWKs);  
        System.out.println("Ks(m) = " + encryptMessageWKs + "\n" + ">>>Set packet.cipher = " + encryptMessageWKs + "\n");
//---------------------------------------------------------------------

//Step 7: encrypt sender's digital signature Ka-(H(m)) using session key (ks) and symmetric algorithm ------------ We add the session Key (Ks = 5) to the digital signature that we found in step 3: (49). Then we set packet.digitalSignature to equal the new value: 54
        Step3encryptedMessageWKeyMODULUS = Step3encryptedMessageWKeyMODULUS.add(Ks);
        pk.setDigitalSignature(Step3encryptedMessageWKeyMODULUS);
        System.out.println("---Step 1-7: encrypt sender's digital signature Ka-(H(m)) using session key (ks) and symmetric algorithm" + "\n" + "Ks(Ka-(H(m))) = " + Step3encryptedMessageWKeyMODULUS + "\n" + ">>>Set packet.digitialSignature = " + Step3encryptedMessageWKeyMODULUS + "\n");
//---------------------------------------------------------------------------------------
        
//Step 8:  the packet to be sent on to Internet is:
        System.out.println("---Step 1-8: the packet to be sent on to Internet is:" + "\n" + "pk.cipher'Ks(m)' = " + encryptMessageWKs + "\n" + "pk.digitialSignature 'Ks(Ka-(H(m)))' = " + Step3encryptedMessageWKeyMODULUS + "\n" + "pk.encryptedKs  'Kb+(Ks)' = " + encryptWBobPublicKey + "\n");
        
        return pk;
    }

}
