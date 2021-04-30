// PA#1 Secure Message System - Ryan Earp - ID:07 - CIS 435 Section 01 
import java.math.BigInteger;

public class Packet {

    private BigInteger encryptedKs;
    private BigInteger cipherMessage;
    private BigInteger digitalSignature;

    Packet() {

        encryptedKs = BigInteger.ZERO;
        cipherMessage = BigInteger.ZERO;
        digitalSignature = BigInteger.ZERO;

    }

    public BigInteger getEncryptedKs() {
        return encryptedKs;
    }

    public void setEncryptedKs(BigInteger encryptedKs) {
        this.encryptedKs = encryptedKs;
    }

    public BigInteger getCipherMessage() {
        return cipherMessage;
    }

    public void setCipherMessage(BigInteger cipherMessage) {
        this.cipherMessage = cipherMessage;
    }

    public BigInteger getDigitalSignature() {
        return digitalSignature;
    }

    public void setDigitalSignature(BigInteger digitalSignature) {
        this.digitalSignature = digitalSignature;
    }

    public String toString() {

        String result = "";

        result += "\tpk.cipherMessage 'Ks(m)' = " + this.cipherMessage.toString() + "\n"
                + "\tpk.digitalSignature 'Ks(Ka-(H(m)))' = " + this.digitalSignature.toString() + "\n"
                + "\tpk.encryptedKs  'Kb+(Ks)' =" + this.encryptedKs.toString();

        return result;
    }

    void setErrorInMessage(BigInteger bigInteger) {
        this.cipherMessage = this.cipherMessage.add(BigInteger.TEN);
    }

}
