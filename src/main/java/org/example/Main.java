package org.example;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

public class Main {

    private void checkSymmetric(Pairing pairing){
        if(pairing.isSymmetric()){ System.out.println("yahoo it is Symmetric :)"); }
    }

    // Encrypt a string using AES and HTK
    public static byte[] encrypt(String data, byte[] HTK) throws Exception {
        SecretKey secretKey = new SecretKeySpec(HTK, 0, 16, "AES"); // Use first 16 bytes for AES-128, to use AES256 just replace the value 16 with 32
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    // Decrypt a byte array using AES and HTK
    public static String decrypt(byte[] encryptedData, byte[] HTK) throws Exception {
        SecretKey secretKey = new SecretKeySpec(HTK, 0, 16, "AES"); // Use first 16 bytes for AES-128
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

    // Generate Handshake Traffic Key (HTK) using HKDF
    public static byte[] generateHTK(byte[] SS_D, byte[] P_Pub_bytes) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        HKDFParameters params = new HKDFParameters(SS_D, null, P_Pub_bytes);
        hkdf.init(params);

        // byte[] HTK = new byte[32]; // Length of output key (256 bits) if AES256 to be used , but AES256 is a little slower due to longer key length
        byte[] HTK = new byte[16]; // Here Length will be 128 bits as in this project I am going to use AES 128 which will give enough level of security and will be faster than AES256
        hkdf.generateBytes(HTK, 0, HTK.length);
        return HTK;
    }

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        // *********************************************** PKG Function *************************************************

        // #################### Setup Phase ####################################
//        int rBits = 160; // 384
//        int qBits = 512;
//        TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
//        PairingParameters pp = pg.generate();
        Pairing pairing = PairingFactory.getPairing("src/main/java/params/a.properties");

        // check Symmetric
        Main ob = new Main();
        ob.checkSymmetric(pairing);

        // ########################### Elements and Fields Initialization Phase ###########################

        // Generator = P
        Element P = pairing.getG1().newRandomElement().getImmutable();

        // Master Secret Key = s
        Element s = pairing.getZr().newRandomElement().getImmutable();

        // Master Public Key = Ppub
        Element Ppub = pairing.getG1().newElement();
        Ppub = P.duplicate().mulZn(s).getImmutable();

        // ####################### Identities of Devices ############################################
        String IDs = "bestSigner@yahoo.com";
        String IDd = "documentSignee@gmail.com";
        byte[] signerIdBytes = ob.sha256(IDs);
        byte[] signeeIdBytes = ob.sha256(IDd);

        // ###################### Initialization of Public and private keys of devices ######################

        // Public key of Signer
        Element PKs = pairing.getG1().newElementFromHash(signerIdBytes, 0, signerIdBytes.length).getImmutable();

        // I was just checking, whether do we get different element from the same hash or not
//        Element checkPKs = pairing.getG1().newElementFromHash(signerIdBytes, 0, signerIdBytes.length).getImmutable();
//        Element checkAnotherPks = pairing.getG1().newElementFromHash(signerIdBytes, 0, signerIdBytes.length).getImmutable();
//        System.out.println(PKs.isEqual(checkPKs));
//        System.out.println(checkAnotherPks.isEqual(checkPKs));

        // Public key of Signee
        Element PKd = pairing.getG1().newElementFromHash(signeeIdBytes, 0, signeeIdBytes.length).getImmutable();

        // Private key of Signer
        // Element SKs = pairing.getZr().newElement().set(s).mul(PKs.toBigInteger()).getImmutable();
        Element SKs = PKs.duplicate().mulZn(s).getImmutable();

        // Private key of Signee

        Element SKd = pairing.getG1().newElement();
        SKd = PKd.duplicate().mulZn(s).getImmutable();

        // **************************************************************************************************************

        // ################# Signer Hello ##########################

        // generate x , randomly chosen ephimeral secret
        Element x = pairing.getZr().newRandomElement().getImmutable();

        // Ephemeral Public key
        // Element EKs = pairing.getG1().newElement();
        Element EKs = P.duplicate().mulZn(x).getImmutable();

        // ################## Signee Hello ########################

        // generate y, randomly chosen ephimeral secret
        Element y = pairing.getZr().newRandomElement().getImmutable();

        // Ephemeral Public key
        // Element EKd = pairing.getG1().newElement();
        Element EKd = P.duplicate().mulZn(y).getImmutable();

        // To compute SSd = y.EKs || e(EKs + H(IDs) , y.Ppub + SKd)

        // Step - 1
        Element y_EKs = EKs.duplicate().mulZn(y);

        Element EKs_plus_H_IDs = EKs.duplicate().add(PKs);
        Element y_Ppub_plus_SKd = Ppub.duplicate().mulZn(y).add(SKd);
        Element SSd_PairingResult = pairing.pairing(EKs_plus_H_IDs, y_Ppub_plus_SKd);

        // Step - 2 : Converting the result into byte arrays
        byte[] y_EKs_bytes = y_EKs.toBytes();
        byte[] SSd_PairingResult_bytes = SSd_PairingResult.toBytes();

        // Step - 3 : Concatenating
        byte[] SSd = new byte[y_EKs_bytes.length + SSd_PairingResult_bytes.length];
        System.arraycopy(y_EKs_bytes, 0, SSd, 0, y_EKs_bytes.length);
        System.arraycopy(SSd_PairingResult_bytes, 0, SSd, y_EKs_bytes.length, SSd_PairingResult_bytes.length);

        byte[] HTKd = generateHTK(SSd,Ppub.toBytes());


        // To compute SSs = x.EKd || e(x.Ppub + SKs , EKd + H(IDd))

        // Step - 1
        Element x_EKd = EKd.duplicate().mulZn(x);

        Element x_Ppub_plus_SKs = Ppub.duplicate().mulZn(x).add(SKs);
        Element EKd_plus_H_IDd = EKd.duplicate().add(PKd);
        Element SSs_PairingResult = pairing.pairing(x_Ppub_plus_SKs, EKd_plus_H_IDd);

        // Step - 2 : Converting the result into byte arrays
        byte[] x_EKd_bytes = x_EKd.toBytes();
        byte[] SSs_PairingResult_bytes = SSs_PairingResult.toBytes();

        // Step - 3 : Concatenating
        byte[] SSs = new byte[x_EKd_bytes.length + SSs_PairingResult_bytes.length];
        System.arraycopy(x_EKd_bytes, 0, SSs, 0, x_EKd_bytes.length);
        System.arraycopy(SSs_PairingResult_bytes, 0, SSs, x_EKd_bytes.length, SSs_PairingResult_bytes.length);

        byte[] HTKs = generateHTK(SSs,Ppub.toBytes());

        // ##################### VERIFY PHASE WHETHER BOTH PARTIES HAVE COMPUTED SAME HTK OR NOT #######################################

        boolean areEqual = Arrays.equals(HTKs, HTKd);


        if (areEqual) {
            System.out.println("Yahoo mehenat safal :)))");
        } else {
            System.out.println("Yeah it is working as expected, yahooo");
        }

        String testMessage = "This is a test message";

        byte[] encryptedMessage = encrypt(testMessage,HTKs);

        String decryptedMessage = decrypt(encryptedMessage,HTKd);

        System.out.println("The real message is : "+testMessage);
        System.out.println("Encrypted Message is : "+Arrays.toString(encryptedMessage));
        System.out.println("Encrypted Message into String : "+ new String(encryptedMessage, StandardCharsets.UTF_8));
        System.out.println("Decrypted Message is : "+ decryptedMessage);

        // ###################### This test shows that both HTK generated are same and are working absolutely fine #########################

        // ***************************************************************** DIGITAL SIGNATURE PHASE ******************************************************8

        // ##################### Here doing signatures through HESS IBS Scheme #####################################################

        String message = "My name is Himanshu";

        String message2 = "My name is Himanshu";

        Main obj = new Main();

        byte[] signature = obj.signMessage(message,SKs, P, pairing);

        boolean result = obj.verifyMessage(message2,signature,PKs,P, pairing, Ppub);
        if (result){
            System.out.println("Digital Signatures are valid");
        }else{
            System.out.println("Forged Digital Signatures");
        }
    }

    public byte[] signMessage(String message, Element SKs, Element P, Pairing pairing) throws NoSuchAlgorithmException{
        // Hash the message
        byte[] messageHash = sha256(message);

        Element k = pairing.getZr().newRandomElement().getImmutable();
        Element P1 = pairing.getG1().newRandomElement().getImmutable();
        Element r = pairing.pairing(P1, P).powZn(k);
        Element v = pairing.getZr().newElementFromHash(messageHash,0,messageHash.length).mul(r.toBigInteger()).getImmutable();
        Element u = SKs.duplicate().mulZn(v).add(P1.duplicate().mulZn(k));

        ByteBuffer signature = ByteBuffer.allocate(u.getLengthInBytes() + v.getLengthInBytes());
        signature.put(u.toBytes());
        signature.put(v.toBytes());

        return signature.array();
    }

    public boolean verifyMessage(String message, byte[] signature, Element PKs, Element P, Pairing pairing, Element Ppub) throws NoSuchAlgorithmException{
        byte[] messageHash = sha256(message);

        byte[] uBytes = Arrays.copyOfRange(signature, 0, P.getLengthInBytes());
        byte[] vBytes = Arrays.copyOfRange(signature, P.getLengthInBytes(), signature.length);
        Element u = pairing.getG1().newElementFromBytes(uBytes).getImmutable();
        Element v = pairing.getZr().newElementFromBytes(vBytes).getImmutable();

        Element r_prime = pairing.pairing(u.duplicate(), P.duplicate()).mul(pairing.pairing(PKs.duplicate(), Ppub.duplicate().negate()).powZn(v.duplicate())).getImmutable();
        Element v_prime = pairing.getZr().newElementFromHash(messageHash,0,messageHash.length).mul(r_prime.duplicate().toBigInteger()).getImmutable();

        return v_prime.isEqual(v);

    }

    private byte[] sha256(String data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data.getBytes());
    }
}
