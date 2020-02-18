import java.io.*;
import java.security.*;
import java.security.cert.*;


public class VerifyCertificate {
    String ca;

    public VerifyCertificate(String ca){
        this.ca = ca;
    }

    public boolean verify(byte[] bytes) throws IOException, CertificateException {

        PublicKey CAkey;

        boolean exception = true;
        FileOutputStream fo = new FileOutputStream("changinginfo");
        fo.write(bytes);
        InputStream fi = new FileInputStream("changinginfo");
        FileInputStream fis = new FileInputStream(ca);
        CAkey = getPublicKeyFromCertFile(fis);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate;

        certificate = (X509Certificate)f.generateCertificate(fi);
        try {
            certificate.verify(CAkey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            exception = false;
        } catch (InvalidKeyException e) {
            exception = false;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            exception = false;
        } catch (SignatureException e) {
            e.printStackTrace();
            exception = false;
        }finally {
            if(exception) System.out.println("Pass!");
            else System.out.println("Fail!");
        }
        return exception;
    }
    private PublicKey getPublicKeyFromCertFile(InputStream certfile) throws FileNotFoundException, CertificateException {

        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(certfile);
        Principal subjectDN = certificate.getSubjectDN();
        System.out.println(subjectDN);
        PublicKey publicKey = certificate.getPublicKey();
        return publicKey;
    }
}
