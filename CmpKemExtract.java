import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.cert.crmf.CertificateRepMessage;
import org.bouncycastle.cert.crmf.CertificateResponse;
import org.bouncycastle.cms.jcajce.JceKEMEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Reads a raw CMP response (as saved by curl from CmpKemRequest's output),
 * and either prints the rejection reason or decrypts the KEM-enveloped
 * certificate using the matching ML-KEM private key written by CmpKemRequest.
 */
public class CmpKemExtract {

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Usage: CmpKemExtract <response.der> <privkey.der> <cert-out.der>");
            System.exit(1);
        }
        Security.addProvider(new BouncyCastleProvider());

        byte[] respBytes = Files.readAllBytes(Paths.get(args[0]));
        byte[] privKeyBytes = Files.readAllBytes(Paths.get(args[1]));
        String certOut = args[2];

        PKIMessage respMsg = PKIMessage.getInstance(respBytes);
        PKIBody respBody = respMsg.getBody();
        int type = respBody.getType();
        System.out.println("Response PKIBody type: " + type);

        if (type == PKIBody.TYPE_ERROR) {
            ErrorMsgContent err = ErrorMsgContent.getInstance(respBody.getContent());
            System.out.println("PKIStatus: " + err.getPKIStatusInfo().getStatus());
            System.out.println("FailInfo: " + err.getPKIStatusInfo().getFailInfo());
            if (err.getPKIStatusInfo().getStatusString() != null) {
                for (int i = 0; i < err.getPKIStatusInfo().getStatusString().size(); i++) {
                    System.out.println("StatusString[" + i + "]: "
                            + err.getPKIStatusInfo().getStatusString().getStringAt(i));
                }
            }
            System.exit(2);
        }

        if (type != PKIBody.TYPE_INIT_REP) {
            System.out.println("Unexpected body type, dumping raw content: " + respBody.getContent());
            System.exit(2);
        }

        CertRepMessage certRepMessage = (CertRepMessage) respBody.getContent();
        CertResponse certResponse = certRepMessage.getResponse()[0];
        System.out.println("PKIStatus: " + certResponse.getStatus().getStatus());
        if (certResponse.getStatus().getStatusString() != null) {
            System.out.println("StatusString: " + certResponse.getStatus().getStatusString());
        }

        CertifiedKeyPair ckp = certResponse.getCertifiedKeyPair();
        if (ckp == null) {
            System.out.println("No certified key pair in response - request was rejected.");
            System.exit(2);
        }
        CertOrEncCert coec = ckp.getCertOrEncCert();
        System.out.println("hasEncryptedCertificate: " + coec.hasEncryptedCertificate());

        PrivateKey kemPrivateKey = KeyFactory.getInstance("ML-KEM", "BC")
                .generatePrivate(new PKCS8EncodedKeySpec(privKeyBytes));

        CertificateRepMessage repMessage = CertificateRepMessage.fromPKIBody(respBody);
        CertificateResponse certificateResponse = repMessage.getResponses()[0];

        byte[] certDer;
        if (certificateResponse.hasEncryptedCertificate()) {
            certDer = certificateResponse.getCertificate(new JceKEMEnvelopedRecipient(kemPrivateKey))
                    .getX509v3PKCert().getEncoded();
        } else {
            certDer = certificateResponse.getCertificate().getX509v3PKCert().getEncoded();
        }

        Files.write(Paths.get(certOut), certDer);
        System.out.println("Wrote " + certOut + ", length=" + certDer.length);
    }
}
