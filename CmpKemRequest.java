import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.POPOPrivKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.MacCalculator;

/**
 * Builds a CMPv3 (pvno=3) "ir" request with genuine ML-KEM key-encipherment
 * (encrCert) proof-of-possession, using an externally supplied ML-KEM public
 * key, and writes it to a file so it can be POSTed separately, e.g.:
 *
 *   curl -s -X POST --data-binary @request.der \
 *        -H "Content-Type: application/pkixcmp" \
 *        http://localhost/ejbca/publicweb/cmp/cmpclient -o response.der
 *
 * The key file must be a DER-encoded SubjectPublicKeyInfo, e.g. generated with:
 *
 *   openssl genpkey -algorithm ML-KEM-768 -outform DER -out key.der
 *   openssl pkey -in key.der -inform DER -pubout -outform DER -out pubkey.der
 *
 * or, for a hardware-backed key that never leaves a YubiKey:
 *
 *   yubico-piv-tool -a generate -A ML-KEM-768 -s 83 -K DER -o pubkey.der
 *
 * Only the public key is needed here - proof of possession is satisfied later
 * (see CmpKemExtract) by whoever can decrypt the response, not by anything
 * this tool does with a private key.
 */
public class CmpKemRequest {

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Usage: CmpKemRequest <subject-dn> <password> <pubkey.der> <request-out.der>");
            System.err.println("  subject-dn example: \"CN=John Doe,emailAddress=jd@example.com\"");
            System.exit(1);
        }
        Security.addProvider(new BouncyCastleProvider());

        String subjectDn = args[0];
        char[] password = args[1].toCharArray();
        String pubKeyIn = args[2];
        String requestOut = args[3];

        byte[] pubKeyBytes = Files.readAllBytes(Paths.get(pubKeyIn));
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pubKeyBytes);

        X500Name subject = new X500Name(subjectDn);
        CertTemplate certTemplate = new CertTemplateBuilder()
                .setSubject(subject)
                .setPublicKey(spki)
                .build();

        CertRequest certRequest = new CertRequest(1, certTemplate, null);
        POPOPrivKey popoPrivKey = new POPOPrivKey(SubsequentMessage.encrCert);
        ProofOfPossession pop = new ProofOfPossession(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, popoPrivKey);
        CertReqMsg certReqMsg = new CertReqMsg(certRequest, pop, null);
        CertReqMessages certReqMessages = new CertReqMessages(certReqMsg);

        GeneralName sender = PKIHeader.NULL_NAME;
        GeneralName recipient = PKIHeader.NULL_NAME;

        byte[] transactionId = new byte[16];
        byte[] senderNonce = new byte[16];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(transactionId);
        rnd.nextBytes(senderNonce);

        PKMACBuilder macBuilder = new PKMACBuilder(new JcePKMACValuesCalculator());
        MacCalculator macCalculator = macBuilder.build(password);
        AlgorithmIdentifier protectionAlg = macCalculator.getAlgorithmIdentifier();

        PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(PKIHeader.CMP_2021, sender, recipient)
                .setMessageTime(new ASN1GeneralizedTime(new Date()))
                .setProtectionAlg(protectionAlg)
                .setSenderKID(subjectDn.getBytes("UTF-8"))
                .setTransactionID(transactionId)
                .setSenderNonce(senderNonce);
        PKIHeader header = headerBuilder.build();

        PKIBody body = new PKIBody(PKIBody.TYPE_INIT_REQ, certReqMessages);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(header);
        v.add(body);
        byte[] protectedBytes = new DERSequence(v).getEncoded(ASN1Encoding.DER);

        java.io.OutputStream macOut = macCalculator.getOutputStream();
        macOut.write(protectedBytes);
        macOut.close();
        byte[] mac = macCalculator.getMac();
        DERBitString protection = new DERBitString(mac);

        PKIMessage pkiMessage = new PKIMessage(header, body, protection);
        byte[] requestBytes = pkiMessage.getEncoded(ASN1Encoding.DER);

        Files.write(Paths.get(requestOut), requestBytes);

        System.out.println("Wrote CMPv3 ir request (pvno=3, keyEncipherment/encrCert POP) for subject=" + subjectDn
                + " using public key " + pubKeyIn + " to " + requestOut);
        System.out.println();
        System.out.println("POST it with:");
        System.out.println("  curl -s -X POST --data-binary @" + requestOut
                + " -H \"Content-Type: application/pkixcmp\" "
                + "<cmp-url> -o response.der");
        System.out.println();
        System.out.println("Then extract the certificate with:");
        System.out.println("  java CmpKemExtract response.der <matching-private-key> cert.der");
    }
}
