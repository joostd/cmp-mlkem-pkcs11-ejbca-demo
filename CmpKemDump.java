import java.nio.file.Files;
import java.nio.file.Paths;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.KEMRecipientInfo;
import org.bouncycastle.asn1.cms.OtherRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Reads a raw CMP response and dumps the raw KEMRecipientInfo /
 * EncryptedContentInfo fields (RFC 9629 CMS-for-ML-KEM), without attempting
 * any decryption. For inspecting the exact KDF/wrap parameters EJBCA uses,
 * so a separate (e.g. Python) tool can replicate the derivation using a
 * YubiKey-resident private key for the actual decapsulation.
 */
public class CmpKemDump {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: CmpKemDump <response.der> <output-dir>");
            System.exit(1);
        }
        byte[] respBytes = Files.readAllBytes(Paths.get(args[0]));
        String outDir = args[1];
        Files.createDirectories(Paths.get(outDir));

        PKIMessage respMsg = PKIMessage.getInstance(respBytes);
        PKIBody respBody = respMsg.getBody();
        if (respBody.getType() != PKIBody.TYPE_INIT_REP) {
            System.out.println("Not an ip message, body type=" + respBody.getType());
            System.exit(2);
        }

        CertRepMessage certRepMessage = (CertRepMessage) respBody.getContent();
        CertResponse certResponse = certRepMessage.getResponse()[0];
        CertifiedKeyPair ckp = certResponse.getCertifiedKeyPair();
        CertOrEncCert coec = ckp.getCertOrEncCert();
        if (!coec.hasEncryptedCertificate()) {
            System.out.println("Response does not contain an encrypted certificate.");
            System.exit(2);
        }

        EncryptedKey encrCert = coec.getEncryptedCert();
        ASN1Encodable asn1 = encrCert.getValue();
        System.out.println("Encrypted value ASN.1 type: " + asn1.getClass().getName());

        EnvelopedData ed = EnvelopedData.getInstance(asn1);
        System.out.println("EnvelopedData version: " + ed.getVersion());

        java.util.Enumeration<?> e = ed.getRecipientInfos().getObjects();
        int idx = 0;
        int[] kekLengthOut = new int[1];
        while (e.hasMoreElements()) {
            RecipientInfo ri = RecipientInfo.getInstance(e.nextElement());
            OtherRecipientInfo ori = OtherRecipientInfo.getInstance(ri.getInfo());
            System.out.println("RecipientInfo[" + idx + "] type OID: " + ori.getType());
            KEMRecipientInfo kemri = KEMRecipientInfo.getInstance(ori.getValue());

            System.out.println("  rid: " + kemri.getRecipientIdentifier());

            dumpAlgId("  kem", kemri.getKem());
            byte[] kemct = kemri.getKemct().getOctets();
            System.out.println("  kemct length: " + kemct.length);
            Files.write(Paths.get(outDir, "kemct.bin"), kemct);

            dumpAlgId("  kdf", kemri.getKdf());

            // kekLength has no public getter in this BC version; pull it positionally.
            ASN1Sequence kemSeq = ASN1Sequence.getInstance(kemri.toASN1Primitive());
            System.out.println("  KEMRecipientInfo raw field count: " + kemSeq.size());
            for (int i = 0; i < kemSeq.size(); i++) {
                System.out.println("    [" + i + "] " + kemSeq.getObjectAt(i).getClass().getSimpleName()
                        + " = " + kemSeq.getObjectAt(i));
            }

            byte[] ukm = kemri.getUkm();
            System.out.println("  ukm: " + (ukm == null ? "null" : (ukm.length + " bytes: " + toHex(ukm))));

            dumpAlgId("  wrap", kemri.getWrap());
            byte[] wrappedKey = kemri.getEncryptedKey().getOctets();
            System.out.println("  encryptedKey (wrapped CEK) length: " + wrappedKey.length);
            Files.write(Paths.get(outDir, "wrapped_cek.bin"), wrappedKey);

            // RFC 9629 KemOtherInfo ::= SEQUENCE { wrap AlgorithmIdentifier,
            //   kekLength INTEGER, ukm [0] EXPLICIT OCTET STRING OPTIONAL }
            // This is the exact "info" input HKDF-Expand uses; build it with BC
            // rather than hand-rolling DER in Python.
            ASN1Integer kekLength = (ASN1Integer) kemSeq.getObjectAt(5);
            kekLengthOut[0] = kekLength.getValue().intValue();
            ASN1EncodableVector kemOtherInfo = new ASN1EncodableVector();
            kemOtherInfo.add(kemri.getWrap());
            kemOtherInfo.add(kekLength);
            if (ukm != null) {
                kemOtherInfo.add(new org.bouncycastle.asn1.DERTaggedObject(true, 0,
                        new org.bouncycastle.asn1.DEROctetString(ukm)));
            }
            byte[] kdfInfoDer = new DERSequence(kemOtherInfo).getEncoded(ASN1Encoding.DER);
            Files.write(Paths.get(outDir, "kdf_info.der"), kdfInfoDer);
            System.out.println("  kekLength: " + kekLength.getValue());
            System.out.println("  wrote KemOtherInfo (HKDF 'info') to kdf_info.der: " + toHex(kdfInfoDer));

            idx++;
        }

        AlgorithmIdentifier contentEncAlg = ed.getEncryptedContentInfo().getContentEncryptionAlgorithm();
        dumpAlgId("contentEncryptionAlgorithm", contentEncAlg);
        byte[] iv = ((ASN1Encodable) contentEncAlg.getParameters()).toASN1Primitive() instanceof org.bouncycastle.asn1.ASN1OctetString
                ? ((org.bouncycastle.asn1.ASN1OctetString) contentEncAlg.getParameters().toASN1Primitive()).getOctets()
                : new byte[0];
        byte[] encryptedContent = ed.getEncryptedContentInfo().getEncryptedContent().getOctets();
        System.out.println("encryptedContent length: " + encryptedContent.length);
        Files.write(Paths.get(outDir, "encrypted_content.bin"), encryptedContent);

        StringBuilder props = new StringBuilder();
        props.append("content_enc_oid=").append(contentEncAlg.getAlgorithm()).append("\n");
        props.append("content_enc_iv_hex=").append(toHex(iv)).append("\n");
        props.append("kek_length=").append(kekLengthOut[0]).append("\n");
        Files.write(Paths.get(outDir, "metadata.properties"), props.toString().getBytes());

        System.out.println();
        System.out.println("Wrote kemct.bin, wrapped_cek.bin, kdf_info.der, encrypted_content.bin, "
                + "metadata.properties to " + outDir);
    }

    private static void dumpAlgId(String label, AlgorithmIdentifier alg) throws Exception {
        System.out.println(label + " OID: " + alg.getAlgorithm());
        ASN1Encodable params = alg.getParameters();
        if (params == null) {
            System.out.println(label + " params: none");
        } else {
            byte[] paramsDer = params.toASN1Primitive().getEncoded(ASN1Encoding.DER);
            System.out.println(label + " params: " + params + " (DER hex: " + toHex(paramsDer) + ")");
        }
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
