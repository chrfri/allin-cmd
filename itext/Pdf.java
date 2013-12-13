import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.codec.Base64;
import com.sun.istack.internal.NotNull;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;

public class Pdf {

    private String inputFilePath;
    private String outputFilePath;
    private String pdfPassword;
    private String signReason;
    private String signLocation;
    private String signContact;
    private PdfSignatureAppearance pdfSignatureAppearance;
    private PdfSignature pdfSignature;

    Pdf(@NotNull String inputFilePath,@NotNull String outputFilePath, String pdfPassword, String signReason, String signLocation, String signContact){
        this.inputFilePath = inputFilePath;
        this.outputFilePath = outputFilePath;
        this.pdfPassword = pdfPassword;
        this.signReason = signReason;
        this.signLocation = signLocation;
        this.signContact = signContact;
    }

    public byte[] getPdfHash(@NotNull Calendar signDate, int estimatedSize,@NotNull String hashAlgorithm, boolean isTimestampOnly) throws Exception {

        PdfReader pdfReader = new PdfReader(inputFilePath, pdfPassword != null ? pdfPassword.getBytes() : null);
        AcroFields acroFields = pdfReader.getAcroFields();
        boolean hasSignature = acroFields.getSignatureNames().size() > 0;

        PdfStamper pdfStamper = PdfStamper.createSignature(pdfReader, new FileOutputStream(outputFilePath), '\0', null, hasSignature);
        pdfStamper.setXmpMetadata(pdfReader.getMetadata());

        pdfSignatureAppearance = pdfStamper.getSignatureAppearance();
        pdfSignature = new PdfSignature(PdfName.ADOBE_PPKLITE, isTimestampOnly ? PdfName.ETSI_RFC3161 : PdfName.ADBE_PKCS7_DETACHED);
        pdfSignature.setReason(signReason);
        pdfSignature.setLocation(signLocation);
        pdfSignature.setContact(signContact);
        pdfSignature.setDate(new PdfDate(signDate));
        pdfSignatureAppearance.setCryptoDictionary(pdfSignature);

        HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer>();
        exc.put(PdfName.CONTENTS, new Integer(estimatedSize * 2 + 2));

        pdfSignatureAppearance.preClose(exc);

        MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm);
        try (InputStream rangeStream = pdfSignatureAppearance.getRangeStream()) {
            int i;
            while ((i = rangeStream.read()) != -1)
                messageDigest.update((byte) i);
        }
        return messageDigest.digest();
    }

    /**
     * @param externalSignature
     * @param estimatedSize
     * @throws IOException
     * @throws DocumentException
     */
    private void addSignatureToPdf(@NotNull byte[] externalSignature, int estimatedSize) throws IOException, DocumentException {

        if (estimatedSize < externalSignature.length)
            throw new IOException("Not enough space for signature");

        PdfLiteral pdfLiteral = (PdfLiteral) pdfSignature.get(PdfName.CONTENTS);
        byte[] outc = new byte[(pdfLiteral.getPosLength() -2) /2];

        Arrays.fill(outc, (byte) 0);

        System.arraycopy(externalSignature, 0, outc, 0, externalSignature.length);
        PdfDictionary dic2 = new PdfDictionary();
        dic2.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
        pdfSignatureAppearance.close(dic2);
    }

    /**
     * Decode hash to Base64 and sign PDF
     * @param hash
     * @param estimatedSize
     */
    public void sign(@NotNull String hash, int estimatedSize){
        try {
            addSignatureToPdf(Base64.decode(hash), estimatedSize);
        } catch (UnsupportedEncodingException e) {
            System.out.println("Error when adding hash to pdf");
        } catch (Exception e) {
            System.out.println("Error when adding hash to pdf");
        }
    }


}
