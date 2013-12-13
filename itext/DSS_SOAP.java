/**
 * Created:
 * 03.12.13 KW49 14:51
 * </p>
 * Last Modification:
 * 13.12.13 KW 50 14:21
 * </p>
 * **********************************************************************************
 * Sign PDF using Swisscom DSS                                                      *
 * Tested with iText-5.4.5; Bouncy Castle 1.50 and JDK 1.7.0_45                     *
 * For examples see main method. You only need to change variables in this method.  *
 * **********************************************************************************
 */

import com.sun.istack.internal.NotNull;
import com.sun.istack.internal.Nullable;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.net.ssl.HttpsURLConnection;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.*;
import java.io.*;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Calendar;

public class DSS_SOAP {

    private static final String _CLAIMED_IDENTITY_FORMAT = "urn:com:swisscom:dss:v1.0:entity";
    private static final String _CERTIFICATE_REQUEST_PROFILE = "urn:com:swisscom:advanced";
    private static final String _TIMESTAMP_URN = "urn:ietf:rfc:3161";
    private static final String _OCSP_URN = "urn:ietf:rfc:2560";
    private static final String _MOBILE_ID_TYPE = "urn:com:swisscom:auth:mobileid:v1.0";
    private String _privateKeyName;
    private String _serverCert;
    private String _clientCert;
    private String _keyStorePath;
    private String _keyStorePass;
    private String _trustStorePath;
    private String _trustStorePass;
    private boolean _debug;

    /**
     * Constructor
     *
     * @param privateKeyName
     * @param serverCert
     * @param clientCert
     * @param keyStorePath
     * @param keyStorePass
     * @param trustStorePath
     * @param trustStorePass
     * @param debug
     */

    public DSS_SOAP(String privateKeyName, String serverCert, String clientCert, String keyStorePath, String keyStorePass,
                    String trustStorePath, String trustStorePass, boolean debug) {
        this._privateKeyName = privateKeyName;
        this._serverCert = serverCert;
        this._clientCert = clientCert;
        this._keyStorePath = keyStorePath;
        this._keyStorePass = keyStorePass;
        this._trustStorePath = trustStorePath;
        this._trustStorePass = trustStorePass;
        this._debug = debug;
    }

    /**
     * Sign document with on demand certificate and authenticate with mobile id
     *
     * @param pdfs
     * @param signDate
     * @param hashAlgo
     * @param serverURI
     * @param addTimestamp
     * @param addOcsp
     * @param claimedIdentity
     * @param distinguishedName
     * @param phoneNumber
     * @param certReqMsg
     * @param certReqMsgLang
     * @param requestId
     */
    public void signDocumentOnDemandCertMobileId(@NotNull Pdf pdfs[], @NotNull Calendar signDate, @NotNull HashAlgorithm hashAlgo,
                                                 @NotNull String serverURI, boolean addTimestamp, boolean addOcsp, @NotNull String claimedIdentity,
                                                 @NotNull String distinguishedName, @NotNull String phoneNumber, @NotNull String certReqMsg,
                                                 @NotNull String certReqMsgLang, int requestId) throws Exception {

        String[] additionalProfiles;
        if (pdfs.length > 1) {
            additionalProfiles = new String[2];
            additionalProfiles[1] = AdditionalProfiles.BATCH.getProfileName();
        } else
            additionalProfiles = new String[1];
        additionalProfiles[0] = AdditionalProfiles.ON_DEMAND_CERTIFCATE.getProfileName();

        int estimatedSize = getEstimatedSize(addTimestamp, addOcsp, _CERTIFICATE_REQUEST_PROFILE);

        byte[][] pdfHash = new byte[pdfs.length][];
        for (int i = 0; i < pdfs.length; i++) {
            pdfHash[i] = pdfs[i].getPdfHash(signDate, estimatedSize, hashAlgo.getHashAlgorythm(), false);
        }

        SOAPMessage sigReqMsg = createRequestMessage(RequestType.SignRequest, hashAlgo.getHashUri(), _CERTIFICATE_REQUEST_PROFILE,
                pdfHash, addTimestamp ? _TIMESTAMP_URN : null, addOcsp ? _OCSP_URN : null, additionalProfiles, _CLAIMED_IDENTITY_FORMAT,
                claimedIdentity, SignatureType.CMS.getSignatureType(), distinguishedName, _MOBILE_ID_TYPE, phoneNumber,
                certReqMsg, certReqMsgLang, null, requestId);

        signDocumentSync(sigReqMsg, serverURI, pdfs, estimatedSize, "Base64Signature");

    }

    /**
     * Sign document with on demand certificate
     *
     * @param pdfs
     * @param hashAlgo
     * @param signDate
     * @param serverURI
     * @param certRequestProfile
     * @param addTimeStamp
     * @param addOcsp
     * @param distinguishedName
     * @param claimedIdentity
     * @param requestId
     */
    public void signDocumentOnDemandCert(@NotNull Pdf[] pdfs, @NotNull HashAlgorithm hashAlgo, Calendar signDate, @NotNull String serverURI,
                                         @NotNull String certRequestProfile, boolean addTimeStamp, boolean addOcsp,
                                         @NotNull String distinguishedName, @NotNull String claimedIdentity, int requestId) throws Exception {

        String[] additionalProfiles;
        if (pdfs.length > 1) {
            additionalProfiles = new String[2];
            additionalProfiles[1] = AdditionalProfiles.BATCH.getProfileName();
        } else
            additionalProfiles = new String[1];
        additionalProfiles[0] = AdditionalProfiles.ON_DEMAND_CERTIFCATE.getProfileName();

        int estimatedSize = getEstimatedSize(addTimeStamp, addOcsp, certRequestProfile);

        byte[][] pdfHash = new byte[pdfs.length][];
        for (int i = 0; i < pdfs.length; i++) {
            pdfHash[i] = pdfs[i].getPdfHash(signDate, estimatedSize, hashAlgo.getHashAlgorythm(), false);
        }

        SOAPMessage sigReqMsg = createRequestMessage(RequestType.SignRequest, hashAlgo.getHashUri(), certRequestProfile,
                pdfHash, addTimeStamp ? _TIMESTAMP_URN : null, addOcsp ? _OCSP_URN : null, additionalProfiles, _CLAIMED_IDENTITY_FORMAT,
                claimedIdentity, SignatureType.CMS.getSignatureType(), distinguishedName, null, null, null, null, null, requestId);

        signDocumentSync(sigReqMsg, serverURI, pdfs, estimatedSize, "Base64Signature");
    }

    /**
     * Sign document with static cert
     *
     * @param pdfs
     * @param hashAlgo
     * @param signDate
     * @param serverURI
     * @param addTimeStamp
     * @param addOCSP
     * @param claimedIdentity
     * @param requestId
     */
    public void signDocumentStaticCert(@NotNull Pdf[] pdfs, @NotNull HashAlgorithm hashAlgo, Calendar signDate, @NotNull String serverURI,
                                       boolean addTimeStamp, boolean addOCSP, @NotNull String claimedIdentity, int requestId) throws Exception {

        String[] additionalProfiles = null;
        if (pdfs.length > 1) {
            additionalProfiles = new String[1];
            additionalProfiles[0] = AdditionalProfiles.BATCH.getProfileName();
        }

        int estimatedSize = getEstimatedSize(addTimeStamp, addOCSP, null);

        byte[][] pdfHash = new byte[pdfs.length][];
        for (int i = 0; i < pdfs.length; i++) {
            pdfHash[i] = pdfs[i].getPdfHash(signDate, estimatedSize, hashAlgo.getHashAlgorythm(), false);
        }

        SOAPMessage sigReqMsg = createRequestMessage(RequestType.SignRequest, hashAlgo.getHashUri(), null,
                pdfHash, addTimeStamp ? _TIMESTAMP_URN : null, addOCSP ? _OCSP_URN : null, additionalProfiles, _CLAIMED_IDENTITY_FORMAT,
                claimedIdentity, SignatureType.CMS.getSignatureType(), null, null, null, null, null, null, requestId);

        signDocumentSync(sigReqMsg, serverURI, pdfs, estimatedSize, "Base64Signature");
    }

    /**
     * Sign document only with timestamp
     *
     * @param pdfs
     * @param hashAlgo
     * @param signDate
     * @param serverURI
     * @param claimedIdentity
     * @param requestId
     */
    public void signDocumentTimestampOnly(@NotNull Pdf[] pdfs, @NotNull HashAlgorithm hashAlgo, Calendar signDate,
                                          @NotNull String serverURI, @NotNull String claimedIdentity, int requestId) throws Exception {

        SignatureType signatureType = SignatureType.TIMESTAMP;

        String[] additionalProfiles;
        if (pdfs.length > 1) {
            additionalProfiles = new String[2];
            additionalProfiles[1] = AdditionalProfiles.BATCH.getProfileName();
        } else
            additionalProfiles = new String[1];
        additionalProfiles[0] = AdditionalProfiles.TIMESTAMP.getProfileName();

        int estimatedSize = getEstimatedSize(true, true, null);

        byte[][] pdfHash = new byte[pdfs.length][];
        for (int i = 0; i < pdfs.length; i++) {
            pdfHash[i] = pdfs[i].getPdfHash(signDate, estimatedSize, hashAlgo.getHashAlgorythm(), true);
        }

        SOAPMessage sigReqMsg = createRequestMessage(RequestType.SignRequest, hashAlgo.getHashUri(), null,
                pdfHash, null, null, additionalProfiles, _CLAIMED_IDENTITY_FORMAT, claimedIdentity, signatureType.getSignatureType(),
                null, null, null, null, null, null, requestId);

        signDocumentSync(sigReqMsg, serverURI, pdfs, estimatedSize, "RFC3161TimeStampToken");
    }

    /**
     * Sign document synchron
     *
     * @param sigReqMsg
     * @param serverURI
     * @param pdfs
     * @param estimatedSize
     * @param signNodeName
     */
    private void signDocumentSync(@NotNull SOAPMessage sigReqMsg, @NotNull String serverURI, @NotNull Pdf[] pdfs, int estimatedSize, String signNodeName) throws Exception {

        String sigResponse = sendRequest(sigReqMsg, serverURI);

        ArrayList<String> responseResult = getTextFromXmlText(sigResponse, "ResultMajor");

        if (responseResult == null || !RequestResult.Success.getResultUrn().equals(responseResult.get(0)))
            throw new Exception("Getting signatures failed. Result: " + responseResult);

        ArrayList<String> signHashes = getTextFromXmlText(sigResponse, signNodeName);
        signDocuments(signHashes, pdfs, estimatedSize);
    }

    /**
     * Sign document
     *
     * @param signatureList
     * @param pdfs
     * @param estimatedSize
     * @throws Exception
     */
    private void signDocuments(@NotNull ArrayList<String> signatureList, @NotNull Pdf[] pdfs, int estimatedSize) {
        int counter = 0;
        for (String signatureHash : signatureList) {
            pdfs[counter].sign(signatureHash, estimatedSize);
            counter++;
        }
    }

    /**
     * Get nodes text content
     *
     * @param soapResponseText can be a full response as xml
     * @param nodeName
     * @return if nodes with searched node names exist it will return an array list containing text from value from nodes
     */
    @Nullable
    private ArrayList<String> getTextFromXmlText(String soapResponseText, String nodeName) throws Exception {

        Element element = getNodeList(soapResponseText);
        return getNodesFromNodeList(element, nodeName);
    }

    /**
     * Get nodes text content
     *
     * @param element
     * @param nodeName
     * @return if nodes with searched node names exist it will return an array list containing text from value from nodes
     */
    @Nullable
    private ArrayList<String> getNodesFromNodeList(@NotNull Element element, @NotNull String nodeName) {
        ArrayList<String> returnlist = null;
        NodeList nl = element.getElementsByTagName(nodeName);

        for (int i = 0; i < nl.getLength(); i++) {
            if (nodeName.equals(nl.item(i).getNodeName())) {
                if (returnlist == null)
                    returnlist = new ArrayList<>();
                returnlist.add(nl.item(i).getTextContent());
            }

        }
        return returnlist;
    }

    /**
     * Get a XML string as an element
     *
     * @param xmlString
     * @return org.w3c.dom.Element from XML String
     * @throws ParserConfigurationException
     * @throws IOException
     * @throws SAXException
     */
    private Element getNodeList(@NotNull String xmlString) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        ByteArrayInputStream bis = new ByteArrayInputStream(xmlString.getBytes());
        Document doc = db.parse(bis);
        return doc.getDocumentElement();
    }

    /**
     * Create a SOAP message object. Will print the message if debug is set to true
     *
     * @param reqType                  type of request e.g. singing or pending
     * @param digestMethodAlgorithmURL
     * @param certRequestProfile       only necessary when on demand certificate is needed
     * @param hashList                 pdf hashes
     * @param timestampURN             if needed urn of timestamp
     * @param ocspURN                  if needed urn of ocsp
     * @param additionalProfiles
     * @param claimedIdentity
     * @param claimedIdentityFormat
     * @param signatureType            e.g. cms or timestamp
     * @param distinguishedName
     * @param mobileIdType
     * @param phoneNumber              must start with e.g. +41 or +49
     * @param certReqMsg
     * @param certReqMsgLang
     * @param responseId
     * @return
     * @throws SOAPException
     * @throws IOException
     */
    private SOAPMessage createRequestMessage(@NotNull RequestType reqType, @NotNull String digestMethodAlgorithmURL,
                                             String certRequestProfile, @NotNull byte[][] hashList, String timestampURN, String ocspURN,
                                             String[] additionalProfiles, String claimedIdentityFormat, String claimedIdentity,
                                             @NotNull String signatureType, String distinguishedName,
                                             String mobileIdType, String phoneNumber, String certReqMsg, String certReqMsgLang,
                                             String responseId, int requestId) throws SOAPException, IOException {

        MessageFactory messageFactory = MessageFactory.newInstance();
        SOAPMessage soapMessage = messageFactory.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();

        // SOAP Envelope
        SOAPEnvelope envelope = soapPart.getEnvelope();
        envelope.addAttribute(new QName("xmlns"), "urn:oasis:names:tc:dss:1.0:core:schema");
        envelope.addNamespaceDeclaration("dsig", "http://www.w3.org/2000/09/xmldsig#");
        envelope.addNamespaceDeclaration("ns5", "urn:com:swisscom:dss:1.0:schema");
        envelope.addNamespaceDeclaration("ais", "http://service.ais.swisscom.com/");

        // SOAP Body
        SOAPBody soapBody = envelope.getBody();

        SOAPElement signElement = soapBody.addChildElement("sign", "ais");

        SOAPElement requestElement = signElement.addChildElement(reqType.getRequestType());
        requestElement.addAttribute(new QName("Profile"), reqType.getUrn());
        requestElement.addAttribute(new QName("RequestID"), String.valueOf(requestId));
        SOAPElement inputDocumentsElement = requestElement.addChildElement("InputDocuments");

        SOAPElement digestValueElement;
        SOAPElement documentHashElement;
        SOAPElement digestMethodElement;

        for (int i = 0; i < hashList.length; i++) {
            documentHashElement = inputDocumentsElement.addChildElement("DocumentHash");
            if (hashList.length > 1)
                documentHashElement.addAttribute(new QName("ID"), String.valueOf(i));
            digestMethodElement = documentHashElement.addChildElement("DigestMethod", "dsig");
            digestMethodElement.addAttribute(new QName("Algorithm"), digestMethodAlgorithmURL);
            digestValueElement = documentHashElement.addChildElement("DigestValue", "dsig");

            String s = com.itextpdf.text.pdf.codec.Base64.encodeBytes(hashList[i]);
            digestValueElement.addTextNode(s);
        }

        if (timestampURN != null || additionalProfiles != null || ocspURN != null || certRequestProfile != null || claimedIdentity != null || signatureType != null) {
            SOAPElement optionalInputsElement = requestElement.addChildElement("OptionalInputs");

            SOAPElement additionalProfileelement;
            if (additionalProfiles != null)
                for (String additionalProfile : additionalProfiles) {
                    additionalProfileelement = optionalInputsElement.addChildElement("AdditionalProfile");
                    additionalProfileelement.addTextNode(additionalProfile);
                }

            if (claimedIdentity != null && claimedIdentityFormat != null) {
                SOAPElement claimedIdentityElement = optionalInputsElement.addChildElement(new QName("ClaimedIdentity"));
                if (!_CERTIFICATE_REQUEST_PROFILE.equals(certRequestProfile))
                    claimedIdentityElement.addAttribute(new QName("Format"), claimedIdentityFormat);
                SOAPElement claimedIdNameElement = claimedIdentityElement.addChildElement("Name");
                claimedIdNameElement.addTextNode(claimedIdentity);
            }

            if (certRequestProfile != null) {
                SOAPElement certificateRequestElement = optionalInputsElement.addChildElement("CertificateRequest", "ns5");
                if (!_CERTIFICATE_REQUEST_PROFILE.equals(certRequestProfile))
                    certificateRequestElement.addAttribute(new QName("Profile"), certRequestProfile);
                if (distinguishedName != null) {
                    SOAPElement distinguishedNameElement = _CERTIFICATE_REQUEST_PROFILE.equals(certRequestProfile) ?
                            certificateRequestElement.addChildElement("DistinguishedName", "ns5") :
                            certificateRequestElement.addChildElement("DistinguishedName");
                    distinguishedNameElement.addTextNode(distinguishedName);
                    if (phoneNumber != null) {
                        SOAPElement stepUpAuthorisationElement = certificateRequestElement.addChildElement("StepUpAuthorisation", "ns5");

                        if (mobileIdType != null && phoneNumber != null) {
                            SOAPElement mobileIdElement = stepUpAuthorisationElement.addChildElement("MobileID", "ns5");
                            SOAPElement msisdnElement = mobileIdElement.addChildElement("MSISDN", "ns5");
                            msisdnElement.addTextNode(phoneNumber);
                            SOAPElement certReqMsgElement = mobileIdElement.addChildElement("Message", "ns5");
                            certReqMsgElement.addTextNode(certReqMsg);
                            SOAPElement certReqMsgLangElement = mobileIdElement.addChildElement("Language", "ns5");
                            certReqMsgLangElement.addTextNode(certReqMsgLang.toUpperCase());
                        }
                    }
                }
            }

            if (signatureType != null) {
                SOAPElement signatureTypeElement = optionalInputsElement.addChildElement("SignatureType");
                signatureTypeElement.addTextNode(signatureType);
            }

            if (timestampURN != null && !signatureType.equals(_TIMESTAMP_URN)) {
                SOAPElement addTimeStampelemtn = optionalInputsElement.addChildElement("AddTimestamp");
                addTimeStampelemtn.addAttribute(new QName("Type"), timestampURN);
            }

            if (ocspURN != null && !signatureType.equals(_TIMESTAMP_URN)) {
                SOAPElement addOcspElement = optionalInputsElement.addChildElement("AddOcspResponse", "ns5");
                addOcspElement.addAttribute(new QName("Type"), ocspURN);
            }

            if (responseId != null) {
                SOAPElement responseIdElement = optionalInputsElement.addChildElement("ResponseID");
                responseIdElement.addTextNode(responseId);
            }
        }

        soapMessage.saveChanges();

        if (_debug) {
            System.out.print("Request SOAP Message = ");
            ByteArrayOutputStream ba = new ByteArrayOutputStream();
            soapMessage.writeTo(ba);
            String msg = new String(ba.toByteArray()).replaceAll("><", ">\n<");
            System.out.println(msg);
        }

        return soapMessage;
    }

    /**
     * Send request to a server. If debug is set to true it will print response message.
     *
     * @param soapMsg
     * @param urlPath
     * @return Server response as string
     * @throws SOAPException
     * @throws IOException
     */
    @Nullable
    private String sendRequest(@NotNull SOAPMessage soapMsg, @NotNull String urlPath) throws IOException, SOAPException {

        URLConnection conn = new DSSConnection(urlPath, _privateKeyName, _serverCert, _clientCert, _keyStorePath, _trustStorePath,
                _keyStorePass, _trustStorePass, _debug).getConnection();
        if (conn instanceof HttpsURLConnection) {
            ((HttpsURLConnection) conn).setRequestMethod("POST");
        }

        conn.setAllowUserInteraction(true);
        conn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
        conn.setDoOutput(true);

        OutputStreamWriter out = new OutputStreamWriter(conn.getOutputStream());

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        soapMsg.writeTo(baos);
        String msg = baos.toString();

        out.write(msg);
        out.flush();
        if (out != null) {
            out.close();
        }

        String line = "";
        BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

        String response = "";
        while ((line = in.readLine()) != null) {
            response = response + line;
        }
        if (in != null) {
            in.close();
        }

        if (_debug)
            System.out.println("response : " + response.replaceAll("><", ">\n<"));
        return response;
    }

    /**
     * Calculate size of signature
     *
     * @param useTimestmap
     * @param useOcsp
     * @param certRequestProfile
     * @return calculated size of signature as int
     */
    private int getEstimatedSize(boolean useTimestmap, boolean useOcsp, String certRequestProfile) {
        int returnValue = 8192;
        returnValue = useTimestmap ? returnValue + 4192 : returnValue;
        returnValue = useOcsp ? returnValue + 4192 : returnValue;
        returnValue = certRequestProfile != null ? returnValue + 700 : returnValue;
        return returnValue;
    }

    public static void main(String[] args) throws Exception {


        DSS_SOAP dss = new DSS_SOAP("privateKeyName", "abc.swissdigicert.ch.cer", "abc_firma_xy_client_2013-2014.cer",
                "/Users/fritschka/Projekte/SwissCom/swisscom_keystore", "changeit", "/Users/fritschka/Projekte/SwissCom/swisscom_cacerts",
                "changeit", true);

        String serverUri = "https://ais.pre.swissdigicert.ch/DSS-Server/ws";

        String pdfPathIn = "pdf.pdf";
        String outPdfPathStaticCert = "pdf_dss_static_cert.pdf";
        String outPdfPathOnDemandCert = "pdf_dss_ondemand_cert.pdf";
        String outPdfPathTimestampOnly = "pdf_dss_timestamp_only.pdf";
        String outPdfPathMobileId = "pdf_dss_mobile_id.pdf";
        Pdf outPdfStaticCert = new Pdf(pdfPathIn, outPdfPathStaticCert, null, "need authentication", "Bern", "Hans Mueller");
        Pdf outPdfOnDemandCert = new Pdf(pdfPathIn, outPdfPathOnDemandCert, null, "need authentication", "Bern", "Hans Mueller");
        Pdf outPdfTimestampCert = new Pdf(pdfPathIn, outPdfPathTimestampOnly, null, "need authentication", "Bern", "Hans Mueller");
        Pdf outPdfMobileId = new Pdf(pdfPathIn, outPdfPathMobileId, null, "need authentication", "Bern", "Hans Mueller");

        int requestId;

        requestId = (int) (Math.random() * 1000);
        dss.signDocumentStaticCert(new Pdf[]{outPdfStaticCert}, HashAlgorithm.SHA256, Calendar.getInstance(), serverUri,
                true, true, "Firma XY:kp2-firma_xy", requestId);

        requestId = (int) (Math.random() * 1000);
        dss.signDocumentTimestampOnly(new Pdf[]{outPdfTimestampCert}, HashAlgorithm.SHA256, Calendar.getInstance(), serverUri, "Firma XY AG", requestId);

        requestId = (int) (Math.random() * 1000);
        dss.signDocumentOnDemandCert(new Pdf[]{outPdfOnDemandCert}, HashAlgorithm.SHA256, Calendar.getInstance(), serverUri, _CERTIFICATE_REQUEST_PROFILE,
                true, true, "CN=Hans Mueller, O=Fimra XY AG, L=Bern, ST=Bern, C=CH",
                "Firma XY AG:OnDemand-Advanced", requestId);

        requestId = (int) (Math.random() * 1000);
        dss.signDocumentOnDemandCertMobileId(new Pdf[]{outPdfMobileId}, Calendar.getInstance(), HashAlgorithm.SHA256, serverUri, true, true, "ABACUS Research AG:OnDemand-Advanced",
                "CN=Hans Mueller, O=Firma XY AG, L=Bern, ST=Bern, C=CH", "+41123456", "please sign my pdf", "EN", requestId);
    }

}

