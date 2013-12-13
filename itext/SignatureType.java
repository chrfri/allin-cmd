public enum SignatureType {

    CMS("urn:ietf:rfc:3369"),
    TIMESTAMP("urn:ietf:rfc:3161");

    private String signatureType;

    SignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    public String getSignatureType() {
        return this.signatureType;
    }

}
