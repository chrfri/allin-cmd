public enum HashAlgorithm {

    SHA256("SHA-256", "http://www.w3.org/2001/04/xmlenc#sha256"),
    SHA384("SHA-384", "http://www.w3.org/2001/04/xmldsig-more#sha384"),
    SHA512("SHA-512", "http://www.w3.org/2001/04/xmlenc#sha512"),
    RIPEMD160("RIPEMD-160", "http://www.w3.org/2001/04/xmlenc#ripemd160");

    private String hashAlgo;
    private String hashUri;

    HashAlgorithm(String hashAlgo, String hashUri) {
        this.hashAlgo = hashAlgo;
        this.hashUri = hashUri;
    }

    public String getHashAlgorythm() {
        return this.hashAlgo;
    }

    public String getHashUri() {
        return this.hashUri;
    }

}
