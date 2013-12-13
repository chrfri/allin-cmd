public enum AdditionalProfiles {

    ASYNCHRON("urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing"),
    BATCH("urn:com:swisscom:dss:v1.0:profiles:batchprocessing"),
    ON_DEMAND_CERTIFCATE("urn:com:swisscom:dss:v1.0:profiles:ondemandcertificate"),
    TIMESTAMP("urn:oasis:names:tc:dss:1.0:profiles:timestamping");

    private String profile;

    AdditionalProfiles(String s) {
        this.profile = s;
    }

    public String getProfileName() {
        return this.profile;
    }

}
