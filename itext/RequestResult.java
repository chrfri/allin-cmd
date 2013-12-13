public enum RequestResult {

    Pending("urn:oasis:names:tc:dss:1.0:profiles:asynchronousprocessing:resultmajor:Pending"),
    Success("urn:oasis:names:tc:dss:1.0:resultmajor:Success");

    private String resultUrn;

    RequestResult(String urn) {
        this.resultUrn = urn;
    }

    public String getResultUrn(){
        return this.resultUrn;
    }
}
