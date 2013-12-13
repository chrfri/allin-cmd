public enum RequestType {

    SignRequest("SignRequest", "urn:com:swisscom:dss:v1.0"),
    PendingRequest("PendingRequest", "urn:com:swisscom:dss:v1.0");

    private String urn;
    private String requestType;

    RequestType(String reqType, String urn) {
        this.requestType = reqType;
        this.urn = urn;
    }

    public String getRequestType() {
        return this.requestType;
    }

    public String getUrn(){
        return this.urn;
    }

}
