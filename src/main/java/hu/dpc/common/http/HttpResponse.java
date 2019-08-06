package hu.dpc.common.http;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class HttpResponse {
    @JsonIgnore
    private int    httpResponseCode;
    @JsonIgnore
    private String httpRawContent;

    public int getHttpResponseCode() {
        return httpResponseCode;
    }

    public void setHttpResponseCode(final int httpResponseCode) {
        this.httpResponseCode = httpResponseCode;
    }

    public String getHttpRawContent() {
        return httpRawContent;
    }

    public void setHttpRawContent(final String httpRawContent) {
        this.httpRawContent = httpRawContent;
    }
}
