package hu.dpc.openbank.apigateway.entities.accounts;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import hu.dpc.common.http.HttpResponse;
import uk.org.openbanking.v3_1_2.commons.Parties;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PartyResponse extends HttpResponse {
    @JsonProperty("Data")
    private Parties parties;

    public Parties getParties() {
        return parties;
    }

    public void setParties(final Parties parties) {
        this.parties = parties;
    }
}
