/*
 * Account and Transaction API Specification
 * Swagger for Account and Transaction API Specification
 *
 * OpenAPI spec version: v3.1.2
 * Contact: ServiceDesk@openbanking.org.uk
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package uk.org.openbanking.v3_1_2.accounts;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

import java.util.Objects;

/**
 * Set of elements used to provide details of a benefit or reward amount for the statement resource.
 */
@ApiModel(description = "Set of elements used to provide details of a benefit or reward amount for the statement resource.")
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaJerseyServerCodegen", date = "2019-07-10T09:14:46.696896+02:00[Europe/Budapest]")
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OBStatement2StatementBenefit {
    @JsonProperty("Type")
    private String type = null;

    @JsonProperty("Amount")
    private OBActiveOrHistoricCurrencyAndAmount3 amount = null;

    public OBStatement2StatementBenefit type(String type) {
        this.type = type;
        return this;
    }

    /**
     * Benefit type, in a coded form.
     *
     * @return type
     **/
    @JsonProperty("Type")
    @ApiModelProperty(value = "Benefit type, in a coded form.")
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public OBStatement2StatementBenefit amount(OBActiveOrHistoricCurrencyAndAmount3 amount) {
        this.amount = amount;
        return this;
    }

    /**
     * Get amount
     *
     * @return amount
     **/
    @JsonProperty("Amount")
    @ApiModelProperty(value = "")
    public OBActiveOrHistoricCurrencyAndAmount3 getAmount() {
        return amount;
    }

    public void setAmount(OBActiveOrHistoricCurrencyAndAmount3 amount) {
        this.amount = amount;
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, amount);
    }

    @Override
    public boolean equals(java.lang.Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        OBStatement2StatementBenefit obStatement2StatementBenefit = (OBStatement2StatementBenefit) o;
        return Objects.equals(this.type, obStatement2StatementBenefit.type) &&
                Objects.equals(this.amount, obStatement2StatementBenefit.amount);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("class OBStatement2StatementBenefit {\n");

        sb.append("    type: ").append(toIndentedString(type)).append("\n");
        sb.append("    amount: ").append(toIndentedString(amount)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Convert the given object to string with each line indented by 4 spaces
     * (except the first line).
     */
    private String toIndentedString(java.lang.Object o) {
        if (o == null) {
            return "null";
        }
        return o.toString().replace("\n", "\n    ");
    }
}
