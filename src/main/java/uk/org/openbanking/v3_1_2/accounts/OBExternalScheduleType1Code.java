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

import com.fasterxml.jackson.annotation.JsonCreator;

/**
 * Specifies the scheduled payment date type requested
 */
public enum OBExternalScheduleType1Code {

    ARRIVAL("Arrival"),

    EXECUTION("Execution");

    private String value;

    OBExternalScheduleType1Code(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return String.valueOf(value);
    }

    @JsonCreator
    public static OBExternalScheduleType1Code fromValue(String text) {
        for (OBExternalScheduleType1Code b : OBExternalScheduleType1Code.values()) {
            if (String.valueOf(b.value).equals(text)) {
                return b;
            }
        }
        throw new IllegalArgumentException("Unexpected value '" + text + "'");
    }
}

