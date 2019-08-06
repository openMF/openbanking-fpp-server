/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.repository;

import hu.dpc.openbank.fpp.lionfintech.backend.enity.bank.AccountConsent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountConsentRepository extends JpaRepository<AccountConsent, String> {
    /**
     * Get Consent
     *
     * @param bankId
     * @param userName
     * @return
     */
    @Query(value = "select *\n" //
            + "from ACCOUNT_CONSENT \n" //
            + "where BANKID = :bankid\n" //
            + "  and USERNAME = :userName", nativeQuery = true)
    AccountConsent getConsent(@Param("bankid") String bankId, @Param("userName") String userName);
}
