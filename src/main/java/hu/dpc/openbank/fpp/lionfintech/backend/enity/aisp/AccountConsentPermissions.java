/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 * https://mozilla.org/MPL/2.0/.
 */

package hu.dpc.openbank.fpp.lionfintech.backend.enity.aisp;

import uk.org.openbanking.v3_1_2.accounts.OBReadConsentResponse1Data;

import java.util.Arrays;
import java.util.List;

public class AccountConsentPermissions {
    public static final List<OBReadConsentResponse1Data.PermissionsEnum> PERMISSIONS = Arrays
            .asList(OBReadConsentResponse1Data.PermissionsEnum.READACCOUNTSDETAIL,
                    OBReadConsentResponse1Data.PermissionsEnum.READBALANCES,
                    OBReadConsentResponse1Data.PermissionsEnum.READBENEFICIARIESDETAIL,
                    OBReadConsentResponse1Data.PermissionsEnum.READDIRECTDEBITS,
                    OBReadConsentResponse1Data.PermissionsEnum.READPRODUCTS,
                    OBReadConsentResponse1Data.PermissionsEnum.READSTANDINGORDERSDETAIL,
                    OBReadConsentResponse1Data.PermissionsEnum.READTRANSACTIONSCREDITS,
                    OBReadConsentResponse1Data.PermissionsEnum.READTRANSACTIONSDEBITS,
                    OBReadConsentResponse1Data.PermissionsEnum.READTRANSACTIONSDETAIL,
                    OBReadConsentResponse1Data.PermissionsEnum.READOFFERS,
                    OBReadConsentResponse1Data.PermissionsEnum.READPAN,
                    OBReadConsentResponse1Data.PermissionsEnum.READPARTY,
                    OBReadConsentResponse1Data.PermissionsEnum.READPARTYPSU,
                    OBReadConsentResponse1Data.PermissionsEnum.READSCHEDULEDPAYMENTSDETAIL,
                    OBReadConsentResponse1Data.PermissionsEnum.READSTATEMENTSDETAIL);

}
