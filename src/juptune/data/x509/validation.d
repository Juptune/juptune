/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.x509.validation;

import juptune.core.util : Result;
import juptune.data.x509.asn1convert : X509Certificate;

Result x509ValidatePath(
    scope X509Certificate[] certPath,
    scope X509Certificate trustAnchor,
    X509Certificate.Time pointInTimeUtc,
)
{
    return Result.noError;
}