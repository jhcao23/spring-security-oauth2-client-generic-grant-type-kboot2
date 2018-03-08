package org.springframework.security.oauth2.client.token.grant.client

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails

/**
 * Created by jhcao on 2017-03-27.
 */
class GenericClientCredentialsResourceDetails(grantTypeName: String) : BaseOAuth2ProtectedResourceDetails() {

    val isClientOnly: Boolean
        @Override
        get() = true

    init {
        setGrantType(grantTypeName)
    }

}
