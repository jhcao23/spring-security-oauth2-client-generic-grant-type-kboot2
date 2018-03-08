package org.springframework.security.oauth2.client.token.grant.client

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails

/**
 * Created by jhcao on 2017-03-27.
 */
open class GenericClientCredentialsResourceDetails(grantTypeName: String) : BaseOAuth2ProtectedResourceDetails() {

    override fun isClientOnly(): Boolean {
        return false
    }

    init {
        setGrantType(grantTypeName)
    }

}
