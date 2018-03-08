package org.springframework.security.oauth2.client.token.grant.client

import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException
import org.springframework.security.oauth2.client.token.AccessTokenProvider
import org.springframework.security.oauth2.client.token.AccessTokenRequest
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport
import org.springframework.security.oauth2.common.OAuth2AccessToken
import org.springframework.security.oauth2.common.OAuth2RefreshToken
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap

/**
 * Provider for obtaining an oauth2 access token by using client credentials.
 *
 * @author Dave Syer
 */
class GenericClientCredentialsAccessTokenProvider : OAuth2AccessTokenSupport, AccessTokenProvider {

    private var paramNameClientCredentials = "client_credentials"
//    @get:Override
    private var httpMethod = HttpMethod.POST

    override protected fun getHttpMethod(): HttpMethod {
        return this.httpMethod
    }

    constructor(paramNameClientCredentials: String) {
        this.paramNameClientCredentials = paramNameClientCredentials
    }

    constructor(paramNameClientCredentials: String, httpMethod: HttpMethod) {
        this.paramNameClientCredentials = paramNameClientCredentials
        this.httpMethod = httpMethod
    }

    override fun supportsResource(resource: OAuth2ProtectedResourceDetails): Boolean {
        return resource is GenericClientCredentialsResourceDetails && paramNameClientCredentials.equals(resource.getGrantType())
    }

    override fun supportsRefresh(resource: OAuth2ProtectedResourceDetails): Boolean {
        return false
    }

    @Throws(UserRedirectRequiredException::class)
    override fun refreshAccessToken(resource: OAuth2ProtectedResourceDetails,
                           refreshToken: OAuth2RefreshToken, request: AccessTokenRequest): OAuth2AccessToken? {
        return null
    }

    @Throws(UserRedirectRequiredException::class, AccessDeniedException::class, OAuth2AccessDeniedException::class)
    override fun obtainAccessToken(details: OAuth2ProtectedResourceDetails, request: AccessTokenRequest): OAuth2AccessToken {
        return retrieveToken(request, details, getParametersForTokenRequest(details), HttpHeaders())
    }

    private fun getParametersForTokenRequest(resource: OAuth2ProtectedResourceDetails): MultiValueMap<String, String> {

        val form = LinkedMultiValueMap<String, String>()
        form.set("grant_type", paramNameClientCredentials)

        if (resource.isScoped()) {

            val builder = StringBuilder()
            val scope = resource.getScope()

            if (scope != null) {
                val scopeIt = scope!!.iterator()
                while (scopeIt.hasNext()) {
                    builder.append(scopeIt.next())
                    if (scopeIt.hasNext()) {
                        builder.append(' ')
                    }
                }
            }

            form.set("scope", builder.toString())
        }

        return form

    }

}
