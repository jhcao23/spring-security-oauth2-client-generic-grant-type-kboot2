package org.springframework.security.oauth2.client.token.auth

import org.springframework.http.HttpHeaders
import org.springframework.security.crypto.codec.Base64
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails
import org.springframework.security.oauth2.common.AuthenticationScheme
import org.springframework.util.MultiValueMap
import org.springframework.util.StringUtils

import java.io.UnsupportedEncodingException

/**
 * Created by jhcao on 2017-03-27.
 */
class GenericClientAuthenticationHandler : ClientAuthenticationHandler {

    var nameClientId = "client_id"            //miniprogram: appid
    var nameClientSecret = "client_secret"    //miniprogram: secret

    fun authenticateTokenRequest(resource: OAuth2ProtectedResourceDetails, form: MultiValueMap<String, String>, headers: HttpHeaders) {

        if (resource.isAuthenticationRequired()) {
            var scheme = AuthenticationScheme.header
            if (resource.getClientAuthenticationScheme() != null) {
                scheme = resource.getClientAuthenticationScheme()
            }

            try {
                var clientSecret = resource.getClientSecret()
                clientSecret = if (clientSecret == null) "" else clientSecret
                when (scheme) {
                    header -> {
                        form.remove(nameClientSecret)
                        headers.add(
                                "Authorization",
                                String.format(
                                        "Basic %s",
                                        String(Base64.encode(String.format("%s:%s", resource.getClientId(),
                                                clientSecret).getBytes("UTF-8")), "UTF-8")))
                    }
                    form, query -> {
                        form.set(nameClientId, resource.getClientId())
                        if (StringUtils.hasText(clientSecret)) {
                            form.set(nameClientSecret, clientSecret)
                        }
                    }
                    else -> throw IllegalStateException(
                            "Default authentication handler doesn't know how to handle scheme: $scheme")
                }
            } catch (e: UnsupportedEncodingException) {
                throw IllegalStateException(e)
            }

        }
    }
}
