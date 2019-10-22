from __future__ import absolute_import, unicode_literals

import json

from django.http import JsonResponse
from django.urls import reverse_lazy
from django.http import HttpResponse
from oauthlib.oauth2.rfc6749.errors import ServerError

from django.views.generic import View

from rest_framework.views import APIView

from jwcrypto import jwk

from .mixins import OAuthLibMixin
from ..settings import oauth2_settings

class ConnectDiscoveryInfoView(View):
    """
    View used to show oidc provider configuration information
    """
    def get(self, request, *args, **kwargs):
        issuer_url = oauth2_settings.OIDC_ISS_ENDPOINT
        data = {
            "issuer": issuer_url,
            "authorization_endpoint": "{}{}".format(issuer_url, reverse_lazy("oauth2_provider:authorize")),
            "token_endpoint": "{}{}".format(issuer_url, reverse_lazy("oauth2_provider:token")),
            "userinfo_endpoint": oauth2_settings.OIDC_USERINFO_ENDPOINT,
            "jwks_uri": "{}{}".format(issuer_url, reverse_lazy("oauth2_provider:jwks-info")),
            "response_types_supported": oauth2_settings.OIDC_RESPONSE_TYPES_SUPPORTED,
            "subject_types_supported": oauth2_settings.OIDC_SUBJECT_TYPES_SUPPORTED,
            "id_token_signing_alg_values_supported": oauth2_settings.OIDC_ID_TOKEN_SIGNING_ALG_VALUES_SUPPORTED,
            "token_endpoint_auth_methods_supported": oauth2_settings.OIDC_TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
        }
        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response


class JwksInfoView(View):
    """
    View used to show oidc json web key set document
    """
    def get(self, request, *args, **kwargs):
        key = jwk.JWK.from_pem(oauth2_settings.OIDC_RSA_PRIVATE_KEY.encode("utf8"))
        data = {
            "keys": [{
                "alg": "RS256",
                "use": "sig",
                "kid": key.thumbprint()
            }]
        }
        data["keys"][0].update(json.loads(key.export_public()))
        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response


class UserInfoView(OAuthLibMixin, APIView):
    server_class = oauth2_settings.OAUTH2_SERVER_CLASS
    validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
    oauthlib_backend_class = oauth2_settings.OAUTH2_BACKEND_CLASS

    """
    View used to show Claims about the authenticated End-User
    """

    def get_userinfo_response(self, request, *args, **kwargs):
        try:
            uri, headers, body, status = self.create_userinfo_response(request)
        except ServerError as error:
            return HttpResponse(content=error, status=error.status_code)
        except Exception as error:
            return HttpResponse(content=error, status=500)

        response = HttpResponse(content=body, status=status)
        for k, v in headers.items():
            response[k] = v
        return response

    def get(self, request, *args, **kwargs):
        return self.get_userinfo_response(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.get_userinfo_response(request, *args, **kwargs)
