from __future__ import absolute_import, unicode_literals

import json

from django.contrib.auth import authenticate, get_user_model
from django.http import JsonResponse
from django.urls import reverse_lazy
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from django.views.generic import View

from rest_framework.views import APIView

from jwcrypto import jwk

from .mixins import OAuthLibMixin
from ..settings import oauth2_settings
from ..models import get_access_token_model, get_application_model

UserModel = get_user_model()
get_access_token_model

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
        if not request.auth.id_token:
            raise ValueError("Missing IDToken")

        token = get_access_token_model().objects.filter(
            token=request.auth.token,
            expires__gt=timezone.now()
        ).order_by('-created').first()

        user = None
        claims = request.auth.id_token.get_claims(check_claims={"iss": oauth2_settings.OIDC_ISS_ENDPOINT})
        if not claims:
            raise ValueError("Invalid IDToken claims")

        if token and token.user_id and claims['sub'] == str(token.user_id):
            user = get_user_model().objects.get(id=token.user_id)

        if user is None:
            raise ValueError("user not found")

        data = {
            'claims': claims,
            'sub': str(user.id),
        }

        if not user.profile_image:
            picture = ''
        else:
            picture = user.profile_image.storage.url(str(user.profile_image))

        for scope in token.scope.split():
            if scope == 'profile':
                data['name'] = user.name
            elif scope == 'email':
                data['email'] = user.email
            elif scope == 'phone':
                data['phone_number'] = user.phone_number
            elif scope == 'picture':
                data['picture'] = picture

        response = JsonResponse(data)
        response["Access-Control-Allow-Origin"] = "*"
        return response

    def get(self, request, *args, **kwargs):
        return self.get_userinfo_response(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.get_userinfo_response(request, *args, **kwargs)
