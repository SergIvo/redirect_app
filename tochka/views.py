import json

from django.http import JsonResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

import httpx
import jwt


def decode_jwt(request_body, jwk_key):
    try:
        webhook_jwt = jwt.JWT().decode(
            message=request_body,
            key=jwk_key,
        )
        return webhook_jwt
    except jwt.exceptions.JWTDecodeError:
        return {'error': 'Wrong encryption key'}


@csrf_exempt
def redirect_fastgen(request):
    if request.method == 'POST':
        body = request.body.decode('utf-8')
        print(body)

        tochka_public_key = json.loads(settings.TOCHKA_PUBLIC_KEY_JSON)
        jwk_key = jwt.jwk_from_dict(tochka_public_key)
        body_decoded = decode_jwt(body, jwk_key)
        if body_decoded.get('error'):
            response = JsonResponse({'ok': False})
            response.status = 400
            return response

        httpx.post(settings.FASTGEN_URL, json=body)
        return JsonResponse({'ok': True})
    else:
        return JsonResponse({'ok': True})
