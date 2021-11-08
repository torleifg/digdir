import base64
import json
import jwt
import uuid
import urllib3
import configparser
from datetime import datetime, timedelta
from jwcrypto import jwk
from cryptography.hazmat.primitives import serialization
import cryptography.hazmat.primitives.serialization.pkcs12


class Base:
    def __init__(self, config_file, config_section):
        config = configparser.ConfigParser()
        config.read(config_file)
        self.environment = config[config_section]

        self.http = urllib3.PoolManager()
        request = self.http.request('GET', self.environment['WellKnownEndpoint'])
        self.well_known = json.loads(request.data.decode('utf-8'))


class Selvbetjening(Base):
    def __init__(self, config_file, config_section):
        super().__init__(config_file, config_section)

        with open(self.environment['Keystore'], 'rb') as file:
            (
                private_key,
                certificate,
                additional_certificates,
            ) = serialization.pkcs12.load_key_and_certificates(
                file.read(), self.environment['KeystorePassword'].encode()
            )

            self.private_key = private_key

            self.certificate = base64.b64encode(certificate.public_bytes(
                encoding=serialization.Encoding.DER
            )).decode('ascii')

    def create_jwt_grant(self):
        current_timestamp = datetime.utcnow()

        jwt_grant = jwt.encode(
            payload={
                'aud': self.well_known['issuer'],
                'iss': self.environment['Client'],
                'iat': current_timestamp,
                'exp': current_timestamp + timedelta(seconds=120),
                'jti': str(uuid.uuid4()),
                'scope': self.environment['Scope']
            },
            key=self.private_key,
            algorithm='RS256',
            headers={
                'x5c': [self.certificate]
            }
        )

        return jwt_grant

    def get_access_token(self, jwt_grant):
        request = self.http.request_encode_body(
            method='POST',
            url=self.well_known['token_endpoint'],
            fields={
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': jwt_grant
            },
            encode_multipart=False,
        )

        return json.loads(request.data.decode('utf-8'))

    def create_client(self, access_token, client_name, scopes):
        body = {
            'integration_type': 'maskinporten',
            'application_type': 'web',
            'client_name': client_name,
            'description': 'Ny integrasjon...',
            'token_endpoint_auth_method': 'private_key_jwt',
            'grant_types': [
                'urn:ietf:params:oauth:grant-type:jwt-bearer'
            ],
            'scopes': scopes.split()
        }

        request = self.http.request(
            method='POST',
            url=self.environment['ClientEndpoint'],
            body=json.dumps(body).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + access_token
            }
        )

        return json.loads(request.data.decode('utf-8'))

    def add_keyset_to_client(self, access_token, client_id, keyset):
        request = self.http.request(
            method='POST',
            url=self.environment['ClientKeysEndpoint'].format(client=client_id),
            body=keyset.export(private_keys=False),
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + access_token
            }
        )

        return json.loads(request.data.decode('utf-8'))


class Maskinporten(Base):
    def __init__(self, config_file, config_section):
        super().__init__(config_file, config_section)

    def create_jwt_grant(self, client_id, scope, kid, jwks):
        keyset = jwk.JWKSet.from_json(jwks.export())
        key = jwk.JWK.from_json(keyset.get_key(kid).export())

        current_timestamp = datetime.utcnow()

        jwt_grant = jwt.encode(
            payload={
                'aud': self.well_known['issuer'],
                'iss': client_id,
                'iat': current_timestamp,
                'exp': current_timestamp + timedelta(seconds=120),
                'jti': str(uuid.uuid4()),
                'scope': scope
            },
            key=key.export_to_pem(private_key=True, password=None),
            algorithm='RS256',
            headers={
                'kid': kid
            }
        )

        return jwt_grant

    def get_access_token(self, jwt_grant):
        request = self.http.request_encode_body(
            method='POST',
            url=self.well_known['token_endpoint'],
            fields={
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': jwt_grant
            },
            encode_multipart=False,
        )

        return json.loads(request.data.decode('utf-8'))

    def get_krr_person(self, access_token, person_id):
        body = {
            'personidentifikatorer': person_id.split()
        }

        request = self.http.request(
            method='POST',
            url=self.environment['KrrEndpoint'],
            body=json.dumps(body).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + access_token
            }
        )

        return json.loads(request.data.decode('utf-8'))


def create_jwks(kid):
    key = jwk.JWK.generate(
        kty='RSA',
        use='sig',
        kid=kid,
        alg='RS256',
        size=2048)

    keys = jwk.JWKSet()
    keys.add(key)

    return keys
