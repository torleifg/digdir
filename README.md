# Getting Started

## Set Up the Virtual Environment

In the root folder of the project. Start by creating a virtual environment for managing dependencies:

```bash
python -m venv env
```

Activate the virtual environment:

```bash
source env/bin/activate
```

Install requirements:

```bash
pip install -r requirements.txt
```

## Usage

### Selvbetjening

#### Prerequisites

* Test and/or production Self-Service Client (https://docs.digdir.no/maskinporten_sjolvbetjening_api.html#selvbetjening-som-api-konsument)
* Test and/or production PKCS #12 file (Buypass or Commfides)

```sh
mkdir /cert
cp <path>/*.p12 cert/*.p12
```

```python
import digdir, json, uuid

s = digdir.Selvbetjening('config/selvbetjening.ini', 'TEST')

jwt_grant = s.create_jwt_grant()
access_token = s.get_access_token(jwt_grant)

client = s.create_client(access_token, 'client_name', 'scope1 scope2')
client_id = json.loads(client.data.decode('utf-8'))['client_id']

kid = str(uuid.uuid4())
jwks = digdir.create_jwks(kid)

f = open('cert/keyset.jwks', 'w')
f.write(jwks.export())
f.close()

response = s.add_keyset_to_client(access_token, client_id, jwks.export())
```

### Maskinporten

#### Prerequisites

* Test and/or production Maskinporten Client
* Test and/or production JWKS file

```python
import digdir, json

m = digdir.Maskinporten('config/maskinporten.ini', 'TEST')

f = open('cert/keyset.jwks')
jwks = f.read()
f.close()

jwt_grant = m.create_jwt_grant('client_id', 'scope', 'kid', jwks)
access_token = m.get_access_token(jwt_grant)

person = m.get_krr_person(access_token, 'person_id')
```