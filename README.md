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

https://docs.digdir.no/docs/Maskinporten/maskinporten_sjolvbetjening_api

#### Prerequisites

* Test and/or production Self-Service Client
* Test and/or production PKCS #12 file (Buypass or Commfides)

#### Add certificate

```sh
mkdir /cert
cp <path>/*.p12 cert/*.p12
```

#### Example

```python
import maskinporten, json, uuid

s = maskinporten.Selvbetjening('config/selvbetjening.ini', 'TEST')

jwt_grant = s.create_jwt_grant()
access_token = s.get_access_token(jwt_grant)

client = s.create_client(access_token, 'client_name', 'scope1 scope2')
client_id = json.loads(client.data.decode('utf-8'))['client_id']

kid = str(uuid.uuid4())
jwks = maskinporten.create_jwks(kid)

f = open('cert/keyset.jwks', 'w')
f.write(jwks.export())
f.close()

response = s.add_keyset_to_client(access_token, client_id, jwks.export())
```

### Maskinporten

https://docs.digdir.no/docs/Maskinporten/maskinporten_guide_apikonsument

#### Prerequisites

* Test and/or production Maskinporten Client
* Test and/or production JWKS file

#### Example

```python
import maskinporten, json

m = maskinporten.Maskinporten('config/maskinporten.ini', 'TEST')

f = open('cert/keyset.jwks')
jwks = f.read()
f.close()

jwt_grant = m.create_jwt_grant('client_id', 'scope', 'kid', jwks)
access_token = m.get_access_token(jwt_grant)

person = m.get_krr_person(access_token, 'person_id')

data = json.loads(person.data.decode('utf-8'))
print(data)
```
