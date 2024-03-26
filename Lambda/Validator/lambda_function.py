import json
import boto3
from botocore.exceptions import ClientError
import hmac
import hashlib
import base64
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

cognito_client = boto3.client('cognito-idp')
ssm_client = boto3.client('ssm')

def get_ssm_parameter(parameter_name):
    try:
        response = ssm_client.get_parameter(
            Name=parameter_name,
            WithDecryption=True
        )
        return response['Parameter']['Value']
    except ClientError as e:
        print(f"Failed to retrieve {parameter_name} from SSM Parameter Store: {e}")
        raise e

def get_secret_hash(username, client_id):
    client_secret = get_ssm_parameter('stablespot-user-pool-client-secret')
    message = username + client_id
    dig = hmac.new(client_secret.encode('UTF-8'), msg=message.encode('UTF-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2

def lambda_handler(event, context):
    try:
        email = event['email']
        password = event['password']
    except KeyError:
        print("'email' or 'password' key is missing from the event object.")
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "An error occurred during event processing"})
        }
    except Exception as e:
        print(f"Error occurred during event processing: {e}")
        return {
            "statusCode": 400,
            "body": json.dumps({"message": "An error occurred during event processing"})
        }

    user_pool_id = get_ssm_parameter('stablespot-user-pool-id')
    client_id = get_ssm_parameter('stablespot-user-pool-client-id')
    try:
        auth_response = cognito_client.admin_initiate_auth(
            UserPoolId=user_pool_id,
            ClientId=client_id,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': get_secret_hash(email, client_id)
            }
        )

        # JWKS URL에서 키 세트 가져오기
        jwks_url = get_ssm_parameter('stablespot-user-pool-keys-url')
        with urllib.request.urlopen(jwks_url) as jwks_response:
            jwks = json.loads(jwks_response.read().decode())

        # ID 토큰 검증
        id_token = auth_response['AuthenticationResult']['IdToken']
        headers = jwt.get_unverified_headers(id_token)
        key_index = -1
        
        # 공개키 찾기
        for i in range(len(jwks['keys'])):
            if jwks['keys'][i]['kid'] == headers['kid']:
                key_index = i
                break
        
        if key_index == -1:
            print('Could not find the specified key.')
            return {
                'statusCode': 500,
                'body': json.dumps({'message': 'The signing key could not be found'})
            }
        
        # 서명 검증
        public_key = jwk.construct(jwks['keys'][key_index])
        message, encoded_signature = id_token.rsplit('.', 1)
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        
        if not public_key.verify(message.encode("utf8"), decoded_signature):
            print('Signature verification failed.')
            return {
                'statusCode': 500,
                'body': json.dumps({'message': 'Could not verify the signature'})
            }
        
        # 로그인 성공 응답
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'message': 'Successfully logged in.',
                'data': {
                    'id_token': id_token,
                    'access_token':
                    auth_response['AuthenticationResult']['AccessToken']
                }
            })
        }
    except ClientError as e:
        # 로그인 실패 응답
        print(f"Login failed: {e}")
        return {
            'statusCode': 400,
            'body': json.dumps({
                'success': False,
                'message': f"Login failed: {e.response['Error']['Message']}"
            })
        }
