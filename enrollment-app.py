import boto3
import json
import logging
from custom_encoder import CustomEncoder

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('DYNAMODB_TABLE_NAME')


def lambda_handler(event, context):
    logger.info(event)

    http_method = event['httpMethod']
    path = event['path']

    try:

        if http_method in ["POST", "PATCH"] and not event.get('body'):
            raise ValueError('Request body is empty or invalid')

        routes = {
            ('GET', '/health'): build_response,
            ('GET', '/user'): lambda e: get_user(e['queryStringParameters']['user_id']),
            ('GET', '/users'): lambda e: get_users(e),
            ('POST', '/user'): lambda e: save_user(json.loads(e['body'])),
            ('PATCH', '/user'): lambda e: modify_user(**json.loads(e['body'])),
            ('DELETE', '/user'): lambda e: delete_user(json.loads(e['body'])['user_id'])
        }

        response = routes.get((http_method, path), invalid_request)(event)

    except json.JSONDecodeError as r:
        return error_response(str(r), 400)
    except Exception as e:
        logger.exception(e)
        return error_response(str(e))

    return response


def get_user(userid):
    try:
        response = table.get_item(Key={'userid': userid})
        if 'Item' in response:
            return build_response(200, response['Item'])
        return build_response(404, {'message': f'userid: {userid} not found'})
    except Exception as e:
        logger.exception(e)
        return error_response('Error retrieving user.')


def get_users(event):
    try:
        response = table.scan()
        result = response['Items']
        while 'LastEvaluatedKey' in response:
            response = table.scan(
                ExclusiveStartKey=response['LastEvaluatedKey'])
            result.extend(response['Items'])
        body = {
            'students': result
        }
        return build_response(200, body)
    except:
        logger.exception('Log it here for now')


def save_user(requestBody):
    try:
        table.put_item(Item=requestBody)
        body = {
            'Operation': 'SAVE',
            'Message': 'SUCCESS',
            'Item': requestBody
        }
        return build_response(200, body)
    except:
        logger.exception('Log it here for now')


def modify_user(userid, updateKey, updateValue):
    try:
        response = table.update_item(
            Key={'userid': userid},
            UpdateExpression='set #k = :value',
            ExpressionAttributeNames={
                '#k': updateKey
            },
            ExpressionAttributeValues={
                ':value': updateValue
            },
            ReturnValues='UPDATED_NEW'
        )
        body = {
            'Operation': 'UPDATE',
            'Message': 'SUCCESS',
            'UpdatedAttribute': response
        }
        return build_response(200, body)
    except:
        logger.exception('Log it here for now')


def delete_user(userid):
    try:
        response = table.delete_item(
            Key={
                'userid': userid
            },
            ReturnValues='ALL_OLD'
        )
        body = {
            'Operation': 'DELETE',
            'Message': 'SUCCESS',
            'deletedItem': response
        }
        return build_response(200, body)
    except:
        logger.exception('Log it here for now')


def build_response(status_code=200, body=None):
    response = {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }
    if body:
        response['body'] = json.dumps(body, cls=CustomEncoder)
    return response


def error_response(message, status_code=500):
    return build_response(status_code, {'message': message})


def invalid_request():
    return error_response('Invalid request method', 400)
