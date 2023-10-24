import boto3
import json
import logging
from custom_encoder import CustomEncoder

# Set up logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize a dynamodb resource and specify the table name

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('DYNAMODB_TABLE_NAME')


def lambda_handler(event, context):

    # Logs the incoming events for debugging

    logger.info(event)

    # Extract the http method and path from the event

    http_method = event['httpMethod']
    path = event['path']

    try:

        # Validate the post and patch requests have a non-empty body

        if http_method in ["POST", "PATCH"] and not event.get('body'):
            raise ValueError('Request body is empty or invalid')

        # Define the routing for the http methods and paths

        routes = {
            ('GET', '/health'): build_response,
            ('GET', '/user'): lambda e: get_user(e['queryStringParameters']['user_id']),
            ('GET', '/users'): lambda e: get_users(e),
            ('POST', '/user'): lambda e: save_user(json.loads(e['body'])),
            ('PATCH', '/user'): lambda e: modify_user(**json.loads(e['body'])),
            ('DELETE', '/user'): lambda e: delete_user(json.loads(e['body'])['user_id'])
        }

        # Route the request to the appropriate function or return an invalid request response

        response = routes.get((http_method, path), invalid_request)(event)

    # Error handling for decoding json, ran into this problem couple times

    except json.JSONDecodeError as r:
        return error_response(str(r), 400)
    except Exception as e:
        logger.exception(e)
        return error_response(str(e))

    return response


# Attempt to retrieve the item from dynamodb, if the item is found return a 200 ok reponse with the item if not it handles the error to returns the exception

def get_user(userid):
    try:
        response = table.get_item(Key={'userid': userid})
        if 'Item' in response:
            return build_response(200, response['Item'])
        return build_response(404, {'message': f'userid: {userid} not found'})
    except Exception as e:
        logger.exception(e)
        return error_response('Error retrieving user.')

# Retrieve all items from the table and log any errors


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


# Tries to save the item to the table and log any errors

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


# tries to update the item on the table by providing the userid key and then the attribute to update with the new value, if any exception rise it will logs it

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


# delete item from the table if given a correct userid otherwise it log the exception

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


# Build a http response

def build_response(status_code=200, body=None):
    response = {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        }
    }
    if body:

        # Use the custom encoder to convert the body to json

        response['body'] = json.dumps(body, cls=CustomEncoder)
    return response


# Build and error http response

def error_response(message, status_code=500):
    return build_response(status_code, {'message': message})

# returns a 400 Bad request response for invalid request


def invalid_request():
    return error_response('Invalid request method', 400)
