import base64
import json
import math
import re
import uuid
from asyncio import exceptions
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from flask import Flask, jsonify, request, Response
from azure.cosmos import CosmosClient
from azure.storage.blob import BlobServiceClient
from PIL import Image
from io import BytesIO
import pyscrypt
import hmac
import hashlib
import secrets
import time
import os
import random
import string
from azure.core.exceptions import AzureError
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from werkzeug.utils import secure_filename

app = Flask(__name__)

# Your Cosmos DB connection details
URL = 'https://fye.documents.azure.com:443/'
KEY = '3mRNX6IKinLF9GzU8KgHmuwtCbe8aikiwgj1coLaBQ7VzwVJZsn1Zezwfv7DpiQo0jJR0ZMcbaQSACDbaUwIGQ=='
DATABASE_NAME = 'fyeDb'
CONTAINER_NAME_Volunteer = 'volunteers'
CONTAINER_NAME_Users = 'users'
CONTAINER_NAME_Posts = 'posts'
CONTAINER_NAME_PostsProduction = "postsProduction"
CONTAINER_NAME_UsersProduction = "usersProduction"
CONTAINER_NAME_VolunteerProduction = "volunteerProduction"

CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=fyestorage;AccountKey=1iXz09iW2gU8N54HW4k" \
                    "+4vQMsjxkvhKIyJn7/1rtXMl8fVBWdZI+qO1sXtgymA3Xkj8GqEIfzPOa+AStBBYd2g==;EndpointSuffix=core" \
                    ".windows.net"
CONNECTION_STRING_EMAIL = "endpoint=https://mailingservice.germany.communication.azure.com/;accesskey=XUHUAfdk5EwaKBA+CIySkniXmvA3yXaDhTSTkB3VoMLduaSjHQJOq5vMaVKVFTVEQRONZipfGhNitph27R0PrA=="
CONTAINER_NAME_IMAGE = "fye"
BASE_URL = "https://fyestorage.blob.core.windows.net/fye/"
EXTENSIONS = [".jpg", ".png"]
MAX_WORKERS = 20
ALLOWED_MIME_TYPES = {'video/mp4', 'image/jpeg', 'image/png'}
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'mp4'}

# Create a ThreadPoolExecutor instance
executor = ThreadPoolExecutor(max_workers=5)

client = CosmosClient(URL, credential=KEY)
database = client.get_database_client(DATABASE_NAME)
container_users = database.get_container_client(CONTAINER_NAME_Users)
container_volunteer = database.get_container_client(CONTAINER_NAME_Volunteer)
container_posts = database.get_container_client(CONTAINER_NAME_Posts)

container_usersProduction = database.get_container_client(CONTAINER_NAME_UsersProduction)
container_volunteerProduction = database.get_container_client(CONTAINER_NAME_VolunteerProduction)
container_postsProduction = database.get_container_client(CONTAINER_NAME_PostsProduction)

volunteer = "ch5gldb3TYWP4RCygkdzRV:APA91bGl-iJ0GIkDHHzPcQkZ" \
            "-WBTA3EqmBPZvX3MH5Lr28W46U3SwA1mjFaMPkqGX68nc5QMAySRNW4oAlyIIngNrAaPsQKnRa3lUvWt22qiUR34Afj2ojBVguJG7k3b5ImlfOoGwDR6"
# user = "dFb4CpFKBUqWqMgUKkzpUC:APA91bHkRKB1NTCud1_q8w_GwcxM9bhX1bei99kjBnHJg7-Q1BetaqhjxToqpQEgo3Y_sBj8eeaYfPly08Sza-rTyrPjM4uBwI5AwKRldXabwpKzy4tyNNdJmTTu0jPfbMXdc5sCZuYm"
# user = "f8FXwtggiU8gv5xOxFfj3v:APA91bFLDlglY2ur8VKK9OJ8ZYp8svUyFVHdZ8PSPHlK-nmyqzDqJgVbIwr0QlpWFUYgLkDCUkGjymIfvS0z6Ih1EiA4kJlnI71KRDi0EPhXrah2BpZxnIKUBNTxgoM1C2RDhdMFz0KM"
user = "edrmxCr3a0ztnEf_87_1oI:APA91bEJbdkzLAlINAtw" \
       "-LeL1Z8uimKPhZmHKXyVyjSR7CxQPpOnW_hKKiE9ecS1G05gfIZhMODMwKeBxWSymm3-EbYKRCwMvQCGE4bmAsLasNRwx" \
       "-E72kvqvVBBuG85MddGJ5xzAuBN"


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def sort_key(item):
    # Return a very old date for None values to push them to the end
    return item[1]['date'] if item[1]['date'] is not None else "1900-01-01 00:00:00.000000 UTC"


def generate_salt(length=16):
    """Generate a random salt."""
    # The os.urandom function generates random bytes suitable for cryptographic use.
    # The number of bytes is specified by the 'length' parameter.
    salt = os.urandom(length)
    return salt.hex()


def generate_token(email):
    # current time to set the expiration
    timestamp = str(int(time.time()))
    email = email.split("@")[0]
    msg = email + '|' + timestamp
    SECRET_KEY = secrets.token_bytes(64)
    # Create HMAC object
    hmac_obj = hmac.new(SECRET_KEY, msg.encode(),
                        hashlib.sha256)
    hmac_signature = hmac_obj.hexdigest()

    # Creating the token by concatenating username, timestamp, and signature
    token = base64.b64encode(f"{email}|{timestamp}|{hmac_signature}".encode()).decode()
    return token


def get_user_posts_by_token(token):
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    item_user = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    user_all_posts = {'path': [], 'favorite': [], 'date': [], 'aiComment': [], 'volunteerComment': [], "title": [],
                      "language": [], "posts": []}

    if item_user:
        for post in item_user[0]["posts"]:
            user_all_posts['path'].append(post['name'])

        user_all_posts["language"] = item_user[0]["activeDevice"]["language"]

        query_post = "SELECT * FROM c WHERE c.author.name = '{}'".format(item_user[0]["__key__"]["name"])
        post_user = list(container_posts.query_items(query=query_post, enable_cross_partition_query=True))

        # Create a dictionary to store the data for matching paths
        path_data = {}

        for item in post_user:
            key = item["__key__"]["name"]
            if key in user_all_posts['path']:
                path_data[key] = {
                    'date': item['date'],
                    'aiComment': item["images"]["d_0"]['aiComment'],
                    'volunteerComment': item["images"]["d_0"]['volunteerComment'],
                    'title': item["title"],
                    'favorite': item["favorite"]
                }

        # Filter out elements where the key doesn't exist in path_data
        user_all_posts['path'] = [key for key in user_all_posts['path'] if key in path_data]
        user_all_posts['date'] = [path_data[key]['date'] for key in user_all_posts['path']]
        user_all_posts['aiComment'] = [path_data[key]['aiComment'] for key in user_all_posts['path']]
        user_all_posts['volunteerComment'] = [path_data[key]['volunteerComment'] for key in user_all_posts['path']]
        user_all_posts['title'] = [path_data[key]['title'] for key in user_all_posts['path']]
        user_all_posts['favorite'] = [path_data[key]['favorite'] for key in user_all_posts['path']]

    return user_all_posts


def get_user_posts_by_id(user_id):
    # Query the user's data using the provided ID
    query = "SELECT * FROM c WHERE c.__key__.name = '{}'".format(user_id)
    item_post = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    user_all_posts = {'favorite': [], 'date': [], 'aiComment': [], 'volunteerComment': [], "title": [], "content": [],
                      "images": {}, "volunteerAIReview": "", "userAIReview": ""}

    for post in item_post:
        user_all_posts['date'].append(post['date'])
        user_all_posts['aiComment'].append(post["images"]["d_0"]['aiComment'])
        user_all_posts['volunteerComment'].append(post["images"]["d_0"]['volunteerComment'])
        user_all_posts['title'].append(post["title"])
        user_all_posts['images'] = post["images"]
        user_all_posts["favorite"] = post["favorite"]
        user_all_posts["volunteerAIReview"] = post["volunteerAIReview"]
        user_all_posts["userAIReview"] = post["userAIReview"]

        # If volunteerComment is not null, add it to content. Otherwise, add aiComment
        if post["images"]["d_0"]['volunteerComment']:
            user_all_posts['content'].append(post["images"]["d_0"]['volunteerComment'])
        else:
            user_all_posts['content'].append(post["images"]["d_0"]['aiComment'])

    return user_all_posts


# will add favorite and images

def transform_and_sort_posts(posts_data):
    transformed_data = {
        key: {
            'favorite': posts_data['favorite'][i] if i < len(posts_data['date']) else None,
            'date': posts_data['date'][i] if i < len(posts_data['date']) else None,
            'volunteerComment': posts_data['volunteerComment'][i] if i < len(posts_data['volunteerComment']) else None,
            'title': posts_data['title'][i] if i < len(posts_data['title']) else None
        }
        for i, key in enumerate(posts_data['path'])
    }

    # Sort the transformed_data dictionary by the 'date' field
    sorted_data = dict(sorted(transformed_data.items(), key=sort_key, reverse=True))

    return sorted_data


def create_uid(user_id=None):
    user_id = str(uuid.uuid4()) if user_id is None else user_id
    return user_id


def send_email(from_email, to_email, subject, content):
    try:
        # Prepare the email data
        message = Mail(
            from_email=from_email,
            to_emails=to_email,
            subject=subject,
            html_content=content)

        # Set up SendGrid client with the API key from environment variable
        sg = SendGridAPIClient(os.environ.get('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'))

        # Send the email
        response = sg.send(message)

        # You can print the status code and headers for debugging
        print(response.status_code)
        print(response.headers)

        return response

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    password = data.get("password")
    email = data.get("email")

    if not email or not password:
        return jsonify(error="Invalid input"), 400

    # user_data = container_users.find_one({"username": username})
    user_query = f"SELECT * FROM c WHERE c.email = '{email}'"
    user_data = list(container_users.query_items(query=user_query, enable_cross_partition_query=True))

    if not user_data:
        return jsonify(error="User not found"), 404

    stored_hash = user_data[0]["passwordHash"]
    password_bytes = password.encode('utf-8')

    if stored_hash == "":
        salt = generate_salt(16)
        salt_bytes = salt.encode('utf-8')
        computed_hash = pyscrypt.hash(password=password_bytes,
                                      salt=salt_bytes,
                                      N=1024, r=8, p=1, dkLen=256)
        computed_hash_hex = computed_hash.hex()
        token = generate_token(email)
        user_data[0]["activeDevice"]["token"] = token
        user_data[0]["passwordHash"] = computed_hash_hex
        user_data[0]["salt"] = salt
        container_users.upsert_item(user_data[0]),
        return jsonify(message="Login successful", token=token)

    salt = user_data[0]["salt"]
    salt_bytes = salt.encode("utf-8")
    computed_hash = pyscrypt.hash(password=password_bytes,
                                  salt=salt_bytes,
                                  N=1024, r=8, p=1, dkLen=256)
    computed_hash_hex = computed_hash.hex()
    if computed_hash_hex == stored_hash:
        token = generate_token(email)
        user_data[0]["activeDevice"]["token"] = token
        container_users.upsert_item(user_data[0])
        return jsonify(token=token), 200
    else:
        return jsonify(error="Invalid credentials"), 401


@app.route("/socialLogin", methods=['POST'])
def socialLogin():
    data = request.get_json()
    uid = data.get("uid")
    # Query to find users with a non-null uuid field
    query = f"SELECT * FROM c WHERE c.uid = '{uid}'"

    user_data = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    if len(user_data) != 0:
        user_document = user_data[0]
        email = user_document.get("email", "")
        token = generate_token(email)
        container_users.upsert_item(body=user_document)

    volunteer_data = list(container_volunteer.query_items(query=query, enable_cross_partition_query=True))

    if len(volunteer_data) != 0:
        volunteer_document = user_data[0]
        email = volunteer_document.get("email", "")
        token = generate_token(email)
        container_volunteer.upsert_item(body=volunteer_document)

    return jsonify(token), 400


@app.route("/register", methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get("email")
        name = data.get("name")
        phone = data.get("telNo")
        language = data.get("language")
        password = data.get("password")
        descriptor = data.get("descriptor")
        uid = data.get("uid")
        languages = data.get("languages")

        if descriptor == "True":
            email_query = f'SELECT * FROM c WHERE c.email = "{email}"'
            existing_volunteer = list(container_volunteer.query_items(
                query=email_query,
                enable_cross_partition_query=True  # Enable querying over all logical partitions
            ))

            if existing_volunteer:
                return jsonify({"error": "A volunteer with this email already exists."}), 400
        else:
            # Check if user already exists
            email_query = f'SELECT * FROM c WHERE c.email = "{email}"'
            existing_users = list(container_users.query_items(
                query=email_query,
                enable_cross_partition_query=True  # Enable querying over all logical partitions
            ))

            if existing_users:
                return jsonify({"error": "A user with this email already exists."}), 400

        # If user does not exist, proceed with registration
        password_bytes = password.encode('utf-8')
        salt = generate_salt(16)
        salt_bytes = salt.encode('utf-8')
        computed_hash = pyscrypt.hash(password=password_bytes, salt=salt_bytes, N=1024, r=8, p=1, dkLen=256)
        computed_hash_hex = computed_hash.hex()
        token = generate_token(email)
        if not uid:
            id = create_uid()
        else:
            id = uid

        user_document = {
            "id": id,
            "email": email,
            "name": name,
            "telNo": phone,
            "overallScore": "0",
            "postScoreTotal": "0",
            "descriptedScoreTotal": "0",
            "version": "1.0.1",
            "salt": salt,
            "passwordHash": computed_hash_hex,
            "uid": id,
            "activeDevice": {
                "language": language,
                "token": token
            },
            "status": "false",  # Consider using boolean False
            "languages": [],
            "posts": [],
            "kvkk": True,
            "kam": True,
            "descriptor": descriptor
        }

        if descriptor == "True":
            user_document["__key__"] = {"path": f'"volunteer", "{id}"',
                                        "kind": "volunteer",
                                        "name": id}
            user_document["languages"] = languages
            container_volunteer.upsert_item(body=user_document)
            return jsonify({"message": "Volunteer registered successfully!", "token": token}), 201
        else:
            user_document["__key__"] = {"path": f'"users", "{id}"',
                                        "kind": "users",
                                        "name": id}
            container_users.upsert_item(body=user_document)
            return jsonify({"message": "User registered successfully!", "token": token}), 201

    except exceptions.CosmosHttpResponseError as e:
        # Handle specific database exceptions
        return jsonify({"error": str(e)}), 400

    except Exception as e:
        # General exception handling
        return jsonify({"error": str(e)}), 400


# display last 10 posts for app
@app.route('/displayPosts', methods=['GET'])
def get_tenPosts():
    token = request.headers.get("Authorization")[7:]
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    user_all_posts = get_user_posts_by_token(token)
    transformed_data = transform_and_sort_posts(user_all_posts)
    # if date is null ise almasak mi?

    # Fetch the last 10 image paths from user_all_posts['path']
    last_10_image_paths = list(transformed_data.keys())
    for path in last_10_image_paths:
        image_path_without_extension = "storage/images/" + path
        transformed_data[path]['image_data'] = fetch_images_as_path(image_path_without_extension)

    desired_format = []
    for key, value in transformed_data.items():
        if value.get('image_data'):
            img_data = {
                "0": value['image_data'][0] if value.get('image_data') else None
            }
            entry = {
                "date": value['date'],
                "favorite": value['favorite'],
                "Id": key,
                "image_data": img_data
            }
            desired_format.append(entry)

    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'data': desired_format[start:end],
        'current_page': page,
        'per_page': per_page,
        'total_items': len(desired_format),
        "total_pages": math.ceil(len(desired_format) / per_page)
    })


@app.route('/deletePost', methods=['DELETE'])
def delete_post():
    try:
        # Retrieve post_id from request
        post_id = request.json.get("post_id")

        if not post_id:
            return jsonify({"error": "Post ID is required"}), 400

        # Query to find the post using post_id
        posts_query = f"SELECT * FROM c WHERE c.__key__.name = '{post_id}'"
        posts_items = list(container_postsProduction.query_items(query=posts_query, enable_cross_partition_query=True))

        # Check if post is found
        if not posts_items:
            return jsonify({"error": "Post not found"}), 404

        # Delete the post
        container_postsProduction.delete_item(item=posts_items[0], partition_key=posts_items[0]['id'])

        return jsonify({"success": f"Post {post_id} has been deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/deleteUser', methods=['DELETE'])
def delete_user():
    try:
        # Retrieve token from request
        token = request.headers.get("Authorization")[7:]

        # Query to find the user using token
        user_query = f"SELECT * FROM c WHERE c.activeDevice.token = '{token}'"
        user_items = list(container_users.query_items(query=user_query, enable_cross_partition_query=True))

        # Check if user is found
        if not user_items:
            return jsonify({"error": "User not found"}), 404

        # Extract post ids from user_items
        post_ids = [post['name'] for post in user_items[0]["posts"]]

        # Delete the user
        container_users.delete_item(item=user_items[0], partition_key=user_items[0]['id'])

        # Iterate through each post id and delete related posts
        for post_id in post_ids:
            # Query to find posts linked with the post's ID and delete them
            posts_query = f"SELECT * FROM c WHERE c.__key__.name = '{post_id}'"
            posts_items = list(
                container_posts.query_items(query=posts_query, enable_cross_partition_query=True))

            for post in posts_items:
                container_postsProduction.delete_item(item=posts_items[0], partition_key=posts_items[0]['id'])

        return jsonify({"success": f"User and related posts have been deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/allPosts', methods=['GET'])
def get_allPosts():
    token = request.headers.get("Authorization")[7:]
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    user_all_posts = get_user_posts_by_token(token)
    transformed_data = transform_and_sort_posts(user_all_posts)

    # Fetch all available image paths for each post
    for path in transformed_data.keys():
        image_path_without_extension = "storage/images/" + path
        transformed_data[path]['image_data'] = fetch_images_as_path(image_path_without_extension)

    desired_format = []
    for key, value in transformed_data.items():
        if value.get('image_data'):
            img_data = {}
            for idx, img_path in enumerate(value.get('image_data', [])):
                img_data[str(idx)] = img_path

            entry = {
                "date": value['date'],
                "favorite": value['favorite'],
                "Id": key,
                "image_data": img_data
            }
            desired_format.append(entry)

    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'data': desired_format[start:end],
        'current_page': page,
        'per_page': per_page,
        'total_items': len(desired_format),
        "total_pages": math.ceil(len(desired_format) / per_page)
    })


@app.route('/favoritePosts', methods=['GET'])
def get_favoritePosts():
    token = request.headers.get("Authorization")[7:]
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    user_all_posts = get_user_posts_by_token(token)
    transformed_data = transform_and_sort_posts(user_all_posts)

    favorites_posts = {k: v for k, v in transformed_data.items() if v['favorite']}

    # Fetch all available image paths for each favorite post
    for path, data in favorites_posts.items():
        image_path_without_extension = "storage/images/" + path
        data['image_data'] = fetch_images_as_path(image_path_without_extension)

    desired_format = []
    for key, value in favorites_posts.items():
        img_data = {}
        for idx, img_path in enumerate(value.get('image_data', [])):
            img_data[str(idx)] = img_path

        entry = {
            "date": value['date'],
            "favorite": value['favorite'],
            "Id": key,
            "image_data": img_data
        }
        desired_format.append(entry)

    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'data': desired_format[start:end],
        'current_page': page,
        'per_page': per_page,
        'total_items': len(desired_format),
        "total_pages": math.ceil(len(desired_format) / per_page)
    })


@app.route("/updateFavorite", methods=['POST'])
def update_favoritePosts():
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_id = parsed_data.get('id')
    received_favorite = parsed_data.get("favorite")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.__key__.name = '{}'".format(received_id)
    items = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    if items:
        item = items[0]
        item["favorite"] = received_favorite
        container_posts.replace_item(item, item)
        response_message = "Updated successfully"
    else:
        response_message = f"No document found with id: {received_id}"

    return jsonify(response_message)


@app.route('/sendEmail', methods=['POST'])
def email_endpoint():
    data = request.get_json()

    # Check if required data is available
    if not data or 'from_email' not in data or 'subject' not in data or 'content' not in data:
        return jsonify({'error': 'Bad Request', 'message': 'Missing parameters'}), 400

    # Send the email using the function
    response = send_email(
        from_email=data['from_email'],
        to_email='info@fromyoureyes.com',  # replace with your company's email
        subject=data['subject'],
        content=data['content']
    )

    if response and response.status_code == 202:
        return jsonify({'success': True, 'message': 'Email sent successfully'}), 200
    else:
        return jsonify({'success': False, 'message': 'Email failed to send'}), 500


# More configurations and potentially more routes...


@app.route("/updateTitle", methods=['POST'])
def update_titlePosts():
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_id = parsed_data.get('id')
    received_favorite = parsed_data.get("title")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.__key__.name = '{}'".format(received_id)
    items = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    if items:
        item = items[0]
        item["title"] = received_favorite
        container_posts.replace_item(item, item)
        response_message = "Updated successfully"
    else:
        response_message = f"No document found with id: {received_id}"

    return jsonify(response_message)


@app.route("/changeEmail", methods=['POST'])
def change_Email():
    token = request.headers.get("Authorization")[7:]
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_Email = parsed_data.get("email")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    if items:
        item = items[0]
        item["email"] = received_Email
        container_posts.replace_item(item, item)
        response_message = "Updated successfully"
    else:
        response_message = f"No document found with id: {received_Email}"

    return jsonify(response_message)


@app.route("/changePhone", methods=['POST'])
def change_Phone():
    token = request.headers.get("Authorization")[7:]
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_telNo = parsed_data.get("telNo")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    if items:
        item = items[0]
        item["telNo"] = received_telNo
        container_posts.replace_item(item, item)
        response_message = "Updated successfully"
    else:
        response_message = f"No document found with id: {received_telNo}"

    return jsonify(response_message)


@app.route("/changeName", methods=['POST'])
def change_Name():
    token = request.headers.get("Authorization")[7:]
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_name = parsed_data.get("name")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    if items:
        item = items[0]
        item["name"] = received_name
        container_posts.replace_item(item, item)
        response_message = "Updated successfully"
    else:
        response_message = f"No document found with id: {received_name}"

    return jsonify(response_message)


@app.route("/changePassword", methods=['POST'])
def change_Password():
    token = request.headers.get("Authorization")[7:]
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_oldPassword = parsed_data.get("oldPassword")
    received_NewPassword = parsed_data.get("newPassword")

    # Query the Cosmos DB to retrieve the document
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    salt = items[0]["salt"]
    salt_bytes = salt.encode("utf-8")
    passwordHash = items[0]["passwordHash"]
    password_bytes = received_oldPassword.encode('utf-8')
    computed_hash = pyscrypt.hash(password=password_bytes, salt=salt_bytes, N=1024, r=8, p=1, dkLen=256)
    computed_hash_hex = computed_hash.hex()
    if passwordHash == computed_hash_hex:
        item = items[0]
        password_bytes_new = received_NewPassword.encode("utf-8")
        computed_hash_new = pyscrypt.hash(password=password_bytes_new, salt=salt_bytes, N=1024, r=8, p=1, dkLen=256)

        # Convert the new hash to a hexadecimal string format
        computed_hash_new_hex = computed_hash_new.hex()

        item["passwordHash"] = computed_hash_new_hex  # storing the hex string instead of bytes
        container_users.replace_item(item["id"],
                                     item)  # It's recommended to use 'item["id"]' to specify the document to replace
        response_message = "Password updated successfully"
    else:
        response_message = "Incorrect current password provided."

    return jsonify(response_message)


@app.route("/updateScore", methods=['POST'])
def update_score():
    token = request.headers.get("Authorization")[7:]
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_point = parsed_data.get("point")

    # Try to find the token in users container first
    query_users = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items_users = list(container_users.query_items(query=query_users, enable_cross_partition_query=True))

    # If found in users container, update the score
    if items_users:
        item = items_users[0]
        item["overallScore"] = int(item.get("overallScore", 0)) + int(received_point)
        item["overallScore"] = str(item["overallScore"])
        container_users.replace_item(item["id"], item)
        response_message = "Updated successfully in users"
        return jsonify(response_message)

    # If not found in users, try to find in volunteers container
    query_volunteers = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)
    items_volunteers = list(container_volunteer.query_items(query=query_volunteers, enable_cross_partition_query=True))

    # If found in volunteers container, update the score
    if items_volunteers:
        item = items_volunteers[0]
        item["overallScore"] = int(item.get("overallScore", 0)) + int(received_point)
        item["overallScore"] = str(item["overallScore"])
        container_volunteer.replace_item(item["id"], item)
        response_message = "Updated successfully in volunteers"
        return jsonify(response_message)

    # If not found in both containers
    response_message = f"No document found with token: {token}"
    return jsonify(response_message)


@app.route('/descriptorPosts', methods=['GET'])
def get_descriptorPosts():
    token = request.headers.get("Authorization")[7:]
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    user_all_posts = get_user_posts_by_token(token)
    transformed_data = transform_and_sort_posts(user_all_posts)
    descriptor_data = {key: value for key, value in transformed_data.items() if value.get('volunteerComment')}

    for path, data in descriptor_data.items():
        image_path_without_extension = "storage/images/" + path
        data['image_data'] = fetch_images_as_path(image_path_without_extension)

    for key in descriptor_data:
        if "aiComment" in descriptor_data[key]:
            del descriptor_data[key]["aiComment"]

    desired_format = []
    for key, value in descriptor_data.items():
        if not value.get('image_data'):
            img_data = None
        else:
            img_data = {
                "0": value['image_data'][0] if value.get('image_data') else None
            }
        entry = {
            "date": value['date'],
            "Id": key,
            "image_data": img_data,
            "favorite": value["favorite"]
        }
        desired_format.append(entry)

    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'data': desired_format[start:end],
        'current_page': page,
        'per_page': per_page,
        'total_items': len(desired_format),
        "total_pages": math.ceil(len(desired_format) / per_page)
    })


@app.route("/filteredPost", methods=["POST"])
def filteredPosts():
    token = request.headers.get("Authorization")[7:]
    user_all_posts = get_user_posts_by_token(token)
    decoded_data = request.data.decode('utf-8')
    parsed_data = json.loads(decoded_data)
    received_id = parsed_data.get("id")

    user_posts = get_user_posts_by_id(received_id)
    # Check if the post with received_id belongs to the user with the token
    if received_id not in user_all_posts['path']:
        return jsonify(error="Post with given ID does not exist or doesn't belong to the user"), 404

    # Transformed data structure
    transformed_data = {
        'date': user_posts['date'][0] if user_posts['date'] else None,
        'favorite': user_posts["favorite"],
        'Id': received_id,
        'content': [],
        'title': user_posts["title"][0],
        "userAIReview": user_posts["userAIReview"],
        "volunteerAIReview": user_posts["volunteerAIReview"]
    }
    image_path_without_extension = "storage/images/" + transformed_data["Id"]
    list_of_images = {"images": fetch_images_as_path(image_path_without_extension)}

    output = []

    # Function to extract the numeric part from the key
    def key_sort_order(key_string):
        match = re.match(r'd_(\d+)', key_string)
        return int(match.group(1)) if match else float('inf')

    # Extract keys from 'images', sort them by the numeric part
    sorted_keys = sorted(user_posts['images'].keys(), key=key_sort_order)

    # Extract language from user_all_posts
    language = user_all_posts.get('language', None)

    for key in sorted_keys:
        value = user_posts['images'][key]
        comment_data = {}
        # Check if value is structured as expected
        print(f"Value for {key}:", value)
        if value:
            if value.get('volunteerComment') is not None:
                comment_data['text'] = value['volunteerComment']
                comment_data['volunteer'] = True
            elif value.get('aiComment') is not None:
                if language and value['aiComment'].get(language):
                    comment_data['text'] = value['aiComment'][language]
                    comment_data['volunteer'] = False
                else:
                    comment_data['text'] = "don't have aiComment in desired language"
                    comment_data['volunteer'] = False
            output.append(comment_data)

    list_of_images = list_of_images["images"]
    min_length = min(len(list_of_images), len(output))

    content = [
        {
            "image": list_of_images[i],
            "text": output[i].get('text', ''),  # use get method with a default value
            "volunteer": output[i].get('volunteer', False),  # default to False if not found
        }
        for i in range(min_length)
    ]

    # Add a new field 'hasReview' to each content item
    # Extracting 'volunteerAIReview' and 'userAIReview' from 'user_posts'
    volunteerAIReview = user_posts.get("volunteerAIReview")
    userAIReview = user_posts.get("userAIReview")
    # Check if either 'volunteerAIReview' or 'userAIReview' is not null
    hasReview = volunteerAIReview is not None or userAIReview is not None
    transformed_data["content"] = content
    transformed_data["hasReview"] = hasReview

    # ... [Code for processing images and content] ...

    # No need to add 'hasReview', 'userAIReview', or 'volunteerAIReview' to individual content items

    # ... [Rest of your code for creating response] ...

    # Final structure of 'transformed_data' is ready to be returned
    return jsonify(transformed_data)

    # Now, your 'transformed_data' dictionary is ready with the modifications you wanted.
    # 'indent=4' is for pretty-printing
    transformed_data["date"] = transformed_data["date"][0]
    return jsonify(transformed_data)


@app.route('/titledPosts', methods=['GET'])
def get_titledPosts():
    token = request.headers.get("Authorization")[7:]
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    user_all_posts = get_user_posts_by_token(token)
    transformed_data = transform_and_sort_posts(user_all_posts)

    title_posts = {k: v for k, v in transformed_data.items() if v['title']}
    for path, data in title_posts.items():
        image_path_without_extension = "storage/images/" + path
        data['image_data'] = fetch_images_as_path(image_path_without_extension)

    desired_format = []
    for key, value in title_posts.items():
        if not value.get('image_data'):
            img_data = None
        else:
            img_data = {
                "0": value['image_data'][0]
            }
        entry = {
            "date": value['date'],
            "favorite": value['favorite'],
            "Id": key,
            "image_data": img_data,
            "title": value["title"]
        }
        desired_format.append(entry)

    start = (page - 1) * per_page
    end = start + per_page

    return jsonify({
        'data': desired_format[start:end],
        'current_page': page,
        'per_page': per_page,
        'total_items': len(desired_format),
        "total_pages": math.ceil(len(desired_format) / per_page)
    })


def fetch_single_image(blob_service_client, image_path):
    blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME_IMAGE, blob=image_path)
    try:
        blob_data = blob_client.download_blob()

        # Use PIL to open and resize the image
        image = Image.open(BytesIO(blob_data.readall()))

        # Resize the image
        max_width = 200
        aspect_ratio = image.width / image.height
        new_height = int(max_width / aspect_ratio)
        image_resized = image.resize((max_width, new_height))

        # Convert the resized image back to bytes
        buffer = BytesIO()
        image_format = "JPEG" if ".jpg" in image_path else "PNG"
        image_resized.save(buffer, format=image_format)

        return base64.b64encode(buffer.getvalue()).decode('utf-8')
    except Exception as e:
        return None


@app.route('/details', methods=['GET'])
def get_details():
    token = request.headers.get("Authorization")[7:]
    query = "SELECT * FROM c WHERE c.activeDevice.token = '{}'".format(token)

    user_detail = {}
    items = list(container_users.query_items(query=query, enable_cross_partition_query=True))
    descriptor = False
    container = container_users  # Default to users container

    if not items:
        items = list(container_volunteer.query_items(query=query, enable_cross_partition_query=True))
        descriptor = True
        container = container_volunteer  # Update to volunteers container

    if not items:
        return jsonify({"error": "User not found"}), 404

    user_detail['id'] = items[0]["id"]
    user_detail['name'] = items[0]["name"]
    user_detail['email'] = items[0]["email"]
    user_detail["telNo"] = items[0]["telNo"]
    user_detail['version'] = items[0]["version"]
    user_detail['overallScore'] = items[0]["overallScore"]
    user_detail['descriptor'] = descriptor

    if descriptor:
        user_detail['languages'] = items[0]["languages"]

    # Get all scores from the appropriate container
    query_all_scores = "SELECT c.overallScore FROM c"
    all_scores = [item['overallScore'] for item in
                  container.query_items(query=query_all_scores, enable_cross_partition_query=True)]

    user_score = user_detail.get('overallScore', 0) or 0  # Default to 0 if it's None or not found
    rank = sum(1 for score in all_scores if score and score > user_score) + 1  # 1-based rank
    user_detail['rank'] = rank
    user_detail["badges"] = ["Acemi, Çaylak", "Azimli", "Haftanın betimleyicisi"]

    return jsonify(user_detail)


@app.route('/leaderboard_users', methods=['GET'])
def get_leaderboard_users():
    # Query to fetch top 10 users by point from container_users
    query_users = "SELECT TOP 10 c.firstName, c.overallScore FROM c ORDER BY c.point DESC"
    top_users = list(container_users.query_items(query=query_users, enable_cross_partition_query=True))

    # # Query to fetch top 10 volunteers by point from container_volunteers
    # query_volunteers = "SELECT c.firstName, c.point FROM c ORDER BY c.point DESC TOP 10"
    # top_volunteers = list(container_volunteer.query_items(query=query_volunteers, enable_cross_partition_query=True))

    # Combine and sort both lists by point, then get the top 10
    # combined_list = top_users + top_volunteers
    sorted_list = sorted(top_users, key=lambda x: x['overallScore'], reverse=True)[:10]

    return jsonify(sorted_list)


@app.route('/leaderboard_volunteers', methods=['GET'])
def get_leaderboard_volunteers():
    # Query to fetch top 10 users by point from container_users
    query_users = "SELECT TOP 10 c.firstName, c.overallScore FROM c ORDER BY c.point DESC"
    top_users = list(container_volunteer.query_items(query=query_users, enable_cross_partition_query=True))

    # # Query to fetch top 10 volunteers by point from container_volunteers
    # query_volunteers = "SELECT c.firstName, c.point FROM c ORDER BY c.point DESC TOP 10"
    # top_volunteers = list(container_volunteer.query_items(query=query_volunteers, enable_cross_partition_query=True))

    # Combine and sort both lists by point, then get the top 10
    # combined_list = top_users + top_volunteers
    sorted_list = sorted(top_users, key=lambda x: x['overallScore'], reverse=True)[:10]

    return jsonify(sorted_list)


def check_blob_exists(blob_service_client, path):
    blob_client = blob_service_client.get_blob_client(container=CONTAINER_NAME_IMAGE, blob=path)
    return blob_client.exists()


def fetch_images_as_path(image_path_without_extension):
    blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)
    existing_paths = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for i in range(10):
            futures = []
            for ext in EXTENSIONS:
                path = f"{image_path_without_extension}/{i}{ext}"
                future = executor.submit(check_blob_exists, blob_service_client, path)
                futures.append((path, future))
            image_found_for_current_index = False
            for path, future in futures:
                if future.result():
                    full_path = BASE_URL + path
                    existing_paths.append(full_path)
                    image_found_for_current_index = True
                    break
            if not image_found_for_current_index:
                break
    return existing_paths


# def ensure_container_exists(container_name):
#     try:
#         # Create the BlobServiceClient object which will be used to create a container client
#         blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)
#
#         # Create a unique name for the container (or use the one you've intended to interact with)
#         container_client = blob_service_client.get_container_client(container_name)
#
#         # Create the container if it doesn't exist
#         container_client.create_container()
#
#     except Exception as ex:
#         if ex.error_code == 'ContainerAlreadyExists':
#             print("Container already exists. Proceeding with operations.")
#         else:
#             raise  # An error occurred, the details are in the exception message.


# This method uploads files to the specified container in Azure Blob Storage
def upload_file_to_blob_storage(folder_name, file_stream, filename, file_type='image'):
    try:
        # Create the BlobServiceClient object which will be used to create a container client
        blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)

        # Set the destination path on the blob storage
        if file_type == 'image':
            blob_name = f"storage/images/{folder_name}/{filename}"  # Path for images
            container_name = CONTAINER_NAME_IMAGE
        elif file_type == 'video':
            blob_name = f"storage/images/{folder_name}/{filename}"  # Path for videos
            container_name = CONTAINER_NAME_IMAGE  # You should define this constant for your video container
        else:
            raise ValueError(f"Unsupported file type: {file_type}")

        # Get the blob client with the provided path
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

        # Upload the content to the blob
        blob_client.upload_blob(file_stream, blob_type="BlockBlob",
                                overwrite=True)  # Overwrite parameter is set to True to allow replacing existing files

    except AzureError as azure_exception:
        print('Exception occurred while handling blob storage:')
        print(azure_exception)
        raise  # Re-throwing the exception, so the caller function can handle it as needed
    except Exception as ex:
        print('An unexpected error occurred:')
        print(ex)
        raise  # Re-throwing this as well, as it's an unexpected state


@app.route('/uploadImages', methods=['POST'])
def upload_images():
    try:
        token = request.headers.get("Authorization")[7:]

        # Initial status
        is_user, is_volunteer = False, False

        date = str(datetime.utcnow()) + " UTC",
        # Create a unique folder name for this upload batch
        folder_name = generate_custom_id()

        # Query the 'users' container
        user_query = f"SELECT * FROM c WHERE c.activeDevice.token = '{token}'"
        user_items = list(container_users.query_items(query=user_query, enable_cross_partition_query=True))
        if user_items:
            is_user = True  # Token is found in users container
            user_detail = user_items[0]  # Extract user details if needed

            # Prepare new post data
            new_post = {
                "name": folder_name,
                "path": f'"users", "{folder_name}"',  # Adjust as needed if this formatting is specific
                "kind": "posts"
            }

            # Append new post to the user's posts list
            if "posts" in user_detail:
                user_detail["posts"].append(new_post)
            else:
                user_detail["posts"] = [new_post]

            # Update the user detail in the database with the new posts list
            container_users.replace_item(item=user_detail["id"], body=user_detail)
            # Create a new post entity in the "posts" container
            # Example data for a post
            post_data = {
                "author": {"name": user_detail["__key__"]["name"],
                           "kind": "user"
                           },
                "date": date,
                "images": {},
                "assignedVolunteer": None,
                "lastResponse": None,
                "resolveTime": None,
                "resolved": None,
                "userAIReview": None,
                "score": None,
                "volunteerReview": None,
                "commercial": "false",
                "userRequest": None,
                "overallScore": None,
                "title": None,
                "volunteerAIReview": None,
                "favorite": False,
                "id": create_uid(),
                "__key__": {
                    "name": "",
                    "path": "",
                    "name": "",
                    "kind": "posts"
                }
                # ...
            }
            # create_post_entity(container_posts, post_data)

        # If not found in 'users', check in 'volunteers'
        if not is_user:
            volunteer_query = f"SELECT * FROM c WHERE c.activeDevice.token = '{token}'"
            volunteer_items = list(
                container_volunteer.query_items(query=volunteer_query, enable_cross_partition_query=True))
            if volunteer_items:
                is_volunteer = True  # Token is found in volunteers container
                volunteer_detail = volunteer_items[0]  # Extract volunteer details if needed

                # Prepare new post data
                new_post = {
                    "name": folder_name,
                    "path": f'"volunteers", "{folder_name}"',  # Adjust as needed if this formatting is specific,
                    "kind": "posts"
                }

                # Append new post to the volunteer's posts list
                if "posts" in volunteer_detail:
                    volunteer_detail["posts"].append(new_post)
                else:
                    volunteer_detail["posts"] = [new_post]

                # Update the volunteer detail in the database with the new posts list
                container_volunteer.replace_item(item=volunteer_detail["id"], body=volunteer_detail)
                # Example data for a post
                post_data = {
                    "author": {"name": user_detail["__key__"]["name"],
                               "kind": "volunteer"
                               },
                    "date": date,
                    "images": {},
                    "assignedVolunteer": None,
                    "lastResponse": None,
                    "resolveTime": None,
                    "resolved": None,
                    "userAIReview": None,
                    "score": None,
                    "volunteerReview": None,
                    "commercial": "false",
                    "userRequest": None,
                    "overallScore": None,
                    "title": None,
                    "volunteerAIReview": None,
                    "favorite": False,
                    "id": create_uid(),
                    "__key__": {
                        "name": "",
                        "path": "",
                        "name": "",
                        "kind": "posts"
                    }
                    # ...
                }
                # # Create a new post entity in the "posts" container
                # create_post_entity(container_posts, post_data)

                # New dictionaries for images and videos

        images = {}
        videos = {}
        image_paths = []
        video_paths = []
        files = request.files.getlist('images')
        # If user does not select file, browser submits an empty part without filename
        if not files or files[0].filename == '':
            return jsonify(error="No selected file"), 400

        for file in files:
            # Check the MIME type of the file
            if file.content_type not in ALLOWED_MIME_TYPES:
                print(f"File skipped: {file.filename}, unsupported MIME type: {file.content_type}")
                continue  # Skip this file

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_extension = filename.rsplit('.', 1)[1].lower()

                # Distinguish between image and video files
                if file_extension in ['jpg', 'jpeg', 'png']:
                    image_paths.append(filename)
                    upload_file_to_blob_storage(folder_name, file.stream, filename)  # Image upload
                elif file_extension == 'mp4':
                    video_paths.append(filename)
                    upload_file_to_blob_storage(folder_name, file.stream,
                                                filename)  # Video upload (same function can be used if it supports streaming)

        # Populate the 'images' and 'videos' field with appropriate data
        for i, image_path in enumerate(image_paths):
            key = f"d_{i}"
            images[key] = {
                "imagePath": "images/" + folder_name + "/" + image_path,
                # Add other image-related fields here
                "aiComment": "",
                "volunteerComment": ""
            }

        for i, video_path in enumerate(video_paths):
            key = f"v_{i}"
            videos[key] = {
                "videoPath": "videos/" + folder_name + "/" + video_path,
                # Add other video-related fields here
            }

        post_data["images"] = images
        post_data["videos"] = videos
        post_data["__key__"]["name"] = folder_name
        post_data["__key__"]["kind"] = "post"
        post_data["__key__"]["path"] = f'"users", "{folder_name}"'
        create_post_entity(container_posts, post_data)

        return jsonify(success=True, folder_id=folder_name), 201

    except Exception as e:
        # Ideally log the error here
        return jsonify(error=str(e)), 500


@app.route('/uploadPostScore', methods=['POST'])
def upload_postScore():
    data = request.get_json()
    received_point = data.get("postPoint")
    received_id = data.get("id")
    received_AI = data.get("AI")

    query = "SELECT * FROM c WHERE c.__key__.name = '{}'".format(received_id)
    item_post = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    if received_AI == "true":
        item_post[0]["userAIReview"] = received_point
        container_posts.upsert_item(item_post[0])
    else:
        item_post[0]["volunteerAIReview"] = received_point
        container_posts.upsert_item(item_post[0])

    return jsonify("Successfully updated!"), 200


@app.route("/uidCheck", methods=["POST"])
def uid_check():
    data = request.get_json()
    received_uid = data.get("uid")
    query = "SELECT * FROM c WHERE c.uid = '{}'".format(received_uid)
    user_post = list(container_users.query_items(query=query, enable_cross_partition_query=True))

    if user_post:
        return jsonify(True)
    else:
        return jsonify(False)


@app.route("/descriptorUpdate", methods=["POST"])
def descriptorUpdate():
    try:
        # Parse data from the received JSON
        data = request.get_json()
        received_postId = data.get("post_id")
        received_images = data.get("images")  # This should be a list of image names

        # Query the database to get the post
        query = f"SELECT * FROM c WHERE c.__key__.name = '{received_postId}'"
        user_posts = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

        if not user_posts:
            return jsonify(success=False, message="No post found with the provided ID"), 404

        # Assuming there's only one post with the given postId, otherwise you need to handle multiple posts
        user_post = user_posts[0]

        descriptor_flag = False  # This flag will determine the value of 'descriptorPosts'

        # Process the 'images' field of the post, comparing with 'received_images' and updating 'descriptorReview' flags
        if 'images' in user_post:
            for key, image_info in user_post['images'].items():
                # Extract the image name from the 'imagePath'
                image_name_with_extension = image_info['imagePath'].split('/')[
                    -1]  # Assuming the name is the last part of the path
                image_name = os.path.splitext(image_name_with_extension)[0]  # Remove the file extension

                # Compare with received images and update the 'sendtoDescriptor' flag
                if image_name in received_images:
                    image_info['sendtoDescriptor'] = True
                    descriptor_flag = True  # If any image is sent to the descriptor, set the flag
                else:
                    image_info['sendtoDescriptor'] = False

            # Set 'descriptorPosts' based on the flag's value after checking all images
            user_post['descriptorPosts'] = descriptor_flag

            # Update the post in the database
            container_posts.upsert_item(user_post)

            return jsonify(success=True, message="Post images updated successfully"), 200
        else:
            return jsonify(success=False, message="'images' field does not exist on the target post"), 400

    except Exception as e:
        # For production code, consider logging the actual error for debugging.
        return jsonify(success=False, message=f"An error occurred while updating the post: {str(e)}"), 500


def fetch_descriptor_images_as_path(image_base_path):
    # Here, we are assuming that 'image_base_path' is the path of the image without the extension
    # and we need to check for each possible extension whether the blob exists.
    blob_service_client = BlobServiceClient.from_connection_string(CONNECTION_STRING)
    existing_paths = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for ext in EXTENSIONS:
            path = f"{image_base_path}{ext}"  # Constructing the full path with each extension
            future = executor.submit(check_blob_exists, blob_service_client, path)
            futures.append((path, future))
        for path, future in futures:
            if future.result():  # If the blob exists, we get the result here
                full_path = BASE_URL + path  # Constructing the full URL
                existing_paths.append(full_path)
                # Assuming we only need one valid path per image base path
                break

    return existing_paths


@app.route("/randomDescriptorImages", methods=["GET"])
def randomDescriptorImages():
    # ... (setup for your Azure Cosmos DB and other initial code remains the same)

    query = "SELECT * FROM c WHERE c.descriptorPosts = true"
    all_images = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    valid_image_urls = []
    for item in all_images:
        if 'images' in item:
            images = item['images']
            for image in images.values():
                if image.get('sendtoDescriptor'):
                    image_base_path = "storage/" + image['imagePath'].rsplit('.', 1)[0]  # Get path without extension
                    full_image_paths = fetch_descriptor_images_as_path(image_base_path)
                    valid_image_urls.extend(full_image_paths)

    # Selecting up to 4 random image URLs from the list of valid images
    selected_image_urls = random.sample(valid_image_urls, min(len(valid_image_urls), 4))

    # Prepare the response object
    response = {
        "images": selected_image_urls
    }

    return jsonify(response)


# def extract_id(url):
#     """
#     Extracts a unique ID from a URL.
#
#     This function uses a regular expression to identify the alphanumeric ID
#     typically found in URLs. The regular expression looks for a long string
#     of uppercase letters and numbers. This part can be adjusted based on
#     the specific format of the IDs you're working with.
#
#     Parameters:
#     url (str): The URL containing the unique ID.
#
#     Returns:
#     str: The extracted ID.
#     """
#
#     # Regular expression pattern to identify the ID.
#     # This pattern is for IDs consisting of uppercase letters and numbers.
#     # Adjust based on your needs.
#     pattern = r'([A-Z0-9]{20,})'
#
#     # Search for the pattern in the URL
#     match = re.search(pattern, url)
#
#     # If a match is found, return it. Otherwise, return None.
#     if match:
#         return match.group(1)
#     else:
#         return None

@app.route("/responseDescriptor", methods=["POST"])
def responseDescriptor():
    data = request.get_json()
    received_image = data.get("images")
    received_text = data.get("text")

    # Extracting the post ID and the image index from the received image URL
    received_image_postId = received_image.split("/")[-2]
    received_imageNameIndex = received_image.split("/")[-1].split(".")[0]

    # Query the database to get the post data based on the post ID
    query = f"SELECT * FROM c WHERE c.__key__.name = '{received_image_postId}'"
    descripterImage_documents = list(container_posts.query_items(query=query, enable_cross_partition_query=True))

    if descripterImage_documents:
        descripterImage = descripterImage_documents[0]

        # Construct the expected image path you want to verify
        expected_image_path = f"images/{received_image_postId}/{received_imageNameIndex}.jpg"

        # Check all images in the 'images' field of the document
        for image_key, image_info in descripterImage.get("images", {}).items():
            if image_info.get("imagePath") == expected_image_path:
                # The image path matches one of the entries in the document
                image_info['volunteerComment'] = received_text
                image_info["sendtoDescriptor"] = False

                # Now, we check if all 'sendtoDescriptor' are False, then we'll update 'descriptorPosts'
                all_sent = all(not img.get("sendtoDescriptor") for img in descripterImage.get("images", {}).values())

                if all_sent:
                    descripterImage["descriptorPosts"] = False

                try:
                    # Update the document in the database
                    updated_item = container_posts.replace_item(item=descripterImage['id'], body=descripterImage)
                except exceptions.CosmosHttpResponseError as e:
                    return jsonify(success=False, message=f"An error occurred: {e.message}")

                return jsonify(success=True, message="Image path exists in the document.", data=image_info)

        # If the loop completes, the image path was not found in the document
        return jsonify(success=False, message="Image path does not exist in the document.")
    else:
        # Handle the case where no document was found for the provided post ID
        return jsonify(success=False, message="No document found with the provided post ID.")


def generate_custom_id(length=32):
    """Generate a random string of letters and digits."""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for i in range(length))


def create_post_entity(container, post_data):
    # Insert the new post entity into the "posts" container
    container.create_item(body=post_data)


if __name__ == "__main__":
    app.run(host='0.0.0.0',port=5001, debug=True)
