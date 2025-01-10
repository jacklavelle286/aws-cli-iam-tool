# from . import json
# from . import iam_client
# from . import os

import boto3
import json
import os
iam_client = boto3.client("iam")

# TODO
# list iam users
# create iam user
# delete iam user

# interact with iam user:
# list policies
# add, delete policies
# change password
# get access keys
# revoke access keys
# assign MFA
# rotate access keys


def list_iam_users(username=None):
    if username:
        response = iam_client.list_users(username)
        return response
    else:
        response = iam_client.list_users()
        users = response.get('Users', [])
        users_names = [username['UserName'] for username in users]
        return users_names

# list attached polices for users (this will be reused)

# def list_attached_user_policies(username):
#     list_iam_users()
#
# def delete_iam_user(username):
#     response = iam_client.delete_user(
#         UserName=username
#     )
#     return response

user = "sdfs"
list_iam_users(username=user)