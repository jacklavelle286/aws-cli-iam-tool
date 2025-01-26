from . import iam_client
from iam import iam_policy
from iam import users


def create_iam_group(group_name):
    try:
        if group_name == "":
            return None
        iam_client.create_group(GroupName=group_name)
        return f"{group_name} successfully created."
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        return f"{e}"


