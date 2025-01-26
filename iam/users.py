from . import iam_client
from iam import iam_policy


def create_iam_user(username):
    try:
        if username == "":
            return None
        iam_client.create_user(UserName=username)
        return f"Successfully created user:{username}"
    except iam_client.exceptions.LimitExceededException as e:
        return f"Limit exceeded: {e}"
    except iam_client.exceptions.EntityAlreadyExistsException as e:
        return f"IAM User already exists: {e}"
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No such entity exists: {e}"
    except iam_client.exceptions.InvalidInputException as e:
        return f"Invalid input: {e}"
    except iam_client.exceptions.ConcurrentModificationException as e:
        return f"Concurrent modification: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure: {e}"


def attach_user_policy(username, policy_arn):
    try:
        iam_client.attach_user_policy(UserName=username, PolicyArn=policy_arn)
        return f"Succesfully attached policy: {policy_arn}"
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No Such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate Limit exceeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failed: {e}")
        return None
    except iam_client.exceptions.InvalidInputException as e:
        print(f"Invalid input exception: {e}")
        return None
    except iam_client.exceptions.PolicyNotAttachableException as e:
        print(f"Policy not attachable: {e}")
        return None

class NoUsersFoundException(Exception):
    """Exception raised when no IAM users are found."""
    pass


def list_iam_users():
    try:
        response = iam_client.list_users()
        users = response.get("Users", [])
        user_list = [user['UserName'] for user in users]
        if not user_list:
            raise NoUsersFoundException("No IAM users found in the account.")
        return user_list
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failed: {e}. Try again later.")
        return []



def list_attached_managed_user_policies(username):
    try:
        attached_managed_policies_response = iam_client.list_attached_user_policies(UserName=username)
        attached_managed_policies = attached_managed_policies_response.get("AttachedPolicies", [])

        if not attached_managed_policies:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No managed policies attached"}},
                operation_name="ListAttachedUserPolicies"
            )

        attached_managed = [policy["PolicyName"] for policy in attached_managed_policies]
        return attached_managed
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No policies attached to {username}: {e}"
    except iam_client.exceptions.InvalidInputException as e:
        return f"Invalid input: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure, try again later: {e}"


def list_attached_inline_user_policies(username):
    try:
        attached_inline_policies_response = iam_client.list_user_policies(UserName=username)
        attached_inline_policies = attached_inline_policies_response.get("PolicyNames", [])
        if not attached_inline_policies:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No inline policies attached"}},
                operation_name="ListAttachedUserPolicies"
            )
        return attached_inline_policies

    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No policies attached to {username}: {e}"
    except iam_client.exceptions.InvalidInputException as e:
        return f"Invalid input: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure, try again later: {e}"


def delete_user_policy(username, policy_name):
    try:
        iam_client.delete_user_policy(UserName=username, PolicyName=policy_name)
        return f"successfully deleted {policy_name}"
    except iam_client.exceptions.NoSuchEntityException as e:
        return "No Such entity: {e}"
    except iam_client.exceptions.LimitExceededException as e:
        return f"Rate Limit exceeded: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failed: {e}"

def list_access_keys(username):
    try:
        response = iam_client.list_access_keys(UserName=username)
        key_metadata = response.get("AccessKeyMetadata", [])
        if not key_metadata:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Access Keys found"}},
                operation_name="ListAccessKeys"
            )
        key_ids = [key['AccessKeyId'] for key in key_metadata]
        return key_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Request failure, try again later: {e}"




def list_certificate_ids(username):
    try:
        response = iam_client.list_signing_certificates(UserName=username)
        cert_metadata = response.get("Certificates", [])
        if not cert_metadata:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Certificates found"}},
                operation_name="ListSigningCertificates"
            )
        cert_ids = [cert['CertificateId'] for cert in cert_metadata]
        return cert_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Request failure, try again later: {e}"


def list_public_ssh_keys(username):
    try:
        response = iam_client.list_ssh_public_keys(UserName=username)
        key_metadata = response.get("SSHPublicKeys", [])
        if not key_metadata:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Public Keys found"}},
                operation_name="ListSSHPublicKeys"
            )
        key_ids = [key['SSHPublicKeyId'] for key in key_metadata]
        return key_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"

def list_service_specific_creds(username):
    try:
        response = iam_client.list_service_specific_credentials(UserName = username)
        creds = response.get("ServiceSpecificCredentials", [])
        if not creds:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Service specific creds found"}},
                operation_name="ListServiceSpecificCredentials"
            )
        cred_ids = [cred['ServiceSpecificCredentialId'] for cred in creds]
        return cred_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"
    except iam_client.exceptions.ServiceNotSupportedException as e:
        return f"Unsupported service: {e}"



def list_mfa_devices(username):
    try:
        response = iam_client.list_mfa_devices(UserName=username)
        devices = response.get("MFADevices", [])
        if not devices:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No MFA Devices found"}},
                operation_name="ListMFADevices"
            )
        device_ids = [device['SerialNumber'] for device in devices]
        return device_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"


def set_password_policy():
    print("Setting for admin sect")


def create_access_key(username):
    try:
        response = iam_client.create_access_key(UserName=username)
        key_information = response.get("AccessKey",[])
        access_key_id = [key_information['AccessKeyId']]
        secret_access_key = [key_information['SecretAccessKey']]
        return access_key_id, secret_access_key
    except iam_client.exceptions.NoSuchEntityException as e:
        return {f"{e}"}




def check_password_policy():
    try:
        response = iam_client.get_account_password_policy()
        if not response:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Password Policy found. You can set this in the Admin console of this programme. "}},
                operation_name="GetAccountPasswordPolicy"
            )
        else:
            return response
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"



def check_login_profile(username):
    try:
        profile = iam_client.get_login_profile(UserName=username)
        if profile:
            return True
    except iam_client.exceptions.NoSuchEntityException:
            return False

def create_login_profile(username, password):
    try:
        login_profile = iam_client.create_login_profile(UserName=username, Password=password)
        return f"Created login profile {login_profile} for {username}"
    except iam_client.exceptions.EntityAlreadyExistsException:
        return f"Login Profile already exists for {username}"
    except iam_client.exceptions.PasswordPolicyViolationException as e:
        return f"This password for {username} does not adhere to the account's password policy: {e}"



def change_password(username,password):
    check_if_password_policy = check_password_policy()
    if isinstance(check_if_password_policy, str):
        return "Cannot change password without setting password policy. "
    else:
        is_login_profile = check_login_profile(username)
        if not is_login_profile:
            login_profile = create_login_profile(username=username, password=password)
            print(login_profile)
        else:
            update_login_profile = iam_client.update_login_profile(UserName=username,Password=password)
            print(update_login_profile)
        return f"Password Successfully updated for {username}"



def list_groups_for_user(username):
    try:
        response = iam_client.list_groups_for_user(UserName=username)
        groups = response.get("Groups", [])
        if not groups:
            raise iam_client.exceptions.NoSuchEntityException(
                error_response={"Error": {"Code": "NoSuchEntityException", "Message": "No Groups found attached to user."}},
                operation_name="ListGroupsForUser"
            )
        group_names = [group['GroupName'] for group in groups]
        return group_names
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"{e}"

    except iam_client.exceptions.ServiceFailureException as e:
        return f"Request failure, try again later: {e}"


def add_user_to_group(username):
    print("adding user to group")

def detach_user_policy(username, policy_arn):
    try:
        iam_client.detach_user_policy(UserName=username, PolicyArn=policy_arn)
        return f"successfully detached {policy_arn}."
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No such entity: {e}"
    except iam_client.exceptions.LimitExceededException as e:
        return f"Rate limit succeeded: {e}"
    except iam_client.exceptions.InvalidInputException as e:
        return f"Invalid input: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure: {e}"

def delete_access_key(username, access_key_id):
    try:
        iam_client.delete_access_key(UserName=username, AccessKeyId=access_key_id)
        return f"Successfully deleted access key: {access_key_id}"
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No such entity: {e}"
    except iam_client.exceptions.LimitExceededException as e:
        return f"Rate limit exceeded: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure: {e}"


def delete_signing_certificate(username, cert):
    try:
        iam_client.delete_signing_certificate(UserName=username, CertificateId=cert)
        return f"Successfully deleted cert: {cert}"
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No such entity: {e}"
    except iam_client.exceptions.LimitExceededException as e:
        return f"Rate limit succeeded: {e}"
    except iam_client.exceptions.ConcurrentModificationException as e:
        return f"Concurrent modification exception: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure: {e}"


def delete_ssh_public_key(username, key_id):
    try:
        iam_client.delete_ssh_public_key(UserName=username, SSHPublicKeyId=key_id)
        return f"Deleted {key_id} from {username}"
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No such entity: {e}"


def delete_service_specific_creds(username, cred):
    try:
        iam_client.delete_service_specific_credential(UserName=username, ServiceSpecificCredentialId=cred)
        return f"Deleted {cred} for {username}. "
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No such entity: {e}"

def deactivate_mfa_device(username, serial_id):
    try:
        iam_client.deactivate_mfa_device(UserName=username, SerialNumber=serial_id)
        return f"Successfully deactivated MFA: {serial_id}"
    except iam_client.exceptions.EntityTemporarilyUnmodifiableException as e:
        return f"Entity temporarily unmodifiable, try again later: {e}"
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No such entity: {e}"
    except iam_client.exceptions.LimitExceededException as e:
        return f"Rate limit exceeded: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure: {e}"
    except iam_client.exceptions.ConcurrentModificationException as e:
        return f"Concurrent modification exception: {e}"

def delete_login_profile(username):
    try:
        iam_client.delete_login_profile(UserName=username)
        return f"Login profile for {username} deleted successfully."
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No login profile found for {username}: {e}"
    except iam_client.exceptions.EntityTemporarilyUnmodifiableException as e:
        return f"Entity temporarily unmodifiable, try again later: {e}"
    except iam_client.exceptions.LimitExceededException as e:
        return f"Rate limit exceeded: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure: {e}"
    except iam_client.exceptions.ConcurrentModificationException as e:
        return f"Concurrent modification exception: {e}"



def remove_user_from_group(username, group):
    try:
        iam_client.remove_user_from_group(UserName=username, GroupName=group)
        return f"User {username} removed from groups successfully. "
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No such entity: {e}"
    except iam_client.exceptions.LimitExceededException as e:
        return f"Rate limit succeeded: {e}"
    except iam_client.exceptions.ServiceFailureException as e:
        return f"Service failure: {e}"

def delete_user(username):
    try:
        iam_client.delete_user(UserName=username)
        return f"Successfully deleted {username}"
    except iam_client.exceptions.LimitExceededException as e:
        return f"Rate limited exceeded: {e}"
    except iam_client.exceptions.NoSuchEntityException as e:
        return f"No such user: {e}"
    except iam_client.exceptions.DeleteConflictException as e:
        return f"Delete conflict, make sure everything is detached before deletion: {e}"
    except iam_client.exceptions.ConcurrentModificationException as e:
        return f"Concurrent modification exception: {e}"
    except iam_client.exceptions.ConcurrentModificationException as e:
        return f"Service failure: {e}"



def delete_iam_user(username):
    # checking if user is valid:
    list_of_users = list_iam_users()
    if not list_of_users:
        print(list_of_users)
    print("Deleting inline policies...\n")
    # list attached policies
    user_inline_policy_list = list_attached_inline_user_policies(username=username)
    if isinstance(user_inline_policy_list, str):
        print(user_inline_policy_list)
    else:
        for policy in user_inline_policy_list:
            print(f"deleting inline policy {policy}")
            delete_user_policy_action = delete_user_policy(username=username, policy_name=policy)
            print(delete_user_policy_action)


    print("Detaching managed policies...")
    # list managed policies
    managed_policy_list = list_attached_managed_user_policies(username)
    if isinstance(managed_policy_list, str):
        print(managed_policy_list)
    else:
        for policy in managed_policy_list:
            # get arn of each policy
            policy_arn = iam_policy.get_iam_policy_arn(new_policy=policy)
            detach_user_policy(username=username, policy_arn=policy_arn)
            print(f"Detached {policy_arn} from {username}")

    print("Deleting access keys...\n")
    key_list = list_access_keys(username)
    if isinstance(key_list, str):
        print(key_list)
    elif key_list:
        print("Listing Keys..")
        for key in key_list:
            print(f"-{key}")
        for key in key_list:
            print(f"Deleting: {key}\n")
            delete_access_key(username=username, access_key_id=key)


    print("Deleting certificates...\n")
    cert_ids = list_certificate_ids(username)
    if isinstance(cert_ids, str):
        print(cert_ids)
    elif cert_ids:
        for cert in cert_ids:
            print(f"Deleting: {cert}\n")
            deleting_certs = delete_signing_certificate(username=username, cert=cert)
            print(deleting_certs)


    print("Deleting SSH keys...\n")
    keys = list_public_ssh_keys(username=username)
    if isinstance(keys, str):
        print(keys)
    elif keys:
        for key in keys:
            print(f"Deleting: {key}\n")
            delete_ssh_public_key(username=username, key_id=key)

    print("Deleting service-specific credentials...\n")
    creds = list_service_specific_creds(username)
    if isinstance(creds, str):
        print(creds)
    elif creds:
        for cred in creds:
            print(f"Deleting: {cred}\n")
            delete_service_specific_creds(username=username, cred=cred)

    print("Deleting MFA devices...\n")
    devices_ids = list_mfa_devices(username)
    if isinstance(devices_ids, str):
        print(devices_ids)
    elif devices_ids:
        for serial_id in devices_ids:
            print(f"Deactivating: {serial_id}\n")
            deactivate = deactivate_mfa_device(username=username, serial_id=serial_id)
            print(deactivate)

    print("Deleting login profile...\n")
    delete_login_profile_response = delete_login_profile(username=username)
    if isinstance(delete_login_profile_response, str):
        print(delete_login_profile_response)
    elif delete_login_profile_response:
        print(f"Deleted Login profile.")

    print("Removing user from groups...\n")
    users_groups = list_groups_for_user(username)
    if isinstance(users_groups, str):
        print(users_groups)
    elif users_groups:
        for group in users_groups:
            print(f"Removing user from group: {group}\n")
            removed_result = remove_user_from_group(username=username, group=group)
            print(removed_result)

    print("Deleting IAM user...\n")
    delete_user_response = delete_user(username=username)
    return delete_user_response






# edit all functions to change error handling to deliver actual error code to main.py through returning the error string and checking ifinstance (function_output, str) then return error as if its a string then it's not a list for example
# start with detaching policies