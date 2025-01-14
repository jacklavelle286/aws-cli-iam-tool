from . import iam_client
from iam import iam_policy



def list_iam_users():
    try:
        response = iam_client.list_users()
        users = response.get("Users", [])
        return [user['UserName'] for user in users]
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failed: {e}. Try again later.")
        return []
    except Exception as e:
        print(f"Service failed. {e} - try again later.")
        return []


def list_attached_managed_user_policies(username):
    try:
        attached_managed_policies_response = iam_client.list_attached_user_policies(UserName=username)
        attached_managed_policies = attached_managed_policies_response.get("AttachedPolicies", [])
        return [policy["PolicyName"] for policy in attached_managed_policies]
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No policies attached to {username}: {e}")
        return None
    except iam_client.exceptions.InvalidInputException as e:
        print(f"Invalid input: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure, try again later: {e}")
        return None


def list_attached_inline_user_policies(username):
    try:
        attached_inline_policies_response = iam_client.list_user_policies(UserName=username)
        attached_inline_policies = attached_inline_policies_response.get("PolicyNames", [])
        return attached_inline_policies

    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No policies attached to {username}: {e}")
        return None
    except iam_client.exceptions.InvalidInputException as e:
        print(f"Invalid input: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure, try again later: {e}")
        return None


def delete_user_policy(username, policy_name):
    try:
        iam_client.delete_user_policy(UserName=username, PolicyName=policy_name)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No Such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate Limit exceeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failed: {e}")
        return None

def list_access_keys(username):
    try:
        access_keys = iam_client.list_access_keys(UserName=username)
        key_ids = [key['AccessKeyId'] for key in access_keys.get("AccessKeyMetadata", [])]
        return key_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No Access Keys found: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Request failure, try again later: {e}")
        return None


def list_certificate_ids(username):
    try:
        certificates = iam_client.list_signing_certificates(UserName=username)
        cert_ids = [cert['CertificateId'] for cert in certificates.get('Certificates', [])]
        return cert_ids
    except iam_client.exceptions.NoSuchEntityException:
        print(f"No certificates found.")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Request failure, try again later: {e}")
        return None


def list_public_ssh_keys(username):
    try:
        keys = iam_client.list_ssh_public_keys(UserName = username)
        key_ids = [key['SSHPublicKeyId'] for key in keys.get('SSHPublicKeys', [])]
        return key_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No publish SSH keys found: {e}")
        return None

def list_service_specific_creds(username):
    try:
        creds = iam_client.list_service_specific_credentials(UserName = username)
        cred_ids = [cred['ServiceSpecificCredentialId'] for cred in creds.get('ServiceSpecificCredentials', [])]
        return cred_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No credentials found: {e}")
        return None
    except iam_client.exceptions.ServiceNotSupportedException as e:
        print(f"Unsupported service: {e}")
        return None



def list_mfa_devices(username):
    try:
        devices = iam_client.list_mfa_devices(UserName=username)
        device_ids = [device['SerialNumber'] for device in devices.get('MFADevices', [])]
        return device_ids
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No MFA devices found: {e}")
        return None

def list_groups_for_user(username):
    try:
        groups = iam_client.list_groups_for_user(UserName=username)
        return [group['GroupName'] for group in groups.get("Groups", [])]
    except iam_client.exceptions.NoSuchEntityException:
        print(f"No groups found.")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Request failure, try again later: {e}")
        return None


def detach_user_policy(username, policy_arn):
    try:
        iam_client.detach_user_policy(UserName=username, PolicyArn=policy_arn)
        return True
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit succeeded: {e}")
        return None
    except iam_client.exceptions.InvalidInputException as e:
        print(f"Invalid input: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None

def delete_access_key(username, access_key_id):
    try:
        iam_client.delete_access_key(UserName=username, AccessKeyId=access_key_id)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit exceeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None


def delete_signing_certificate(username, cert):
    try:
        iam_client.delete_signing_certificate(UserName=username, CertificateId=cert)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit succeeded: {e}")
        return None
    except iam_client.exceptions.ConcurrentModificationException as e:
        print(f"Concurrent modification exception: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None


def delete_ssh_public_key(username, key_id):
    try:
        iam_client.delete_ssh_public_key(UserName=username, SSHPublicKeyId=key_id)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None


def delete_service_specific_creds(username, cred):
    try:
        iam_client.delete_service_specific_credential(UserName=username, ServiceSpecificCredentialId=cred)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None

def deactivate_mfa_device(username, serial_id):
    try:
        iam_client.deactivate_mfa_device(UserName=username, SerialNumber=serial_id)
    except iam_client.exceptions.EntityTemporarilyUnmodifiableException as e:
        print(f"Entity temporarily unmodifiable, try again later: {e}")
        return None
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit exceeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None
    except iam_client.exceptions.ConcurrentModificationException as e:
        print(f"Concurrent modification exception: {e}")
        return None

def delete_login_profile(username):
    try:
        iam_client.delete_login_profile(UserName=username)
        return "Login profile deleted successfully."
    except iam_client.exceptions.NoSuchEntityException:
        return "No login profile found for user."
    except iam_client.exceptions.EntityTemporarilyUnmodifiableException as e:
        print(f"Entity temporarily unmodifiable, try again later: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit exceeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None
    except iam_client.exceptions.ConcurrentModificationException as e:
        print(f"Concurrent modification exception: {e}")
        return None



def remove_user_from_group(username, group):
    try:
        iam_client.remove_user_from_group(UserName=username, GroupName=group)
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such entity: {e}")
        return None
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limit succeeded: {e}")
        return None
    except iam_client.exceptions.ServiceFailureException as e:
        print(f"Service failure: {e}")
        return None

def delete_user(username):
    try:
        iam_client.delete_user(UserName=username)
    except iam_client.exceptions.LimitExceededException as e:
        print(f"Rate limited exceeded: {e}")
        return None
    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"No such user: {e}")
        return None
    except iam_client.exceptions.DeleteConflictException as e:
        print(f"Delete conflict, make sure everything is detatched before deletion: {e}")
        return None
    except iam_client.exceptions.ConcurrentModificationException as e:
        print(f"Concurrent modification exception: {e}")
        return None
    except iam_client.exceptions.ConcurrentModificationException as e:
        print(f"Service failure: {e}")
        return None




def delete_iam_user(username):
    print("Deleting attached policies...")
    managed_policies = list_attached_managed_user_policies(username=username)
    if managed_policies is None:
        print("Error retrieving managed policies. Skipping.")
    elif not managed_policies:
        print("No managed policies attached.")
    else:
        for policy in managed_policies:
            print(f"Detaching managed policies: {policy}")
            arn = iam_policy.get_iam_policy_arn(policy)
            detach_response = detach_user_policy(username=username, policy_arn=arn)
            if detach_response is None:
                print("Error detaching policy. ")
            elif not detach_response:
                print("No Managed Policies found. ")
            else:
                managed_policies = list_attached_managed_user_policies(username=username)
    if managed_policies is None:
        print("Error retrieving managed policies. ")
    elif not managed_policies:
        print("No Managed Policies attached. ")
    else:
        for policy in managed_policies:
            print(f"Detaching managed policies: {policy}")
        policy_arns = []
        for name in managed_policies:
            arn = iam_policy.get_iam_policy_arn(name)
            policy_arns.append(arn)
        for arn in policy_arns:
            detach_response = detach_user_policy(username=username, policy_arn=arn)
            if detach_response is None:
                print("Error detaching managed policies.")
    print("Deleting inline policies...")
    i_policies = list_attached_inline_user_policies(username=username)
    if i_policies is None:
        print("Error listing attached Inline policies. ")
    elif not i_policies:
        print("No Inline policies attached. ")
    else:
        for i_policy in i_policies:
            delete_user_policy(username=username, policy_name=i_policy)
    print("Deleting access keys...")
    key_list = list_access_keys(username)
    if key_list is None:
        print("Error listing keys. ")
    elif not key_list:
        print("Not Access keys found. ")
    else:
        for key in key_list:
            print(f"Deleting: {key}")
            delete_access_key(username=username, access_key_id=key)
    print("Deleting certificates..")
    cert_ids = list_certificate_ids(username)
    if cert_ids is None:
        print("Error listing Cert IDs.")
    elif not cert_ids:
        print("No Certificiates found.")
    else:
        for cert in cert_ids:
            print(f"Deleting: {cert}")
            delete_signing_certificate(username=username, cert=cert)
    print("Deleting Public SSH Keys...")
    keys = list_public_ssh_keys(username=username)
    if keys is None:
        print("Error listing keys. ")
    elif not keys:
        print("No Publish SSH keys found. ")
    else:
        for key in keys:
            print(key)
            print(f"Deleting: {key}")
            delete_key_response = delete_ssh_public_key(username=username, key_id=key)
            if delete_key_response is None:
                print("Error deleting public SSH keys. ")

    print("Deleting Public Git Credentials...")
    creds = list_service_specific_creds(username)
    if creds is None:
        print("Error listing public git credentials. ")
    elif not creds:
        print("no public git credentials found. ")
    else:
        for cred in creds:
            print(f"Deleting: {cred}")
            delete_service_response = delete_service_specific_creds(username=username, cred=cred)
            if delete_service_response is None:
                print("Error deleting public Git credentials. ")
    print("Deleting MFA Devices...")
    devices_ids = list_mfa_devices(username)
    if devices_ids is None:
        print("Error listing MFA devices. ")
    elif not devices_ids:
        print("No MFA Devices found. ")
    else:
        for serial_id in devices_ids:
            print(id)
            print(f"Deactivating: {serial_id}")
            deactivate_mfa_device_response = deactivate_mfa_device(username=username, serial_id=serial_id)
            if deactivate_mfa_device_response is None:
                print("Error Deactivating MFA. ")
    print("Deleting Login Profile...")
    delete_login_profile_response = delete_login_profile(username=username)
    if delete_login_profile_response is None:
        print("Error deleting login profile. ")
    users_groups = list_groups_for_user(username)
    if users_groups is None:
        print(f"Error listing {username}'s groups. ")
    elif not users_groups:
        print("Not user groups found. ")
    else:
        for group in users_groups:
            print(f"Removing user from group: {group}")
            remove_user_from_group_choice = remove_user_from_group(username=username, group=group)
            if remove_user_from_group_choice is None:
                print(f"Error removing {username} from groups. ")
        print("Deleting user...")
        delete_iam_user_response = delete_iam_user(username=username)
        if delete_iam_user_response is None:
            print("Error deleting IAM user.")
        else:
            print("User Deleted!")



