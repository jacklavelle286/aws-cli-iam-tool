import json
from iam import iam_client






create_role_output = create_role(role_name="dsssa", description="testing", assume_role_type_value="Service",assume_role_entity_value="ec2", user=False)



