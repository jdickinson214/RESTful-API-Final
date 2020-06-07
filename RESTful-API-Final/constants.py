import random
import string

#url = "https://dickinsj-project.uc.r.appspot.com"
url = "http://127.0.0.1:8080"


#general error messages
id_not_found = {"Error": "entered id is unknown"}
bad_req = {"Error": "The request object is missing at least one of the required attributes"}
invalid_attribute = {"Error": "Attribute not found in entity"}
invalid_method = {"Error": "Invalid method for this endpoint"}

#boat/id/load/id error messages
ids_not_found = {"Error": "The specified boat and/or load don\u2019t exist"}
not_empty = {"Error": "The load is already on a boat"}
load_not_on_boat = {"Error": "This load is not on this boat"}

#request error messages
content_type_not_JSON = {"Error": "request header ['Content-Type'] must be application/json"}
accept_head_not_JSON = {"Error": "request header 'Accept' mimetype must be application/json"}

#Authorization related error messages
user_not_authorized = {"Error": "User not authorized to access this content"}
valid_jwt_entity_not_found = {"Error": "JWT valid but no entity with this id exists"}
invalid_jwt = {"Error": "Missing or invalid JWT"}

#adds id and self web URL to list of objects
def addTags(results, typeObject):
    for e in results:
        e["id"] = str(e.key.id)
        e["self"] = url + str(typeObject) + str(e.key.id)

#adds id and self web URL to single object
def addTag(result, typeObject):
    result["id"] = str(result.key.id)
    result["self"] = url + str(typeObject) + str(result.key.id)

#input length parameter and get a string of random ascii letters and digits
#used for app.secret_key and for 'state' variable in OAuth2 main.py
def generate_random_code(stateLength=10):
    chars = string.ascii_letters + string.digits
    return ''.join((random.choice(chars) for i in range(stateLength)))