import random
import string

#url = "https://dickinsj-project.uc.r.appspot.com"
url = "http://127.0.0.1:8080"

#boat error messages
badRequest = {"Error": "The request object is missing at least one of the required attributes"}
notFound = {"Error": "No boat with this boat_id exists"}

#load error messages
loadNotFound = {"Error": "No load with this load_id exists"}

#boat/id/load/id error messages
notFoundBS = {"Error": "The specified boat and/or load don\u2019t exist"}
notEmpty = {"Error": "The load is already on a boat"}
boatNotHere = {"Error": "No boat with this boat_id is at the load with this load_id"}

#request error messages
reqHeadNotJSON = {"Error": "request header ['Content-Type'] must be application/json"}
unknownHeaderReq = {"Error": "unknown header request type. Must be application/json or text/html"}
accNotJSON = {"Error": "request header 'Accept' mimetype must be application/json"}


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