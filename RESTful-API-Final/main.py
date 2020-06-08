from google.cloud import datastore
from flask import Flask, request, make_response
from requests_oauthlib import OAuth2Session
import json
import constants as c
import model
import os

from google.oauth2 import id_token
from google.auth import crypt
from google.auth import jwt
from google.auth.transport import requests

app = Flask(__name__)
client = datastore.Client()


###################################################################################################
###################################################################################################
###################################################################################################

#                       OAuth2.0 JWT Generation for users

###################################################################################################
###################################################################################################
###################################################################################################
#used for testing locally. disables https requirement
#os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.secret_key = str(c.generate_random_code(20))

# #get client_secret file from directory and assign values
client_secret_path = os.path.dirname(os.path.abspath(__file__)) + "/creds/client_secret.json"
CLIENT_SECRET_FILE = json.load(open(client_secret_path))
client_id = CLIENT_SECRET_FILE['web']['client_id']
client_secret = CLIENT_SECRET_FILE['web']["client_secret"]

# This is the page that you will use to decode and collect the info from
# the Google authentication flow
redirect_uri = c.url + '/oauth'

# These let us get basic info to identify a user and not much else
# they are part of the Google People API
scope = ['https://www.googleapis.com/auth/userinfo.email', 
         'openid',
         'https://www.googleapis.com/auth/userinfo.profile']
oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)

# This link will redirect users to begin the OAuth flow with Google
@app.route('/')
def index():
    authorization_url, state = oauth.authorization_url(
        'https://accounts.google.com/o/oauth2/auth',
        # access_type and prompt are Google specific extra parameters.
        access_type="offline", prompt="select_account")
    return 'Please go <a href=%s>here</a> and authorize access.' % authorization_url

# This is where users will be redirected back to and where you can collect
# the JWT for use in future requests
@app.route('/oauth')
def oauthroute():
    #get token
    token = oauth.fetch_token(
        'https://accounts.google.com/o/oauth2/token',
        authorization_response=request.url,
        client_secret=client_secret)
    #get id_info
    req = requests.Request()
    id_info = id_token.verify_oauth2_token(token['id_token'], req, client_id)
    verify_url = c.url + '/verify-jwt?jwt=' + token['id_token']

    # check if user exists, if not store user uniqueID and email in database
    query = client.query(kind=model.users)
    query.add_filter('uniqueID', '=', id_info['email'])
    results = list(query.fetch())
    if not results:
        #user is not already in database, add new user
        new_user = datastore.entity.Entity(key=client.key(model.users))
        new_user.update({"uniqueID": id_info['email']})
        client.put(new_user)

    return """Your JWT is: %s <br><br> Please go <a href=%s> here</a> to verify JWT <br><br> user's uniqueID is %s""" % (token['id_token'], verify_url, id_info['email'])
    
# This page demonstrates verifying a JWT. id_info['email'] contains
# the user's email address and can be used to identify them
# this is the code that could prefix any API call that needs to be
# tied to a specific user by checking that the email in the verified
# JWT matches the email associated to the resource being accessed.
@app.route('/verify-jwt')
def verify():
    req = requests.Request()

    try:
      id_info = id_token.verify_oauth2_token( 
        request.args['jwt'], req, client_id)
    except ValueError:
        return (json.dumps(c.invalid_jwt), 401)

    return repr(id_info) + "<br><br> the user is: " + id_info['email']
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################




###################################################################################################
###################################################################################################
###################################################################################################
#                                           Users
###################################################################################################
###################################################################################################
###################################################################################################

#*******/users*************************************************************************************
#
#   GET:    gets all users
#
#   Note: Unprotected. anyone can see list of all users
#
#**************************************************************************************************

@app.route('/users', methods=['GET'])
def users_get():
    if request.method == "GET":
        query = client.query(kind=model.users)  
        results = list(query.fetch())
        for e in results:
            e["id"] = str(e.key.id)
        output = {"users": results}
        return json.dumps(output)    
    else:
        return (json.dumps(c.invalid_method), 405)

#*************************/users/<id>*************************************************************
#
#   GET:    gets this user and all boats they own
#   DELETE: if authorized, delete this user
#    
#   note: checks bearer token for jwt and returns all boats for
#   that jwt, not for the id
#
#*************************************************************************************************

@app.route('/users/<id>', methods=['DELETE', 'GET'])
def user_get_delete(id):
    if 'Authorization' not in request.headers:
        return (json.dumps(c.invalid_jwt), 401)
    #ensure token is valid
    try:
        req = requests.Request()
        token_value = request.headers['Authorization'].split(' ')[1]
        id_info = id_token.verify_oauth2_token(token_value, req, client_id)
    except ValueError:
        return (json.dumps(c.invalid_jwt), 401)
    
    user_key = client.key(model.users, int(id))    
    user = client.get(key=user_key)
    if user == None:
        return (json.dumps(c.valid_jwt_entity_not_found), 404)
    if user["uniqueID"] != id_info["email"]:
        return (json.dumps(c.user_not_authorized), 403)

    #all valid, run query
    if request.method == 'GET':
        query = client.query(kind=model.boats)
        query.add_filter('owner', '=', str(id_info['email']))
        boatList = list(query.fetch())
        c.addTags(boatList, "/boats/")
        for boat in boatList:
            boat.pop("owner", None)
        user.update({"id": str(user.key.id), "boats": boatList})
        output = {"user": user}
        return json.dumps(output)
 
    elif request.method == "DELETE":
        client.delete(user_key)
        return ('', 204)

    else:
        return (json.dumps(c.invalid_method), 405)


###################################################################################################
###################################################################################################
###################################################################################################
#                                       Boats
###################################################################################################
###################################################################################################
###################################################################################################

#*************/boats******************************************************************************
#
#   Post:   create a new boat
#   Get:    returns all boats
#
#*************************************************************************************************
@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():

    if 'application/json' not in request.accept_mimetypes:
        return (json.dumps(c.accept_head_not_JSON), 406)
    #ensure token is valid
    if 'Authorization' not in request.headers:
        return (json.dumps(c.invalid_jwt), 401)
    try:
        req = requests.Request()
        token_value = request.headers['Authorization'].split(' ')[1]
        id_info = id_token.verify_oauth2_token(token_value, req, client_id)
    except ValueError:
        return (json.dumps(c.invalid_jwt), 401)

    if request.method == 'POST':
        #ensure content type is correct
        if request.headers['Content-Type'] != 'application/json':
            return (json.dumps(c.content_type_not_JSON), 415)
        content = request.get_json()

        #   Input Validation
        if model.invalidRequest(content, "boat"):
            return (json.dumps(c.bad_req), 400)
        if 'Authorization' not in request.headers:
            return (json.dumps(c.invalid_jwt), 401)
        
        #All valid, store values and post to client
        new_boat = datastore.entity.Entity(key=client.key(model.boats))
        new_boat.update({"name": content["name"], "type": content["type"], "length": int(content["length"]), "owner": id_info['email'], "loads": []})
        client.put(new_boat)
        c.addTag(new_boat, "/boats/")
        return (json.dumps(new_boat), 201)

    elif request.method == "GET":
        query = client.query(kind=model.boats)
        query.add_filter('owner', '=', id_info['email'])
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit = q_limit, offset = q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
        	next_offset = q_offset + q_limit 
        	next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
        	next_url = None
        c.addTags(results, "/boats/")  #function in c.py
        output = {"boats": results}
        if next_url:
        	output["next"] = next_url
        return json.dumps(output)

    else:
        return (json.dumps(c.invalid_method), 405)

#*************/boats/<id>*******************************************************************
#
#   DELETE:     deletes this boat
#   GET:        returns this boat
#   PUT:        changes object. removes unmentioned attributes
#   PATCH:      changes object. retains unmentioned attributes
#
#*******************************************************************************************
@app.route('/boats/<id>', methods=['DELETE', 'GET', 'PUT', 'PATCH'])
def boat_get_delete(id):

    #check authorization
    if 'Authorization' not in request.headers:
        return (json.dumps(c.invalid_jwt), 401)
    #ensure token is valid
    try:
        req = requests.Request()
        token_value = request.headers['Authorization'].split(' ')[1]
        id_info = id_token.verify_oauth2_token( 
        token_value, req, client_id)
    except ValueError:
        return (json.dumps(c.invalid_jwt), 401)
    #check boat is valid
    boat_key = client.key(model.boats, int(id))
    boat = client.get(key=boat_key)
    if boat == None:
        return (json.dumps(c.valid_jwt_entity_not_found), 404)
    if id_info['email'] != boat['owner']:
        return (json.dumps(c.user_not_authorized), 403)
    
    #PUT/PATCH request
    if request.method == 'PUT' or request.method == 'PATCH':

        if request.headers['Content-Type'] != 'application/json':
            return (json.dumps(c.content_type_not_JSON), 415)
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps(c.accept_head_not_JSON), 406)
        content = request.get_json()

        #if Put, reset all values to None
        if request.method == 'PUT':
            boat.update({'name': None, 'length': None, 'type': None})

        #error check content and add into boat object
        if model.invalidAttribute(content, "boat"):
            return (json.dumps(c.bad_req), 400)
        for attribute in content:
            boat.update({str(attribute): content[attribute]})
        client.put(boat)
        c.addTag(boat, "/boats/")
        if request.method == 'PUT':
            res = make_response(json.dumps(boat))
            res.location = boat["self"]
            res.status_code = 303
            return res
        else:
            return (json.dumps(boat), 200)

    #GET request
    if request.method == 'GET':
        if 'application/json' not in request.accept_mimetypes:
            return (json.dumps(c.accept_head_not_JSON), 406)
        for load in boat['loads']:
            load.update({"self": c.url + "/loads/" + load['id']})
        c.addTag(boat, "/boats/")
        return json.dumps(boat)

    #DELETE request
    elif request.method == 'DELETE':
        #go through all loads on boat and reset 'carrier' to null
        #then delete boat
        if len(boat['loads']) > 0:
            for current_Load in boat['loads']:
                load_key = client.key(model.loads, int(current_Load['id']))
                load = client.get(key=load_key)
                load.update({"carrier": None})
                client.put(load)
        client.delete(boat_key)
        return ('',204)

    else:
        return (json.dumps(c.invalid_method), 405)


###################################################################################################
###################################################################################################
###################################################################################################
#                                       Loads
###################################################################################################
###################################################################################################
###################################################################################################

#*************/loads*******************************************************************************
#
#   Post:   create a new load
#   Get:    returns all loads
#
#   Note: New loads start with null in their 'carrier' field
#**************************************************************************************************
@app.route('/loads', methods=['POST', 'GET'])
def loads_get_post():

    if 'application/json' not in request.accept_mimetypes:
        return (json.dumps(c.accept_head_not_JSON), 406)

    if request.method == 'POST':
        if request.headers['Content-Type'] != 'application/json':
            return (json.dumps(c.content_type_not_JSON), 415)
        content = request.get_json()
        if model.invalidRequest(content, "load"):
            return (json.dumps(c.bad_req), 400)
        new_load = datastore.entity.Entity(key=client.key(model.loads))
        new_load.update({"weight": content["weight"], "carrier": None, "content": content["content"], "delivery_date": content["delivery_date"]})
        client.put(new_load)
        c.addTag(new_load, "/loads/")
        return (json.dumps(new_load), 201)

    elif request.method == "GET":
        query = client.query(kind=model.loads)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit = q_limit, offset = q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
        	next_offset = q_offset + q_limit
        	next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
        	next_url = None
        for e in results:
        	e["id"] = e.key.id
        output = {"loads": results}
        if next_url:
        	output["next"] = next_url
        c.addTags(results, "/loads/")
        return json.dumps(output)

    else:
        return (json.dumps(c.invalid_method), 405)

#*********************************/loads/<id>******************************************************
#
#   DELETE:     deletes this load
#   GET:        returns this load
#   PUT:        changes object. removes unmentioned attributes
#   PATCH:      changes object. retains unmentioned attributes
#
#**************************************************************************************************
@app.route('/loads/<id>', methods=['DELETE', 'GET', 'PUT', 'PATCH'])
def load_get_delete(id):
    if 'application/json' not in request.accept_mimetypes:
        return (json.dumps(c.accept_head_not_JSON), 406)
    load_key = client.key(model.loads, int(id))
    load = client.get(key=load_key)
    if load == None:
        return (json.dumps(c.id_not_found), 404)
    #PUT/PATCH request
    if request.method == 'PUT' or request.method == 'PATCH':
        if request.headers['Content-Type'] != 'application/json':
            return (json.dumps(c.content_type_not_JSON), 415)
        content = request.get_json()
        #if Put, reset all values to None
        if request.method == 'PUT':
            load.update({'weight': None, 'content': None, 'delivery_date': None})
        #error check content and add into boat object
        if model.invalidAttribute(content, "load"):
            return (json.dumps(c.bad_req), 400)
        for attribute in content:
            load.update({str(attribute): content[attribute]})
        client.put(load)
        c.addTag(load, "/loads/")
        if request.method == 'PUT':
            res = make_response(json.dumps(load))
            res.location = load["self"]
            res.status_code = 303
            return res
        else:
            return (json.dumps(load), 200)
    if request.method == 'DELETE':
        if load['carrier'] != None:
            #check authorization
            if 'Authorization' not in request.headers:
                return (json.dumps(c.invalid_jwt), 401)
            #ensure token is valid
            try:
                req = requests.Request()
                token_value = request.headers['Authorization'].split(' ')[1]
                id_info = id_token.verify_oauth2_token( 
                token_value, req, client_id)
            except ValueError:
                return (json.dumps(c.invalid_jwt), 401)
            boat_key = client.key(model.boats, int(load['carrier']['id']))
            boat = client.get(key=boat_key)
            if id_info['email'] != boat['owner']:
                return (json.dumps(c.user_not_authorized), 403)
            for index, current_load in enumerate(boat['loads']):
                if current_load['id'] == str(id):
                    #del load
                    del boat['loads'][index]
            load.update({'carrier': None})
            client.put(boat)
        client.delete(load_key)
        return ('',204)
    elif request.method == 'GET':
        c.addTag(load, "/loads/")
        return json.dumps(load)
    else:
        return (json.dumps(c.invalid_method), 405)


###################################################################################################
###################################################################################################
###################################################################################################
#                                Boats and Loads Interactions
###################################################################################################
###################################################################################################
###################################################################################################

#*************/boats/<boat_id>/loads/<load id>*****************************************************
#
#   PUT:        Puts this boat's id into load's 'current_boat' field
#   DELETE:     Removes load from boat, resets 'current_boat' to null
#
#   Note: user must be owner of boat to do either
#
#**************************************************************************************************
@app.route('/boats/<bid>/loads/<lid>', methods=['PUT', 'DELETE'])
def load_boat_put_delete(lid, bid):
    
    #check authorization
    if 'Authorization' not in request.headers:
        return (json.dumps(c.invalid_jwt), 401)
        #ensure token is valid
    try:
        req = requests.Request()
        token_value = request.headers['Authorization'].split(' ')[1]
        id_info = id_token.verify_oauth2_token( 
        token_value, req, client_id)
    except ValueError:
        return (json.dumps(c.invalid_jwt), 401)
 
    #get load
    load_key = client.key(model.loads, int(lid))
    load = client.get(key=load_key)
    #get boat
    boat_key = client.key(model.boats, int(bid))
    boat = client.get(key=boat_key)
    #check if either is null
    if load == None or boat == None:
        return (json.dumps(c.ids_not_found), 404)  
    #ensure user is owner of boat
    if id_info['email'] != boat['owner']:
        return (json.dumps(c.user_not_authorized), 403)
    if request.method == 'PUT':
        #ensure load is open
        if load["carrier"] != None:
            return (json.dumps(c.not_empty), 403)
        #add boat id and name to load 'carrier' field
        load.update({"carrier": {"id": str(bid), "name": boat['name']}})
        client.put(load)
        #add load id and name to new json object, append to boat's 'loads'
       	new_load = {'id': lid, 'content': load['content']}
        boat['loads'].append(new_load)
        client.put(boat)
        return ('', 204)
    elif request.method == 'DELETE':
        #ensure this boat has this load
        if load["carrier"]["id"] != str(bid):
            return (json.dumps(c.load_not_on_boat), 404)
    	#delete the load in the boat's 'loads'
        for index, current_load in enumerate(boat['loads']):
        	if current_load['id'] == str(lid):
        		#del load
        		del boat['loads'][index]
        #reset 'carrier' to null
        load.update({"carrier": None})
        client.put(boat)
        client.put(load)
        return ('', 204)
    else:
        return (json.dumps(c.invalid_method), 405)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
