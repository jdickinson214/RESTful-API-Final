from google.cloud import datastore
from flask import Flask, request
import json
import constants as c
import model

app = Flask(__name__)
client = datastore.Client()


#*************Main Page*************
@app.route('/')
def index():
    return "Please navigate to /boats to use this API"\


#*************/boats*************
#
#   Post:   create a new boat
#   Get:    returns all boats
#
#********************************
@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():


    if request.method == 'POST':
        content = request.get_json()
        if model.invalidRequest(content, "boat"):
            return (json.dumps(c.badRequest), 400)
        new_boat = datastore.entity.Entity(key=client.key(model.boats))
        new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"], "loads": []})
        client.put(new_boat)
        new_boat.update({"id": str(new_boat.key.id), "self": c.url + "/boats/" + str(new_boat.key.id)})
        return (json.dumps(new_boat), 201)


    elif request.method == "GET":
        query = client.query(kind=model.boats)
        q_limit = int(request.args.get('limit', '3'))
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
        output = {"boats": results}
        if next_url:
        	output["next"] = next_url
        c.addTags(results, "/boats/")  #function in c.py
        return json.dumps(output)

    else:
        return 'Method not recognized, please use either GET or POST'


#*************/boats/<id>*************
#
#   Delete:     deletes this boat
#   Get:        returns this boat
#
#*************************************
@app.route('/boats/<id>', methods=['DELETE', 'GET'])
def boat_get_delete(id):


    boat_key = client.key(model.boats, int(id))
    boat = client.get(key=boat_key)
    if boat == None:
        return (json.dumps(c.notFound), 404)


    elif request.method == 'DELETE':
        #go through all loads on boat and reset 'carrier' to null
        #then delete boat
        for current_Load in boat['loads']:
            load_key = client.key(model.loads, int(current_Load['id']))
            load = client.get(key=load_key)
            load.update({"carrier": None})
            client.put(load)
        client.delete(boat_key)
        return ('',204)


    elif request.method == 'GET':
        for load in boat['loads']:
        	load.update({"self": c.url + "/loads/" + load['id']})
        boat.update({"id": id, "self": c.url + "/boats/" + id})
        return json.dumps(boat)


    else:
        return 'Method not recognized, please use DELETE, or GET'





#*************/loads**********************************************
#
#   Post:   create a new load
#   Get:    returns all loads
#
#   Note: New loads start with null in their 'carrier' field
#*****************************************************************
@app.route('/loads', methods=['POST', 'GET'])
def loads_get_post():


    if request.method == 'POST':
        content = request.get_json()
        if model.invalidRequest(content, "load"):
            return (json.dumps(c.badRequest), 400)
        new_load = datastore.entity.Entity(key=client.key(model.loads))
        new_load.update({"weight": content["weight"], "carrier": None, "content": content["content"], "delivery_date": content["delivery_date"]})
        client.put(new_load)
        new_load.update({"id": str(new_load.key.id), "self": c.url + "/loads/" + str(new_load.key.id)})
        return (json.dumps(new_load), 201)


    elif request.method == "GET":
        query = client.query(kind=model.loads)
        q_limit = int(request.args.get('limit', '3'))
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
        c.addTags(results, "/loads/") #function in constants.py
        return json.dumps(output)


    else:
        return 'Method not recognized, please use either GET or POST'


#*************/loads/<id>*****************************************
#
#   Delete:     deletes this load
#   Get:        returns this load
#
#*****************************************************************
@app.route('/loads/<id>', methods=['DELETE', 'GET'])
def load_get_delete(id):

    load_key = client.key(model.loads, int(id))
    load = client.get(key=load_key)
    if load == None:
        return (json.dumps(c.loadNotFound), 404)

    if request.method == 'DELETE':

        if load['carrier'] != None:

            boat_key = client.key(model.boats, int(load['carrier']['id']))
            boat = client.get(key=boat_key)

            for index, current_load in enumerate(boat['loads']):
                if current_load['id'] == str(id):
                    #del load
                    del boat['loads'][index]

            load.update({'carrier': None})

            client.put(boat)

        client.delete(load_key)
        return ('',204)

    elif request.method == 'GET':
        load.update({"id": id, "self": c.url + "/loads/" + id})
        return json.dumps(load)

    else:
        return 'Method not recognized, please use DELETE, or GET'




#*************/boats/<boat_id>/loads/<load id>********************
#
#   Put:    Puts this boat's id into load's 'current_boat' field
#   Delete: Removes load from boat, resets 'current_boat' to null
#
#*****************************************************************
@app.route('/boats/<bid>/loads/<lid>', methods=['PUT', 'DELETE'])
def load_boat_put_delete(lid, bid):
    
    #get load
    load_key = client.key(model.loads, int(lid))
    load = client.get(key=load_key)
    #get boat
    boat_key = client.key(model.boats, int(bid))
    boat = client.get(key=boat_key)

    #check if either is null
    if load == None or boat == None:
        return (json.dumps(c.notFoundBS), 404)  

    if request.method == 'PUT':

        #ensure load is open
        if load["carrier"] != None:
            return (json.dumps(c.notEmpty), 403)

        #add boat id and name to load 'carrier' field
        load.update({"carrier": {"id": str(bid), "name": boat['name']}})
        client.put(load)

        #add load id and name to new json object, append to boat's 'loads'
       	new_load = {'id': lid, 'content': load['content']}
        boat['loads'].append(new_load)
        client.put(boat)
        return ('', 204)

    elif request.method == 'DELETE':

        #ensure this boat is in this load
        if load["carrier"]["id"] != str(bid):
            return (json.dumps(c.boatNotHere), 404)
    
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
        return 'Method not recognized, please use PUT or DELETE'
1


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
