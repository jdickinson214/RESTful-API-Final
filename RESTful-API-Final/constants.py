url = "https://hw4-dickinsj.uc.r.appspot.com"

#boat error messages
badRequest = {"Error": "The request object is missing at least one of the required attributes"}
notFound = {"Error": "No boat with this boat_id exists"}

#load error messages
loadNotFound = {"Error": "No load with this load_id exists"}

#boat/id/load/id error messages
notFoundBS = {"Error": "The specified boat and/or load don\u2019t exist"}
notEmpty = {"Error": "The load is already on a boat"}
boatNotHere = {"Error": "No boat with this boat_id is at the load with this load_id"}



#adds id and self web URL to object
def addTags(results, typeObject):
    for e in results:
        e["id"] = str(e.key.id)
        e["self"] = url + str(typeObject) + str(e.key.id)
