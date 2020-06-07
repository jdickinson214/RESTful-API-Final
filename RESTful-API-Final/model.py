boats = "boats"
loads = "loads"
users = "users"

#attribute list for each type
#these are the required attributes when posting a new attribute

models = {
    "boat": 
        ["name", "type", "length"], 
    "load": 
        ["weight", "content", "delivery_date"]
}


#used in POST requests
#checks to see if all attributes are in request
#true if one is missing, false if all are within request
def invalidRequest(request, inputModel):
    for mod in models:
        if str(inputModel) == str(mod):
            for att in models[mod]:
                if att not in request:
                    return True
            return False
    return True

#used in PUT/PATCH requests
#ensures req attributes are in the model
#false if all req atts are valid ones
def invalidAttribute(request, inputModel):
    for mod in models:
        if str(inputModel) == str(mod):
            for att in request:
                if att not in models[mod]:
                    return True
            return False
    return True


            

