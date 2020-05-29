boats = "boats"
loads = "loads"


#attribute list for each type
#these are the required attributes when posting a new attribute
#boat = ["name", "type", "length"]
#load = ["weight", "content", "delivery_date"]

models = {
    "boat": 
        ["name", "type", "length"], 
    "load": 
        ["weight", "content", "delivery_date"]
}


#checks to see if all attributes are in request
#false if one is missing, true if all are within request
def invalidRequest(request, inputModel):
    for mod in models:
        if str(inputModel) == str(mod):
            for att in models[mod]:
                if att not in request:
                    return True
            return False
    return True


