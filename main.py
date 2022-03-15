from fastapi import FastAPI

from GEOLogic import geo_processor
from RDPLogic import rdp_processor

app = FastAPI()


@app.get("/checkRDP/{ip}/{port}/{username}/{password}")
def check_rdp_method(ip: str, port: int, username: str, password: str):
    try:
        request = rdp_processor.check_rdp(ip, username, password, port, '')
        if request == "Access Granted":
            geo_information = geo_processor.detect_geo(ip)
            return {"result": request, "city": geo_information[0], "country": geo_information[1]}
        else:
            return {"result": "Access Denied"}
    except:
        return {"result": "Error"}

