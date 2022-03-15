import geoip2
import geoip2.database


def detect_geo(ip):
    reader = geoip2.database.Reader('./GEOLogic/MaxMindDatabases/GeoLite2-City.mmdb')
    response = reader.city(ip)
    reader.close()
    return [response.city.name, response.country.iso_code]

