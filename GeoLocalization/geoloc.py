import ipinfo
import sys
# Obtener la ip como comando de consola
try:
    ip_address = sys.argv[1]
except IndexError:
    ip_address = None
# access token para ipinfo.io
access_token = 'e8c77a8721f156'

handler = ipinfo.getHandler(access_token)
# Obtener la informacion de la ip
details = handler.getDetails(ip_address)
# Mostrar por pantalla la informacion de la ip
for key, value in details.all.items():
    print(f"{key}: {value}")