import socket
import random
import time

import urllib.request
import json

import ee
import folium


# socket: interface de rede de baixo nível;
# random: geração de números aleatórios;
# time: funções para obter e gerenciar variáveis relacionadas ao tempo;
# urllib: fornece funções e classes que auxiliam no gerenciamento de URLs;
# json: gerenciamento de estruturas JSON;
# ee: funções para geração de mapa;
# folium: biblioteca que auxilia a criação de mapas leaflet.

# função auxiliar para geração e localização de um mapa
def map_display(center, dicionario, latitude, longitude, tiles="OpenStreetMap", zoom_start=10):
    figure = folium.Figure(width=1280, height=800)
    map = folium.Map(location=center, tiles=tiles, zoom_start=zoom_start, min_zoom=2)
    for k, v in dicionario.items():
        if ee.image.Image in [type(x) for x in v.values()]:
            folium.TileLayer(
                tiles=v["tile_fetcher"].url_format,
                attr='Google Earth Engine',
                overlay=True,
                name=k
            ).add_to(map)
        else:
            folium.GeoJson(
                data=v,
                name=k
            )
    map.add_child(folium.LayerControl())
    map = folium.Map(location=center, tiles=tiles, zoom_start=zoom_start)
    marker = folium.Marker(location=[latitude, longitude], popup='Test')
    marker.add_to(map)
    map = map.add_to(figure)
    return figure


# função para plotar e gerar mapa
def plot_map(latitude=0, longitude=0):
    imagem = ee.ImageCollection('LANDSAT/LC08/C01/T1_SR') \
        .filterDate('2021-01-01', '2022-01-01') \
        .filterBounds(ee.Geometry.Point(latitude, longitude))
    mediana = imagem.median()
    dicionario = {
        'Mediana': mediana.getMapId({'bands': ['B4', 'B3', 'B2'], 'min': 0, 'max': 3000})
    }
    centro = [latitude, longitude]
    return map_display(centro, dicionario, latitude, longitude, zoom_start=8)


# função que obtém dados de localização baseados no IPv4 recebido
def get_loc(ipv4=''):
    request = urllib.request.Request('https://geolocation-db/jsonp/' + ipv4, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(request) as url:
        data = url.read().decode()
        data = data.split('(')[1].strip(')')
        return json.loads(data)


# função auxiliar para ajudar na exibição de espaços em branco na hora de exibir os dados do trace
def adicionar_espacos_em_branco(numero_espacos=0):
    espacos = ''
    for i in range(numero_espacos):
        espacos += ' '
    return espacos


# função auxiliar para exibir o que está ocorrendo no trace
def print_mensagem_envio(pacotes_enviados=0, ttl=0, rtt='0s', ipv4='', localizacao='', erro_conexao=False):
    message = ''

    if erro_conexao:
        if pacotes_enviados == 1:
            if ttl < 10:
                message = str(ttl) + adicionar_espacos_em_branco(10) + '*' + adicionar_espacos_em_branco(16)
            else:
                message = str(ttl) + adicionar_espacos_em_branco(9) + '*' + adicionar_espacos_em_branco(16)
        elif pacotes_enviados == 2:
            message = '*' + adicionar_espacos_em_branco(16)
        elif pacotes_enviados == 3:
            if ipv4 != '':
                message = '*' + adicionar_espacos_em_branco(16) + \
                          '(' + adicionar_espacos_em_branco(44 - len(str(ipv4))) + '*' + \
                          adicionar_espacos_em_branco(19) + '*\n'
            else:
                message = '*' + adicionar_espacos_em_branco(16) + '*' + adicionar_espacos_em_branco(45) + '*' + \
                          adicionar_espacos_em_branco(19) + '*\n'
    else:
        pais = 'Não encontrado'
        cidade = 'Não encontrada'

        if localizacao != '' and localizacao['country_name'] != 'Not Found' and localizacao['country_name'] is not None:
            pais = localizacao['country_name']
        if localizacao != '' and localizacao['city'] != 'Not Found' and localizacao['city'] is not None:
            cidade = localizacao['city']

        if pacotes_enviados == 1:
            if ttl < 10:
                message = str(ttl) + adicionar_espacos_em_branco(10) + str(rtt) + ' ms' + \
                          adicionar_espacos_em_branco(14 - len(str(rtt)))
            else:
                message = str(ttl) + adicionar_espacos_em_branco(9) + str(rtt) + ' ms' + \
                          adicionar_espacos_em_branco(14 - len(str(rtt)))
        elif pacotes_enviados == 2:
            message = str(rtt) + ' ms' + adicionar_espacos_em_branco(14 - len(str(rtt)))
        elif pacotes_enviados == 3:
            message = str(rtt) + ' ms' + adicionar_espacos_em_branco(14 - len(str(rtt))) + '(' + str(ipv4) + ')' + \
                      adicionar_espacos_em_branco(44 - len(str(ipv4))) + pais + \
                      adicionar_espacos_em_branco(20 - len(pais)) + cidade + '\n'
    print(message, end="", flush=True)


# função que cria um receptor
def gerar_receiver(port):
    # É criado um socket receiver utilizando SOCK_RAW e o protocolo ICMP
    socket_receiver = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_RAW,
        proto=socket.IPPROTO_ICMP
    )

    # Define o timeout do receiver
    socket_receiver.settimeout(3)

    # Bind associa o socket receiver a um endereço e uma porta
    try:
        socket_receiver.bind(('', port))
    except socket.error:
        print(f'Não foi possível estabelecer conexão com a porta: {port}')

    # retorna o socket receptor
    return socket_receiver


# função que cria um remetente
def gerar_sender(ttl):
    socket_sender = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_DGRAM,
        proto=socket.IPPROTO_UDP
    )

    # define o nível da opção do socket e o TTL no pacote UDP a ser enviado
    socket_sender.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    # retorna o socket remetente
    return socket_sender


# o traceroute
def trace(route):
    # se a rota for inválida, para
    if len(route) < 3:
        print(f'Erro: Rota {route} é inválida')
        return

    # A rota informada é salva, a quantidade de saltos máxima e o valor inicial do ttl são definidos
    route = route
    max_saltos = 30
    ttl = 1

    # uma porta aleatória com número entre 33434 e 33535 é escolhida
    porta = random.choice(range(33434, 33535))

    # tenta obter o ip da rota informada
    print(f'Tentando obter o IP do host: {route}')
    try:
        ip_dest = socket.gethostbyname(route)
    except socket.error:
        print(f'Erro: Não foi possível obter o IP do host: {route}')
        return

    print(f'O IP do host foi encontrado: {ip_dest}')

    # imprime informações
    print(f'Iniciando o TraceRoute para : {route}({ip_dest}), com o máximo de {max_saltos} saltos\n')
    print('Saltos     RTT 1º Pacote    RTT 2º Pacote    RTT 3º Pacote    Router IP ' +
          'País                Cidade\n')

    # inicia o traceroute
    pacotes_enviados = 0

    # salva o router_ip mais recente para que não exiba somente no envio do terceiro pacote
    router_ip = ''

    # loop de navegação do traceroute
    while True:
        # reseta quando o número de pacotes enviados para um TTL chega a 3
        if pacotes_enviados == 3:
            pacotes_enviados = 0

        # cria remetentes e receptores para enviar pacotes UDP e receber ICMP
        sender = gerar_sender(ttl)
        receiver = gerar_receiver(porta)

        # envia um pacote UDP em branco para a rota definida
        sender.sendto(b'', (route, porta))
        # salva o tempo em que o pacote foi enviado para determinar o RTT posteriormente
        start_time = time.time()

        endr = None
        try:
            # lê um número de bytes enviados de um socket UDP
            # 'data' são os dados enviados ao receiver e 'endr[0]' é o endereço do socket que envia os dados
            data, endr = receiver.recvfrom(1024)

            # captura a hora de término em que o pacote ICMP foi recebido
            end_time = time.time()
        except socket.error:
            pass

        # fecha os sockets
        sender.close()
        receiver.close()

        # incrementa o total de pacotes de enviados com o mesmo TTL
        pacotes_enviados += 1

        if pacotes_enviados == 1:
            router_ip = ''

        # se um socket responder com uma resposta ICMP ao pacote UDP enviado pelo remetente
        if endr:
            # localizacao = ''
            # trava de segurança para a biblioteca de localização
            localizacao = get_loc(endr[0])
            router_ip = endr[0]

            # calcula o RTT(Round Trip Time)
            rtt = round((end_time - start_time) * 1000, 2)

            print_mensagem_envio(pacotes_enviados, ttl, rtt, router_ip, localizacao)

            # se o host de destino foi alcançado e se foi recebido os 3 pacotes enviados
            if endr[0] == ip_dest and pacotes_enviados == 3:
                print(f'\nChegou no destino: {endr[0]}')
                if localizacao != '':
                    return plot_map(localizacao['latitude'], localizacao['longitude'])
                break
        else:
            print_mensagem_envio(pacotes_enviados=pacotes_enviados, ttl=ttl, ipv4=router_ip, erro_conexao=True)

        # se os 3 pacotes foram enviados, incrementa o TTL em 1
        if pacotes_enviados == 3:
            ttl += 1

        # se para o TTL exceder o número máximo de saltos
        print('Limite de saltos atingido')
        break


ee.Authenticate()
ee.Initialize()

print('''
 /$$$$$$$$                                     /$$$$$$$                        /$$                        
|__  $$__/                                    | $$__  $$                      | $$                        
   | $$  /$$$$$$  /$$$$$$   /$$$$$$$  /$$$$$$ | $$  \ $$  /$$$$$$  /$$   /$$ /$$$$$$    /$$$$$$   /$$$$$$ 
   | $$ /$$__  $$|____  $$ /$$_____/ /$$__  $$| $$$$$$$/ /$$__  $$| $$  | $$|_  $$_/   /$$__  $$ /$$__  $$
   | $$| $$  \__/ /$$$$$$$| $$      | $$$$$$$$| $$__  $$| $$  \ $$| $$  | $$  | $$    | $$$$$$$$| $$  \__/
   | $$| $$      /$$__  $$| $$      | $$_____/| $$  \ $$| $$  | $$| $$  | $$  | $$ /$$| $$_____/| $$      
   | $$| $$     |  $$$$$$$|  $$$$$$$|  $$$$$$$| $$  | $$|  $$$$$$/|  $$$$$$/  |  $$$$/|  $$$$$$$| $$      
   |__/|__/      \_______/ \_______/ \_______/|__/  |__/ \______/  \______/    \___/   \_______/|__/                                                                                                        
\n\n''')

trace(input('Digite o endereço da rota: '))
