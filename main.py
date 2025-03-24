from collections import deque

# Função para adicionar o sufixo 's' aos eventos vistos
def add_label_s(ev):
    if isinstance(ev, event):
        return str(ev.value) + 's'
    else:
        return str(ev) + 's'

# Função para adicionar o sufixo 'l' aos eventos perdidos
def add_label_l(ev):
    if isinstance(ev, event):
        return str(ev.value) + 'l'
    else:
        return str(ev) + 'l'

# Função principal para construir a rede de autômatos (autoGnet)
def autoGnet(O, E, Kd=0, Kl=0):
    nu = 'n'  # Estado neutro, inicial
    # Extrai eventos observáveis (Eo) e vulneráveis (Ev) da lista de observações O
    Eo = [e for ch in O for e in ch[0]]
    Ev = [e for ch in O for e in ch[0] if ch[1]]
    
    # Define as listas de eventos 'Es' (vistos) e 'El' (perdidos)
    Es = [add_label_s(e) for e in Eo]
    El = [add_label_l(e) for e in Ev]
    
    # A rede de eventos inclui todos os eventos, mais o evento de ataque ('att')
    Enet = E + Es + El + ['att']

    # Estado inicial da rede
    x0net = (nu, nu, 0)
    Xnet = set()
    Tnet = []  # Transições
    F = deque()
    F.append(x0net)  # Coloca o estado inicial na fila

    while F:
        xnet = F.popleft()  # Remove o próximo estado da fila
        Xnet = Xnet | {xnet}  # Adiciona o estado ao conjunto de estados já visitados
        (q, d, l) = xnet  # Desempacota o estado (q: estado atual, d: indicador de ataque, l: contador de perdas)

        # Se o estado é neutro, realiza a transição para os eventos observáveis
        if q == nu:
            for e in E:
                if e in Eo:
                    qnew = e
                else:
                    qnew = nu

                # Ajusta o contador de perdas
                if d == nu:  # Sem ataque
                    dnew = nu
                    lnew = l - 1 if l > 0 else 0
                else:  # Com ataque
                    lnew = Kl
                    dnew = nu if d == 0 else (nu if e not in Eo else d - 1)

                # Adiciona a nova transição
                xnew = (qnew, dnew, lnew)
                Tnet.append((xnet, e, xnew))

                # Se o estado novo não foi visitado, adiciona à fila
                if xnew not in Xnet and xnew not in F:
                    F.append(xnew)
        else:
            # Transições com base nos eventos perdidos ou observados corretamente
            if d == 0:  # Sem ataque
                dnew = nu
            else:
                dnew = d

            if d == nu or q not in Ev:
                e = add_label_s(q)
            else:
                e = add_label_l(q)

            xnew = (nu, dnew, l)
            Tnet.append((xnet, e, xnew))

            # Se o estado novo não foi visitado, adiciona à fila
            if xnew not in Xnet and xnew not in F:
                F.append(xnew)

            # Transição de ataque se a contagem de perdas for zero
            if l == 0:
                xnew = (nu, Kd, Kl)
                Tnet.append((xnet, 'att', xnew))
                if xnew not in Xnet and xnew not in F:
                    F.append(xnew)

    # Retorna a rede de autômatos gerada (usando uma função externa 'fsa', que não foi fornecida aqui)
    return fsa(Xnet, Enet, Tnet, [x0net], Xnet)

# Função auxiliar semelhante, mas com ajustes adicionais para a consideração de eventos vulneráveis
def autoGnet2(O, E, Kd=0, Kl=0):
    nu = 'n'  # Estado neutro
    # Extrai eventos observáveis e vulneráveis da lista de observações
    Eo = [e for ch in O for e in ch[0]]
    Ev = [e for ch in O for e in ch[0] if ch[1]]
    Env = set(Eo) - set(Ev)  # Eventos que não são vulneráveis
    
    # Define as listas de eventos 'Es' e 'El' como antes
    Es = [add_label_s(e) for e in Eo]
    El = [add_label_l(e) for e in Ev]
    
    # Rede de eventos
    Enet = E + Es + El + ['att']

    # Estado inicial
    x0net = (nu, 0)
    Xnet = set()
    Tnet = []
    F = deque()
    F.append(x0net)

    while F:
        xnet = F.popleft()
        Xnet = Xnet | {xnet}
        (q, k) = xnet  # Estado atual (q: estado, k: contagem de eventos perdidos)

        if q == nu:  # Estado neutro, eventos observáveis
            for e in E:
                if e in Eo:
                    qnew = e
                else:
                    qnew = nu

                knew = max(0, k - 1)  # Atualiza o contador de perdas
                xnew = (qnew, knew)
                Tnet.append((xnet, e, xnew))

                if xnew not in Xnet and xnew not in F:
                    F.append(xnew)
        else:
            # Transições com base em eventos perdidos ou observados corretamente
            e = add_label_s(q)  # Evento de sucesso
            knew = Kl - 1 if q in Ev and k >= Kl else k
            xnew = (nu, knew)
            Tnet.append((xnet, e, xnew))

            if xnew not in Xnet and xnew not in F:
                F.append(xnew)

            # Evento de perda
            if k >= Kl and q in Ev:
                e = add_label_l(q)  # Evento perdido
                xnew = (nu, k)
                Tnet.append((xnet, e, xnew))

                if xnew not in Xnet and xnew not in F:
                    F.append(xnew)

        # Transições de ataque quando k == 0
        if k == 0 and q == nu:
            qnew = q if q in Env else nu
            xnew = (qnew, Kd + Kl)
            Tnet.append((xnet, 'att', xnew))

            if xnew not in Xnet and xnew not in F:
                F.append(xnew)

    return fsa(Xnet, Enet, Tnet, [x0net], Xnet, Eo=Es)

# Abaixo você pode visualizar o autômato resultante (não fornecido o código completo de visualização)
# Gnet = autoGnet2(O, E, Kd, Kl)
# plot(Gnet)
# print(Gnet)
