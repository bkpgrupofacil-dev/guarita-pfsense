# Regras de firewall por usuário

Como usar os aliases do Guarita nas regras do pfSense, e o que dá e o que não
dá para fazer na fase 1.

---

## O conceito

Cada grupo do Guarita gera um alias chamado `guarita_<nome curto>`. Esse alias
contém os IPs das estações onde há usuários daquele grupo logados, e é
atualizado automaticamente conforme as pessoas entram e saem.

Nas regras, você usa esse alias como **origem**. O resto da regra é pfSense
comum.

A ordem das regras importa, como sempre no pfSense: a primeira que casa vence.
Coloque as regras dos grupos **acima** da regra genérica de liberação da LAN.

---

## Exemplo 1: liberação total para a diretoria

**Firewall > Rules > LAN**, no topo:

| Campo | Valor |
|-------|-------|
| Action | Pass |
| Interface | LAN |
| Protocol | Any |
| Source | Single host or alias → `guarita_diretoria` |
| Destination | any |
| Description | Diretoria: acesso liberado |

---

## Exemplo 2: grupo restrito, só o essencial

Primeiro crie um alias de portas em **Firewall > Aliases > Ports**, com nome
`portas_web` e as portas `80`, `443`.

| Campo | Valor |
|-------|-------|
| Action | Pass |
| Protocol | TCP |
| Source | `guarita_restrito` |
| Destination | any |
| Destination port | `portas_web` |
| Description | Restrito: somente web |

E, abaixo dela, o bloqueio do resto para esse grupo:

| Campo | Valor |
|-------|-------|
| Action | Block |
| Protocol | Any |
| Source | `guarita_restrito` |
| Destination | any |
| Description | Restrito: bloqueia o resto |

Sem essa segunda regra, o grupo cairia na regra genérica da LAN logo abaixo e
teria acesso a tudo.

---

## Exemplo 3: acesso por horário

Em **Firewall > Schedules**, crie um horário chamado `almoco`, de 12:00 às
13:30, de segunda a sexta.

| Campo | Valor |
|-------|-------|
| Action | Pass |
| Source | `guarita_vendas` |
| Destination | `alias_redes_sociais` |
| Schedule | `almoco` |
| Description | Vendas: redes sociais só no almoço |

Fora do horário a regra não existe para o pf, então o tráfego cai na próxima
regra que casar — normalmente um Block.

---

## Exemplo 4: limitar banda por grupo

Em **Firewall > Traffic Shaper > Limiters**, crie um limiter `banda_restrito`
com, por exemplo, 2 Mbit/s.

Na regra do grupo, em **Advanced Options > In/Out pipe**, escolha o limiter.
Todo o grupo passa a dividir aquela banda.

---

## Exemplo 5: separar acesso às redes internas

Útil para impedir que o pessoal de uma área alcance servidores de outra.

| Campo | Valor |
|-------|-------|
| Action | Block |
| Source | `guarita_vendas` |
| Destination | `rede_servidores_rh` |
| Description | Vendas não acessa os servidores do RH |

Coloque acima das regras de liberação interna.

---

## Exemplo 6: política padrão para quem não foi identificado

Crie um grupo chamado `nao_identificado` em **Services > Guarita > Grupos**, e
aponte-o no campo **Grupo padrão** das Configurações. Ele recebe:

- usuários do domínio que não caem em nenhum grupo configurado;
- usuários cujo logon aconteceu enquanto o AD estava inacessível.

Importante: máquinas **sem nenhum usuário identificado** (impressoras,
celulares, visitantes, servidores) não entram em nenhuma tabela do Guarita.
Para elas, o que vale é a regra genérica da LAN, abaixo das regras de grupo.
Decida consciamente se essa regra genérica deve liberar ou bloquear.

---

## YouTube e aplicações: o que é possível hoje

Esta é a parte que motivou o projeto, então vale ser preciso sobre o estado
atual.

### O problema

O YouTube não tem IPs próprios: ele usa a mesma infraestrutura do Google que
serve Gmail, Drive e Google Workspace. Bloquear por IP derruba tudo junto.
É por isso que o pfBlockerNG não resolve bem esse caso.

Além disso, o navegador tem rotas de fuga:

- **QUIC** (UDP 443): protocolo próprio do Google, passa por fora do
  HTTP/TLS comum.
- **DNS criptografado** (DoH/DoT): o Chrome e o Firefox podem resolver nomes
  por fora do seu servidor DNS, ignorando qualquer filtro de DNS.

Qualquer bloqueio por nome que não feche essas duas portas é contornável.

### O que a fase 1 já permite

**a) Fechar as rotas de fuga, por grupo.** Isso é pré-requisito para a fase 2 e
já vale a pena fazer agora.

Bloquear QUIC para um grupo:

| Campo | Valor |
|-------|-------|
| Action | Block |
| Protocol | UDP |
| Source | `guarita_restrito` |
| Destination port | 443 |
| Description | Restrito: bloqueia QUIC (força HTTPS comum) |

Bloquear DNS externo, forçando o uso do DNS do pfSense:

| Campo | Valor |
|-------|-------|
| Action | Block |
| Protocol | TCP/UDP |
| Source | `guarita_restrito` |
| Destination | `!` (invertido) `This Firewall` |
| Destination port | 53 |
| Description | Restrito: só o DNS do firewall |

E o DNS over TLS:

| Campo | Valor |
|-------|-------|
| Action | Block |
| Protocol | TCP |
| Source | `guarita_restrito` |
| Destination port | 853 |
| Description | Restrito: bloqueia DNS over TLS |

O DoH é mais difícil, porque anda na porta 443 junto com o resto. Ele depende
de bloquear os nomes dos servidores de DoH conhecidos, o que é trabalho da
fase 2.

**b) Usar o pfBlockerNG junto, para a rede inteira.** Se existe uma categoria
que deve ser bloqueada para todos sem exceção, o pfBlockerNG continua sendo o
lugar certo. O Guarita não conflita com ele.

### O que a fase 1 não permite

**Bloquear YouTube para o grupo A e liberar para o grupo B.** O filtro de DNS
do pfSense (e o do pfBlockerNG) responde igual para todo mundo: ele não sabe
qual usuário está perguntando. É exatamente isso que a fase 2 resolve, ao
colocar um resolvedor de DNS que decide a resposta conforme o grupo de quem
pergunta.

Se precisar de algo já agora, há duas saídas intermediárias, ambas com
limitações honestas:

1. **Grupo "sem YouTube" com proxy explícito.** Funciona, mas exige configurar
   proxy nas estações.
2. **Rede separada (VLAN) para quem tem acesso restrito.** Funciona, mas volta
   a amarrar a política ao lugar da máquina, não ao usuário — ou seja, perde o
   ponto do Guarita.

A recomendação é: use a fase 1 para a política de rede por usuário (destinos,
portas, horários, banda, segmentação interna) e fechar as rotas de fuga, e
espere a fase 2 para o bloqueio de aplicações por nome e por grupo.

---

## Modo restrito do YouTube (a partir da fase 2)

Vale registrar o caminho, porque é melhor que bloquear: o YouTube aceita um
cabeçalho/registro DNS que força o modo restrito, filtrando conteúdo adulto
sem derrubar o site inteiro. Isso se faz respondendo `restrict.youtube.com`
para `www.youtube.com` no DNS — por grupo, o que depende do resolvedor da
fase 2.

---

## Conferindo se uma regra está pegando

1. **Services > Guarita > Sessões**: o IP da estação está no grupo esperado?
2. **Services > Guarita > Status**: as colunas "IPs (serviço)" e "IPs (pf)"
   batem para aquele grupo?
3. **Diagnostics > Tables**: escolha `guarita_<grupo>` e veja os IPs.
4. **Status > System Logs > Firewall**: a regra que casou aparece aqui. Ative
   *Log packets that are handled by this rule* na regra, enquanto estiver
   testando.

Se a tabela está certa mas a regra não pega, quase sempre é ordem: uma regra
acima está casando primeiro.

---

## Cuidados

- **Não mude o nome curto de um grupo** depois de criar regras com ele: as
  regras passariam a apontar para um alias que não existe mais. Crie um grupo
  novo e ajuste as regras.
- **Estações compartilhadas**: o Guarita associa um usuário por IP, o último
  que fez logon. Em terminal com vários usuários simultâneos (RDS/Terminal
  Server), todos saem pelo mesmo IP e o modelo não distingue entre eles.
- **Sessão expirada**: passado o tempo configurado sem eventos, o IP sai das
  tabelas e cai na regra genérica. Se isso for um problema, aumente a duração
  da sessão ou fixe a sessão daquele IP.
- **Prioridade**: confira a prioridade dos grupos para usuários que estão em
  vários. Vale o de menor número.
